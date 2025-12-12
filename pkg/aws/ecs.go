package aws

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/rs/zerolog/log"
)

// ECSService represents an ECS service
type ECSService struct {
	Name             string `json:"name"`
	Image            string `json:"image"`
	Version          string `json:"version"`
	PushedAt         string `json:"pushed_at"`
	CVECriticalCount int    `json:"cve_critical_count"`
	DesiredCount     int32  `json:"desired_count"`
	RunningCount     int32  `json:"running_count"`
	PendingCount     int32  `json:"pending_count"`
}

// isECRImage checks if an image is from the specified ECR registry
func isECRImage(fullImage, accountID, region string) bool {
	if accountID == "" || region == "" {
		return false
	}
	ecrHost := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region)
	return strings.Contains(fullImage, ecrHost)
}

// GetECSServices retrieves ECS services from the specified cluster
// If limit > 0, only returns up to that many services
// If scanEnabled is true, retrieves CVE critical counts using scanProfile
func GetECSServices(ctx context.Context, profile, clusterName string, limit int, scanEnabled bool, scanProfile string) ([]ECSService, error) {
	// Load AWS config with the specified profile
	cfg, err := LoadAWSConfig(ctx, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create ECS client
	ecsClient := ecs.NewFromConfig(cfg)

	// Get AWS account ID and region from scanProfile (acorns-production) for ECR registry detection
	var accountID string
	var region string
	if scanProfile != "" {
		accountID, err = GetAccountID(ctx, scanProfile)
		if err != nil {
			log.Debug().Err(err).Str("profile", scanProfile).Msg("Failed to get account ID, ECR detection may be limited")
		}
		ecrCfg, err := LoadAWSConfig(ctx, scanProfile)
		if err == nil {
			region = ecrCfg.Region
		}
	}

	// Create ECR client for getting image push dates (use scanProfile which is acorns-production)
	var ecrClient *ecr.Client
	ecrCfg, err := LoadAWSConfig(ctx, scanProfile)
	if err == nil {
		ecrClient = ecr.NewFromConfig(ecrCfg)
	}

	// Create Inspector2 client for scanning if enabled
	var inspectorClient *inspector2.Client
	if scanEnabled {
		var err error
		inspectorClient, err = GetInspector2Client(ctx, scanProfile)
		if err != nil {
			return nil, err
		}
	}

	// Initialize progress bar
	pw := progress.NewWriter()
	pw.SetOutputWriter(os.Stderr)
	pw.SetStyle(progress.StyleDefault)
	pw.SetTrackerPosition(progress.PositionRight)
	pw.SetUpdateFrequency(time.Millisecond * 50)

	tracker := &progress.Tracker{
		Message: "Retrieving ECS services",
		Total:   0, // Will be updated as we discover pages
		Units:   progress.UnitsDefault,
	}
	pw.AppendTracker(tracker)

	// Start progress bar rendering
	go pw.Render()
	defer pw.Stop()

	// Process services as we list them (streaming approach)
	// This avoids storing all ARNs in memory and allows early termination
	var services []ECSService
	var nextToken *string
	var totalProcessed int64
	batchSize := 10

	for {
		// List services for this page
		input := &ecs.ListServicesInput{
			Cluster: aws.String(clusterName),
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		listOutput, err := ecsClient.ListServices(ctx, input)
		if err != nil {
			tracker.MarkAsErrored()
			return nil, fmt.Errorf("failed to list ECS services: %w", err)
		}

		if len(listOutput.ServiceArns) == 0 {
			break
		}

		// Update total estimate
		totalProcessed += int64(len(listOutput.ServiceArns))
		if tracker.Total < totalProcessed {
			tracker.Total = totalProcessed
		}

		// Describe services in batches and process immediately
		for i := 0; i < len(listOutput.ServiceArns); i += batchSize {
			// Check if we've reached the limit before processing more
			if limit > 0 && len(services) >= limit {
				break
			}

			end := i + batchSize
			if end > len(listOutput.ServiceArns) {
				end = len(listOutput.ServiceArns)
			}
			batch := listOutput.ServiceArns[i:end]

			describeInput := &ecs.DescribeServicesInput{
				Cluster:  aws.String(clusterName),
				Services: batch,
			}

			tracker.Message = fmt.Sprintf("Describing services (%d processed)", len(services))

			describeOutput, err := ecsClient.DescribeServices(ctx, describeInput)
			if err != nil {
				tracker.MarkAsErrored()
				return nil, fmt.Errorf("failed to describe ECS services: %w", err)
			}

			// Process each service
			for _, service := range describeOutput.Services {
				tracker.Increment(1)

				// Only include services with desired count greater than 0
				if service.DesiredCount <= 0 {
					continue
				}

				// Only include services with ACTIVE status
				if service.Status == nil || string(*service.Status) != "ACTIVE" {
					continue
				}

				// Get container image from task definition (only if we haven't hit limit)
				image := ""
				version := ""
				fullImage := ""
				if limit == 0 || len(services) < limit {
					if service.TaskDefinition != nil {
						taskDefArn := aws.ToString(service.TaskDefinition)
						taskDefOutput, err := ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
							TaskDefinition: aws.String(taskDefArn),
						})
						if err == nil && taskDefOutput.TaskDefinition != nil {
							// Get image from the first container definition (main container)
							if len(taskDefOutput.TaskDefinition.ContainerDefinitions) > 0 {
								containerDef := taskDefOutput.TaskDefinition.ContainerDefinitions[0]
								if containerDef.Image != nil {
									fullImage = aws.ToString(containerDef.Image)
									// Remove ECR host prefix (e.g., "ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/")
									// Extract everything after the last "/"
									var imageWithTag string
									if idx := strings.LastIndex(fullImage, "/"); idx >= 0 && idx < len(fullImage)-1 {
										imageWithTag = fullImage[idx+1:]
									} else {
										imageWithTag = fullImage
									}

									// Split image name and tag (version) on colon
									if colonIdx := strings.LastIndex(imageWithTag, ":"); colonIdx >= 0 {
										image = imageWithTag[:colonIdx]
										version = imageWithTag[colonIdx+1:]
									} else {
										image = imageWithTag
										version = "latest" // Default if no tag specified
									}
								}
							}
						}
					}
				}

				// Get image push date if image is from ECR
				pushedAt := ""
				if ecrClient != nil && image != "" && version != "" {
					// Check if image is from the ECR registry
					if isECRImage(fullImage, accountID, region) {
						pushedAt = GetImagePushedAt(ctx, ecrClient, image, version)
					}
				}

				// Get CVE critical count if scanning is enabled and image is from ECR
				cveCriticalCount := 0
				if scanEnabled && inspectorClient != nil && image != "" && version != "" {
					// Check if image is from the ECR registry
					if isECRImage(fullImage, accountID, region) {
						cveCriticalCount = GetCVECriticalCount(ctx, inspectorClient, image, version)
					}
				}

				services = append(services, ECSService{
					Name:             aws.ToString(service.ServiceName),
					Image:            image,
					Version:          version,
					PushedAt:         pushedAt,
					CVECriticalCount: cveCriticalCount,
					DesiredCount:     service.DesiredCount,
					RunningCount:     service.RunningCount,
					PendingCount:     service.PendingCount,
				})

				// Check limit after adding service
				if limit > 0 && len(services) >= limit {
					break
				}
			}

			// Check if we've reached the limit
			if limit > 0 && len(services) >= limit {
				break
			}
		}

		// Check if we've reached the limit before fetching next page
		if limit > 0 && len(services) >= limit {
			break
		}

		nextToken = listOutput.NextToken
		if nextToken == nil {
			break
		}
	}

	tracker.MarkAsDone()
	time.Sleep(100 * time.Millisecond) // Give progress bar time to update

	log.Info().
		Str("cluster", clusterName).
		Str("profile", profile).
		Int("count", len(services)).
		Msg("Retrieved ECS services")

	return services, nil
}

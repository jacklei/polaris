package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/rs/zerolog/log"
)

// ECSService represents an ECS service
type ECSService struct {
	Name         string `json:"name"`
	DesiredCount int32  `json:"desired_count"`
	RunningCount int32  `json:"running_count"`
	PendingCount int32  `json:"pending_count"`
}

// GetECSServices retrieves all ECS services from the specified cluster
func GetECSServices(ctx context.Context, profile, clusterName string) ([]ECSService, error) {
	// Load AWS config with the specified profile
	cfg, err := LoadAWSConfig(ctx, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create ECS client
	ecsClient := ecs.NewFromConfig(cfg)

	// List services in the cluster
	var services []ECSService
	var nextToken *string

	for {
		input := &ecs.ListServicesInput{
			Cluster: aws.String(clusterName),
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		listOutput, err := ecsClient.ListServices(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list ECS services: %w", err)
		}

		if len(listOutput.ServiceArns) == 0 {
			break
		}

		// Describe the services to get full details
		describeInput := &ecs.DescribeServicesInput{
			Cluster:  aws.String(clusterName),
			Services: listOutput.ServiceArns,
		}

		describeOutput, err := ecsClient.DescribeServices(ctx, describeInput)
		if err != nil {
			return nil, fmt.Errorf("failed to describe ECS services: %w", err)
		}

		// Convert to our ECSService struct and filter by desired count > 0 and status = ACTIVE
		for _, service := range describeOutput.Services {
			// Only include services with desired count greater than 0
			if service.DesiredCount <= 0 {
				continue
			}

			// Only include services with ACTIVE status
			if service.Status == nil || string(*service.Status) != "ACTIVE" {
				continue
			}

			services = append(services, ECSService{
				Name:         aws.ToString(service.ServiceName),
				DesiredCount: service.DesiredCount,
				RunningCount: service.RunningCount,
				PendingCount: service.PendingCount,
			})
		}

		nextToken = listOutput.NextToken
		if nextToken == nil {
			break
		}
	}

	log.Info().
		Str("cluster", clusterName).
		Str("profile", profile).
		Int("count", len(services)).
		Msg("Retrieved ECS services")

	return services, nil
}

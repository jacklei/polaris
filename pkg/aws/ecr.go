package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/rs/zerolog/log"
)

// GetECRClient creates an ECR client using the specified profile
func GetECRClient(ctx context.Context, profile string) (*ecr.Client, error) {
	cfg, err := LoadAWSConfig(ctx, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for ECR profile %s: %w", profile, err)
	}
	return ecr.NewFromConfig(cfg), nil
}

// GetInspector2Client creates an Inspector2 client using the specified profile
func GetInspector2Client(ctx context.Context, profile string) (*inspector2.Client, error) {
	cfg, err := LoadAWSConfig(ctx, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for Inspector2 profile %s: %w", profile, err)
	}
	return inspector2.NewFromConfig(cfg), nil
}

// GetImagePushedAt retrieves the push date for an ECR image
// Returns empty string if image not found or on error
func GetImagePushedAt(ctx context.Context, ecrClient *ecr.Client, repositoryName, imageTag string) string {
	describeInput := &ecr.DescribeImagesInput{
		RepositoryName: aws.String(repositoryName),
		ImageIds: []ecrtypes.ImageIdentifier{
			{
				ImageTag: aws.String(imageTag),
			},
		},
	}

	describeOutput, err := ecrClient.DescribeImages(ctx, describeInput)
	if err != nil {
		log.Debug().
			Str("repository", repositoryName).
			Str("tag", imageTag).
			Err(err).
			Msg("Failed to get image push date")
		return ""
	}

	if len(describeOutput.ImageDetails) > 0 {
		imageDetail := describeOutput.ImageDetails[0]
		if imageDetail.ImagePushedAt != nil {
			// Format as readable date/time
			return imageDetail.ImagePushedAt.Format(time.RFC3339)
		}
	}

	return ""
}

// GetCVECriticalCount retrieves the critical CVE count for an ECR image using AWS Inspector v2
// Returns 0 if scanning is not enabled, no scans found, or on error
func GetCVECriticalCount(ctx context.Context, inspectorClient *inspector2.Client, repositoryName, imageTag string) int {
	criticalCount := 0
	var nextToken *string

	for {
		listInput := &inspector2.ListFindingsInput{
			FilterCriteria: &inspector2types.FilterCriteria{
				// Filter by ECR container image resource type
				ResourceType: []inspector2types.StringFilter{
					{
						Comparison: inspector2types.StringComparisonEquals,
						Value:      aws.String("AWS_ECR_CONTAINER_IMAGE"),
					},
				},
				// Filter by CRITICAL severity
				Severity: []inspector2types.StringFilter{
					{
						Comparison: inspector2types.StringComparisonEquals,
						Value:      aws.String("CRITICAL"),
					},
				},
				// Filter by repository name
				EcrImageRepositoryName: []inspector2types.StringFilter{
					{
						Comparison: inspector2types.StringComparisonEquals,
						Value:      aws.String(repositoryName),
					},
				},
				// Filter by image tag
				EcrImageTags: []inspector2types.StringFilter{
					{
						Comparison: inspector2types.StringComparisonEquals,
						Value:      aws.String(imageTag),
					},
				},
			},
			MaxResults: aws.Int32(100),
		}

		if nextToken != nil {
			listInput.NextToken = nextToken
		}

		listOutput, err := inspectorClient.ListFindings(ctx, listInput)
		if err != nil {
			// If scanning is not enabled, no scans found, or other error, return 0
			log.Debug().
				Str("repository", repositoryName).
				Str("tag", imageTag).
				Err(err).
				Msg("Failed to get Inspector2 findings (scanning may not be enabled or no scans found)")
			return 0
		}

		// Count the findings
		if listOutput.Findings != nil {
			criticalCount += len(listOutput.Findings)
		}

		nextToken = listOutput.NextToken
		if nextToken == nil {
			break
		}
	}

	return criticalCount
}

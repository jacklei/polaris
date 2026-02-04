package aws

import (
	"context"
	"fmt"
	"sort"
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

// GetLatestImageTags retrieves the latest N tags for an ECR repository
// Returns up to maxTags tags, sorted by push date (newest first)
func GetLatestImageTags(ctx context.Context, ecrClient *ecr.Client, repositoryName string, maxTags int) ([]string, error) {
	if maxTags <= 0 {
		maxTags = 10
	}

	// Use ListImages to get images, then describe them to get tags
	listImagesInput := &ecr.ListImagesInput{
		RepositoryName: aws.String(repositoryName),
		MaxResults:     aws.Int32(int32(maxTags)),
		Filter: &ecrtypes.ListImagesFilter{
			TagStatus: ecrtypes.TagStatusTagged,
		},
	}

	listOutput, err := ecrClient.ListImages(ctx, listImagesInput)
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	if len(listOutput.ImageIds) == 0 {
		return []string{}, nil
	}

	// Get image details to sort by push date
	imageIds := make([]ecrtypes.ImageIdentifier, 0, len(listOutput.ImageIds))
	for _, imgId := range listOutput.ImageIds {
		if imgId.ImageTag != nil {
			imageIds = append(imageIds, ecrtypes.ImageIdentifier{
				ImageTag: imgId.ImageTag,
			})
		}
	}

	if len(imageIds) == 0 {
		return []string{}, nil
	}

	describeInput := &ecr.DescribeImagesInput{
		RepositoryName: aws.String(repositoryName),
		ImageIds:       imageIds,
	}

	describeOutput, err := ecrClient.DescribeImages(ctx, describeInput)
	if err != nil {
		return nil, fmt.Errorf("failed to describe images: %w", err)
	}

	// Sort by push date (newest first)
	type imageWithTag struct {
		tag      string
		pushedAt *time.Time
	}
	images := make([]imageWithTag, 0, len(describeOutput.ImageDetails))
	for _, detail := range describeOutput.ImageDetails {
		if len(detail.ImageTags) > 0 && detail.ImagePushedAt != nil {
			// Use the first tag
			images = append(images, imageWithTag{
				tag:      detail.ImageTags[0],
				pushedAt: detail.ImagePushedAt,
			})
		}
	}

	// Sort by push date descending
	for i := 0; i < len(images)-1; i++ {
		for j := i + 1; j < len(images); j++ {
			if images[i].pushedAt != nil && images[j].pushedAt != nil {
				if images[i].pushedAt.Before(*images[j].pushedAt) {
					images[i], images[j] = images[j], images[i]
				}
			}
		}
	}

	// Extract tags
	tags := make([]string, 0, len(images))
	for i, img := range images {
		if i >= maxTags {
			break
		}
		tags = append(tags, img.tag)
	}

	return tags, nil
}

// TagInfo contains tag and push date information
type TagInfo struct {
	Tag      string
	PushedAt *time.Time
}

// GetLatestImageTagsWithDates retrieves the latest N tags with their push dates for an ECR repository
// Returns up to maxTags tags, sorted by push date (newest first)
func GetLatestImageTagsWithDates(ctx context.Context, ecrClient *ecr.Client, repositoryName string, maxTags int) ([]TagInfo, error) {
	if maxTags <= 0 {
		maxTags = 10
	}

	// Fetch a large sample of images to ensure we get the latest ones
	// ListImages doesn't guarantee ordering, so we fetch many and sort
	// We'll fetch up to 100 images per page (API limit) and process multiple pages if needed

	// Use ListImages to get images, then describe them to get tags
	// Use a map to track unique images by digest to avoid duplicates
	imageDigestMap := make(map[string]bool)
	var allImageIds []ecrtypes.ImageIdentifier
	var nextToken *string
	pageCount := 0
	maxPages := 5 // Limit to 5 pages (500 images max) to avoid excessive API calls

	// Paginate through images to get a good sample
	for pageCount < maxPages {
		listImagesInput := &ecr.ListImagesInput{
			RepositoryName: aws.String(repositoryName),
			MaxResults:     aws.Int32(100), // Max allowed by API
			Filter: &ecrtypes.ListImagesFilter{
				TagStatus: ecrtypes.TagStatusTagged,
			},
		}

		if nextToken != nil {
			listImagesInput.NextToken = nextToken
		}

		listOutput, err := ecrClient.ListImages(ctx, listImagesInput)
		if err != nil {
			return nil, fmt.Errorf("failed to list images: %w", err)
		}

		if len(listOutput.ImageIds) == 0 {
			break
		}

		// Collect unique image IDs by digest (prefer digest over tag to avoid duplicates)
		for _, imgId := range listOutput.ImageIds {
			// Prefer digest if available, otherwise use tag
			if imgId.ImageDigest != nil {
				digest := aws.ToString(imgId.ImageDigest)
				if !imageDigestMap[digest] {
					imageDigestMap[digest] = true
					allImageIds = append(allImageIds, ecrtypes.ImageIdentifier{
						ImageDigest: imgId.ImageDigest,
					})
				}
			} else if imgId.ImageTag != nil {
				// Fallback to tag if no digest
				tag := aws.ToString(imgId.ImageTag)
				if !imageDigestMap[tag] {
					imageDigestMap[tag] = true
					allImageIds = append(allImageIds, ecrtypes.ImageIdentifier{
						ImageTag: imgId.ImageTag,
					})
				}
			}
		}

		pageCount++

		// Stop if no more pages
		if listOutput.NextToken == nil {
			break
		}
		nextToken = listOutput.NextToken
	}

	if len(allImageIds) == 0 {
		return []TagInfo{}, nil
	}

	// Describe images in batches to get push dates
	// ECR DescribeImages has a limit, so we'll process in batches
	batchSize := 100
	tagInfos := make([]TagInfo, 0, len(allImageIds))

	for i := 0; i < len(allImageIds); i += batchSize {
		end := i + batchSize
		if end > len(allImageIds) {
			end = len(allImageIds)
		}
		batch := allImageIds[i:end]

		describeInput := &ecr.DescribeImagesInput{
			RepositoryName: aws.String(repositoryName),
			ImageIds:       batch,
		}

		describeOutput, err := ecrClient.DescribeImages(ctx, describeInput)
		if err != nil {
			return nil, fmt.Errorf("failed to describe images: %w", err)
		}

		// Build tag info with push dates - collect ALL tags from each image
		for _, detail := range describeOutput.ImageDetails {
			if detail.ImagePushedAt != nil {
				// Add all tags for this image (an image can have multiple tags)
				for _, tag := range detail.ImageTags {
					tagInfos = append(tagInfos, TagInfo{
						Tag:      tag,
						PushedAt: detail.ImagePushedAt,
					})
				}
			}
		}
	}

	// Sort by push date descending (newest first) using proper sorting
	sort.Slice(tagInfos, func(i, j int) bool {
		if tagInfos[i].PushedAt == nil && tagInfos[j].PushedAt == nil {
			return false
		}
		if tagInfos[i].PushedAt == nil {
			return false // nil dates go to the end
		}
		if tagInfos[j].PushedAt == nil {
			return true
		}
		return tagInfos[i].PushedAt.After(*tagInfos[j].PushedAt) // Descending order
	})

	// Limit to maxTags (take the latest ones)
	if len(tagInfos) > maxTags {
		tagInfos = tagInfos[:maxTags]
	}

	return tagInfos, nil
}

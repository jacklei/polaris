package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jacklei/polaris/pkg/aws"
	"github.com/jacklei/polaris/pkg/output"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var ecrScanProfile string

// awsGetEcrScanCmd represents the get-ecr-scan command
var awsGetEcrScanCmd = &cobra.Command{
	Use:   "get-ecr-scan",
	Short: "Scan an ECR image for critical CVEs",
	Long: `Scans an ECR image for critical CVEs using AWS Inspector v2.
	
The image should be specified as repository:tag (e.g., "my-repo:1.0.0").
If the image is from a specific ECR registry, you can also provide the full path.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		imageArg := args[0]

		// Parse image:tag format (tag is optional)
		repositoryName, imageTag, err := parseImageTag(imageArg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to parse image")
			return
		}

		// Get ECR client for fetching tags if needed
		ecrClient, err := aws.GetECRClient(ctx, ecrScanProfile)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create ECR client")
			return
		}

		// Get Inspector2 client
		inspectorClient, err := aws.GetInspector2Client(ctx, ecrScanProfile)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create Inspector2 client")
			return
		}

		var tagInfos []aws.TagInfo
		if imageTag == "" {
			// No tag provided, get latest 10 tags with push dates
			log.Info().
				Str("repository", repositoryName).
				Msg("No tag specified, fetching latest 10 tags")

			tagInfos, err = aws.GetLatestImageTagsWithDates(ctx, ecrClient, repositoryName, 10)
			if err != nil {
				log.Error().Err(err).Msg("Failed to get latest tags")
				return
			}

			if len(tagInfos) == 0 {
				log.Warn().Str("repository", repositoryName).Msg("No tags found in repository")
				return
			}

			log.Info().
				Str("repository", repositoryName).
				Int("tag_count", len(tagInfos)).
				Msg("Found tags, scanning for CVEs")
		} else {
			// Single tag provided - get push date for it
			pushedAt := aws.GetImagePushedAt(ctx, ecrClient, repositoryName, imageTag)
			var pushedAtTime *time.Time
			if pushedAt != "" {
				if t, err := time.Parse(time.RFC3339, pushedAt); err == nil {
					pushedAtTime = &t
				}
			}
			tagInfos = []aws.TagInfo{
				{
					Tag:      imageTag,
					PushedAt: pushedAtTime,
				},
			}
		}

		// Scan each tag
		results := make([]map[string]interface{}, 0, len(tagInfos))
		hasCriticalCVEs := false
		for _, tagInfo := range tagInfos {
			cveCount := aws.GetCVECriticalCount(ctx, inspectorClient, repositoryName, tagInfo.Tag)

			if cveCount > 0 {
				hasCriticalCVEs = true
			}

			// Format pushed at date
			pushedAtStr := ""
			if tagInfo.PushedAt != nil {
				pushedAtStr = tagInfo.PushedAt.Format(time.RFC3339)
			}

			results = append(results, map[string]interface{}{
				"repository": repositoryName,
				"tag":        tagInfo.Tag,
				"pushed_at":  pushedAtStr,
				"cve_count":  cveCount,
			})
		}

		// Prepare output
		result := map[string]interface{}{
			"repository": repositoryName,
			"scans":      results,
		}

		if err := output.Print(result, outputType, "", false, ""); err != nil {
			log.Error().Err(err).Msg("Failed to print output")
			os.Exit(1)
			return
		}

		// Exit with error code if critical CVEs were found
		if hasCriticalCVEs {
			os.Exit(1)
		}
	},
}

func init() {
	awsCmd.AddCommand(awsGetEcrScanCmd)

	// Add profile flag for ECR scanning
	awsGetEcrScanCmd.Flags().StringVarP(&ecrScanProfile, "profile", "p", "acorns-production", "AWS profile to use for ECR scanning")
}

// parseImageTag parses an image:tag string and returns repository name and tag
// Tag is optional - if not provided, returns empty tag string
// Handles formats like:
//   - "repository:tag"
//   - "repository" (no tag)
//   - "namespace/repository:tag"
//   - "ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/repository:tag"
func parseImageTag(imageArg string) (repositoryName, imageTag string, err error) {
	// Remove ECR host prefix if present (e.g., "ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/")
	var imageWithTag string
	if idx := strings.LastIndex(imageArg, "/"); idx >= 0 && idx < len(imageArg)-1 {
		imageWithTag = imageArg[idx+1:]
	} else {
		imageWithTag = imageArg
	}

	// Split on colon to get repository and tag (tag is optional)
	parts := strings.SplitN(imageWithTag, ":", 2)
	if len(parts) == 1 {
		// No tag provided
		repositoryName = parts[0]
		imageTag = ""
	} else {
		repositoryName = parts[0]
		imageTag = parts[1]
	}

	if repositoryName == "" {
		return "", "", fmt.Errorf("repository name cannot be empty")
	}

	return repositoryName, imageTag, nil
}

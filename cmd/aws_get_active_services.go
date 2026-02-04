package cmd

import (
	"context"

	"github.com/jacklei/polaris/pkg/aws"
	"github.com/jacklei/polaris/pkg/output"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var profile string
var clusterName string
var sortColumn string
var sortDescending bool
var filter string
var limit int
var scanEnabled bool
var scanProfile string

// awsGetActiveServicesCmd represents the get-active-services command
var awsGetActiveServicesCmd = &cobra.Command{
	Use:   "get-active-services",
	Short: "Get active ECS services from the ozark cluster",
	Long: `Retrieves the list of active ECS services from the specified cluster.
If no profile is specified, uses the default profile.`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		log.Info().
			Str("profile", profile).
			Msg("Getting active ECS services")

		// Get ECS services from the cluster
		services, err := aws.GetECSServices(ctx, profile, clusterName, limit, scanEnabled, scanProfile)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get ECS services")
			return
		}

		// Prepare output
		result := map[string]interface{}{
			"services": services,
			"count":    len(services),
		}

		if err := output.Print(result, outputType, sortColumn, sortDescending, filter); err != nil {
			log.Error().Err(err).Msg("Failed to print output")
		}
	},
}

func init() {
	awsCmd.AddCommand(awsGetActiveServicesCmd)

	// Add profile flag
	awsGetActiveServicesCmd.Flags().StringVarP(&profile, "profile", "p", "default", "AWS profile to use")

	// Set default cluster name to "ozark"
	awsGetActiveServicesCmd.Flags().StringVarP(&clusterName, "cluster", "c", "ozark", "ECS cluster name")

	// Add sort flags
	awsGetActiveServicesCmd.Flags().StringVar(&sortColumn, "sort", "", "Sort by column (name, count, delta, cve)")
	awsGetActiveServicesCmd.Flags().BoolVar(&sortDescending, "desc", false, "Sort in descending order")

	// Add filter flag
	awsGetActiveServicesCmd.Flags().StringVar(&filter, "filter", "", "Filter by column and threshold (e.g., 'count:100', 'delta:0') or 'cve' to show only services with critical CVEs")

	// Add limit flag
	awsGetActiveServicesCmd.Flags().IntVarP(&limit, "limit", "n", 0, "Limit the number of services to query (0 = no limit)")

	// Add container scanning flags
	awsGetActiveServicesCmd.Flags().BoolVar(&scanEnabled, "scan", false, "Enable container scanning to retrieve CVE critical counts")
	awsGetActiveServicesCmd.Flags().StringVar(&scanProfile, "scan-profile", "acorns-production", "AWS profile to use for ECR scanning")
}

package cmd

import (
	"context"
	"os"

	"github.com/jacklei/polaris/pkg/jira"
	"github.com/jacklei/polaris/pkg/output"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// jiraGenerateSummaryCmd represents the generate-summary command
var jiraGenerateSummaryCmd = &cobra.Command{
	Use:   "generate-summary",
	Short: "Generate a summary for a Jira ticket",
	Long: `Generates a summary for a Jira ticket by fetching ticket details and formatting them.

The ticket can be specified as:
  - Ticket key (e.g., "PROJ-123")
  - Full URL (e.g., "https://acorns.atlassian.net/browse/PROJ-123")`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		ticketArg := args[0]

		// Get credentials from environment
		username := os.Getenv("JIRA_USERNAME")
		token := os.Getenv("JIRA_API_TOKEN")
		githubToken := os.Getenv("GITHUB_TOKEN")
		awsProfile := os.Getenv("AWS_PROFILE")
		if awsProfile == "" {
			awsProfile = "acorns-production" // Default AWS profile
		}

		// Generate summary
		summary, err := jira.GenerateSummary(ctx, username, token, ticketArg, githubToken, awsProfile)
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate summary")
			return
		}

		// Print output
		result := map[string]interface{}{
			"summary": summary,
		}
		if err := output.Print(result, outputType, "", false, ""); err != nil {
			log.Error().Err(err).Msg("Failed to print output")
		}
	},
}

func init() {
	jiraCmd.AddCommand(jiraGenerateSummaryCmd)
}

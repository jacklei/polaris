package cmd

import (
	"context"
	"os"

	"github.com/jacklei/polaris/pkg/jira"
	"github.com/jacklei/polaris/pkg/output"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// jiraOverdueCABsCmd represents the overdue-cabs command
var jiraOverdueCABsCmd = &cobra.Command{
	Use:   "overdue-cabs",
	Short: "List overdue CAB tickets grouped by team",
	Long: `Lists all open CAB (Change Advisory Board) tickets that are still open,
grouped by team name. For each ticket, it shows:
  - Ticket key with link
  - Assignee
  - Current status
  - Planned start date`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		// Get credentials from environment
		username := os.Getenv("JIRA_USERNAME")
		token := os.Getenv("JIRA_API_TOKEN")

		// Fetch overdue CAB tickets
		ticketsByTeam, err := jira.GetOverdueCABTickets(ctx, username, token)
		if err != nil {
			log.Error().Err(err).Msg("Failed to fetch overdue CAB tickets")
			return
		}

		// Convert to output format
		result := map[string]interface{}{
			"tickets_by_team": ticketsByTeam,
		}

		// Print output
		if err := output.Print(result, outputType, "", false, ""); err != nil {
			log.Error().Err(err).Msg("Failed to print output")
		}
	},
}

func init() {
	jiraCmd.AddCommand(jiraOverdueCABsCmd)
}

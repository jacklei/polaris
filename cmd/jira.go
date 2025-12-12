package cmd

import (
	"os"

	"github.com/jacklei/polaris/pkg/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// jiraCmd represents the jira command
var jiraCmd = &cobra.Command{
	Use:   "jira",
	Short: "Jira-related commands",
	Long: `Commands for interacting with Jira tickets.
This command requires the JIRA_USERNAME and JIRA_API_TOKEN environment variables to be set.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize logger with the specified log level and output format
		logger.Init(logLevel, outputType)

		// Check for JIRA_USERNAME
		if os.Getenv("JIRA_USERNAME") == "" {
			log.Error().Msg("JIRA_USERNAME environment variable is required for Jira commands")
			os.Exit(1)
		}

		// Check for JIRA_API_TOKEN
		if os.Getenv("JIRA_API_TOKEN") == "" {
			log.Error().Msg("JIRA_API_TOKEN environment variable is required for Jira commands")
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(jiraCmd)
}


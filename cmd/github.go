package cmd

import (
	"os"

	"github.com/jacklei/polaris/pkg/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// githubCmd represents the github command
var githubCmd = &cobra.Command{
	Use:   "github",
	Short: "GitHub-related commands",
	Long: `Commands for interacting with GitHub repositories and pull requests.
This command requires the GITHUB_TOKEN environment variable to be set.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize logger with the specified log level and output format
		logger.Init(logLevel, outputType)

		// Check for GITHUB_TOKEN environment variable
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			log.Error().Msg("GITHUB_TOKEN environment variable is required for GitHub commands")
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(githubCmd)
}

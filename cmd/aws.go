package cmd

import (
	"github.com/jacklei/polaris/pkg/logger"
	"github.com/spf13/cobra"
)

// awsCmd represents the aws command
var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "AWS-related commands",
	Long: `Commands for interacting with AWS services and configurations.
This command uses the AWS SDK to read your local AWS configuration files (~/.aws/config and ~/.aws/credentials).`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize logger with the specified log level and output format
		logger.Init(logLevel, outputType)
	},
}

func init() {
	rootCmd.AddCommand(awsCmd)
}

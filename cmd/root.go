package cmd

import (
	"os"

	"github.com/jacklei/polaris/pkg/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	logLevel   string
	outputType string
)

// GetOutputType returns the current output type (text or json)
func GetOutputType() string {
	return outputType
}

var rootCmd = &cobra.Command{
	Use:   "polaris",
	Short: "Polaris guides your repos/platform toward correct posture",
	Long: `Polaris is a tool that guides your repositories and platform
toward correct posture. It helps ensure best practices and compliance.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize logger with the specified log level and output format
		logger.Init(logLevel, outputType)
	},
	Run: func(cmd *cobra.Command, args []string) {
		log.Info().Msg("Welcome to Polaris!")
		log.Info().Msg("Use 'polaris --help' to see available commands.")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Error().Err(err).Msg("Command execution failed")
		os.Exit(1)
	}
}

func init() {
	// Initialize logger with default level and output format before any command runs
	logger.Init("info", "text")

	// Add global flags
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "Set the logging level (trace, debug, info, warn, error, fatal, panic)")
	rootCmd.PersistentFlags().StringVarP(&outputType, "output", "o", "text", "Set the output format (text, json, table)")
}

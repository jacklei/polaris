package logger

import (
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var Logger zerolog.Logger

// Init initializes the logger with the specified log level and output format
func Init(level string, outputFormat string) {
	// Set time format to Unix timestamp for better performance
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Set log level
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	// Set output format
	var writer io.Writer
	if outputFormat == "json" {
		// Use JSON writer for structured output
		writer = os.Stderr
	} else {
		// Use console writer for better readability in development
		writer = zerolog.ConsoleWriter{Out: os.Stderr}
	}

	Logger = zerolog.New(writer).With().
		Timestamp().
		Logger()

	// Set as global logger
	log.Logger = Logger
}

// SetLevel updates the global log level
func SetLevel(level string) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)
}


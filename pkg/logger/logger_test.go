package logger

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestInit(t *testing.T) {
	// Test with different log levels
	levels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	for _, level := range levels {
		Init(level, "console")
		// Check global level instead of Logger instance level
		globalLevel := zerolog.GlobalLevel()
		expectedLevel, _ := zerolog.ParseLevel(level)
		if globalLevel != expectedLevel {
			t.Errorf("Init() with level %s failed, got level %s", level, globalLevel.String())
		}
	}

	// Test with invalid level (should default to info)
	Init("invalid", "console")
	globalLevel := zerolog.GlobalLevel()
	if globalLevel != zerolog.InfoLevel {
		t.Errorf("Init() with invalid level should default to info, got %s", globalLevel.String())
	}

	// Test with JSON output format
	Init("info", "json")
	globalLevel = zerolog.GlobalLevel()
	if globalLevel != zerolog.InfoLevel {
		t.Errorf("Init() with JSON format failed, got level %s", globalLevel.String())
	}

	// Test with console output format
	Init("info", "console")
	globalLevel = zerolog.GlobalLevel()
	if globalLevel != zerolog.InfoLevel {
		t.Errorf("Init() with console format failed, got level %s", globalLevel.String())
	}
}

func TestSetLevel(t *testing.T) {
	Init("info", "console")

	// Test setting different levels
	levels := []string{"debug", "info", "warn", "error"}
	for _, level := range levels {
		SetLevel(level)
		globalLevel := zerolog.GlobalLevel()
		expectedLevel, _ := zerolog.ParseLevel(level)
		if globalLevel != expectedLevel {
			t.Errorf("SetLevel() with level %s failed, got level %s", level, globalLevel.String())
		}
	}

	// Test with invalid level (should default to info)
	SetLevel("invalid")
	globalLevel := zerolog.GlobalLevel()
	if globalLevel != zerolog.InfoLevel {
		t.Errorf("SetLevel() with invalid level should default to info, got %s", globalLevel.String())
	}
}

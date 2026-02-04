package aws

import (
	"context"
	"testing"
)

func TestGetProfileInfo(t *testing.T) {
	ctx := context.Background()

	// Test with default profile (may fail if AWS credentials not configured)
	info, err := GetProfileInfo(ctx, "default")
	if err != nil {
		// Skip test if AWS credentials not available
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	if info == nil {
		t.Error("GetProfileInfo() returned nil")
		return
	}

	if info.Name == "" {
		t.Error("GetProfileInfo() returned empty name")
	}
}

func TestLoadAWSConfig(t *testing.T) {
	ctx := context.Background()

	// Test with default profile (may fail if AWS credentials not configured)
	cfg, err := LoadAWSConfig(ctx, "default")
	if err != nil {
		// Skip test if AWS credentials not available
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	if cfg.Region == "" {
		t.Log("LoadAWSConfig() returned config with empty region (this may be normal)")
	}
}

func TestLoadAWSConfig_EmptyProfile(t *testing.T) {
	ctx := context.Background()

	// Test with empty profile (should use default)
	cfg, err := LoadAWSConfig(ctx, "")
	if err != nil {
		// Skip test if AWS credentials not available
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	if cfg.Region == "" {
		t.Log("LoadAWSConfig() with empty profile returned config with empty region (this may be normal)")
	}
}

func TestValidateProfile(t *testing.T) {
	ctx := context.Background()

	// Test validation (may fail if AWS credentials not configured)
	err := ValidateProfile(ctx, "default")
	if err != nil {
		// Skip test if AWS credentials not available
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Validation should not return error even if API call fails
	// (it just logs and continues)
}

func TestGetProfileInfo_EmptyProfile(t *testing.T) {
	ctx := context.Background()

	// Test with empty profile (should use default)
	info, err := GetProfileInfo(ctx, "")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	if info == nil {
		t.Error("GetProfileInfo() with empty profile returned nil")
		return
	}

	if info.Name != "default" {
		t.Errorf("GetProfileInfo() with empty profile name = %v, want default", info.Name)
	}
}

func TestGetProfileInfo_DefaultProfile(t *testing.T) {
	ctx := context.Background()

	// Test with "default" profile explicitly
	info, err := GetProfileInfo(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	if info == nil {
		t.Error("GetProfileInfo() returned nil")
		return
	}

	if info.Name != "default" {
		t.Errorf("GetProfileInfo() with default profile name = %v, want default", info.Name)
	}
}

func TestLoadAWSConfig_DefaultProfile(t *testing.T) {
	ctx := context.Background()

	// Test with "default" profile explicitly
	cfg, err := LoadAWSConfig(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	if cfg.Region == "" {
		t.Log("LoadAWSConfig() with default profile returned config with empty region (this may be normal)")
	}
}

func TestValidateProfile_InvalidProfile(t *testing.T) {
	ctx := context.Background()

	// Test with invalid profile (should return error from LoadAWSConfig)
	err := ValidateProfile(ctx, "non-existent-profile-12345")
	if err == nil {
		t.Error("ValidateProfile() with invalid profile should return error")
	}
}

func TestValidateProfile_WithError(t *testing.T) {
	ctx := context.Background()

	// Test validation with a profile that loads but API call fails
	// This tests the error handling path in ValidateProfile
	err := ValidateProfile(ctx, "default")
	// ValidateProfile doesn't return error even if API call fails
	// It just logs and continues
	if err != nil {
		// Only error if config loading fails
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}
	// If we get here, validation succeeded (even if API call failed internally)
}

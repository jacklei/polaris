package aws

import (
	"context"
	"testing"
)

func TestGetECRClient(t *testing.T) {
	ctx := context.Background()

	// Test with default profile (may fail if AWS credentials not configured)
	client, err := GetECRClient(ctx, "default")
	if err != nil {
		// Skip test if AWS credentials not available
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	if client == nil {
		t.Error("GetECRClient() returned nil client")
	}
}

func TestGetECRClient_InvalidProfile(t *testing.T) {
	ctx := context.Background()

	// Test with non-existent profile
	_, err := GetECRClient(ctx, "non-existent-profile-12345")
	if err == nil {
		t.Error("GetECRClient() with invalid profile should return error")
	}
}

func TestGetInspector2Client(t *testing.T) {
	ctx := context.Background()

	// Test with default profile (may fail if AWS credentials not configured)
	client, err := GetInspector2Client(ctx, "default")
	if err != nil {
		// Skip test if AWS credentials not available
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	if client == nil {
		t.Error("GetInspector2Client() returned nil client")
	}
}

func TestGetInspector2Client_InvalidProfile(t *testing.T) {
	ctx := context.Background()

	// Test with non-existent profile
	_, err := GetInspector2Client(ctx, "non-existent-profile-12345")
	if err == nil {
		t.Error("GetInspector2Client() with invalid profile should return error")
	}
}

func TestGetImagePushedAt_Integration(t *testing.T) {
	ctx := context.Background()

	// This is an integration test that requires actual AWS credentials and ECR access
	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping integration test: AWS credentials not available: %v", err)
		return
	}

	// Test with a non-existent repository (should return empty string)
	result := GetImagePushedAt(ctx, client, "non-existent-repo-12345", "non-existent-tag")
	if result != "" {
		t.Errorf("GetImagePushedAt() with non-existent image = %v, want empty string", result)
	}
}

func TestGetCVECriticalCount_Integration(t *testing.T) {
	ctx := context.Background()

	// This is an integration test that requires actual AWS credentials and Inspector2 access
	client, err := GetInspector2Client(ctx, "default")
	if err != nil {
		t.Skipf("Skipping integration test: AWS credentials not available: %v", err)
		return
	}

	// Test with a non-existent repository (should return 0)
	result := GetCVECriticalCount(ctx, client, "non-existent-repo-12345", "non-existent-tag")
	if result != 0 {
		t.Errorf("GetCVECriticalCount() with non-existent image = %v, want 0", result)
	}
}

// Test the filter criteria construction logic
func TestGetCVECriticalCount_FilterCriteria(t *testing.T) {
	ctx := context.Background()

	// This test verifies that the function constructs filter criteria correctly
	// We can't easily test the full flow without mocking, but we can verify
	// the function handles errors gracefully
	client, err := GetInspector2Client(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with empty repository name
	result := GetCVECriticalCount(ctx, client, "", "")
	if result != 0 {
		t.Errorf("GetCVECriticalCount() with empty params = %v, want 0", result)
	}
}

// Test error handling for GetImagePushedAt
func TestGetImagePushedAt_ErrorHandling(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with empty repository name (should handle gracefully)
	result := GetImagePushedAt(ctx, client, "", "")
	if result != "" {
		t.Errorf("GetImagePushedAt() with empty params = %v, want empty string", result)
	}

	// Test with empty tag (should handle gracefully)
	result = GetImagePushedAt(ctx, client, "test-repo", "")
	if result != "" {
		t.Logf("GetImagePushedAt() with empty tag returned: %v (may be valid)", result)
	}
}

func TestGetCVECriticalCount_EmptyParams(t *testing.T) {
	ctx := context.Background()

	client, err := GetInspector2Client(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with empty repository name
	result := GetCVECriticalCount(ctx, client, "", "tag")
	if result != 0 {
		t.Errorf("GetCVECriticalCount() with empty repo = %v, want 0", result)
	}

	// Test with empty tag
	result = GetCVECriticalCount(ctx, client, "repo", "")
	if result != 0 {
		t.Errorf("GetCVECriticalCount() with empty tag = %v, want 0", result)
	}

	// Test with both empty
	result = GetCVECriticalCount(ctx, client, "", "")
	if result != 0 {
		t.Errorf("GetCVECriticalCount() with both empty = %v, want 0", result)
	}
}

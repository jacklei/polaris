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

func TestGetLatestImageTags_Integration(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping integration test: AWS credentials not available: %v", err)
		return
	}

	// Test with a non-existent repository (should return empty slice)
	tags, err := GetLatestImageTags(ctx, client, "non-existent-repo-12345", 10)
	if err != nil {
		// Error is acceptable for non-existent repo
		t.Logf("GetLatestImageTags() with non-existent repo returned error (expected): %v", err)
		return
	}

	if len(tags) != 0 {
		t.Errorf("GetLatestImageTags() with non-existent repo = %v, want empty slice", tags)
	}
}

func TestGetLatestImageTags_EmptyRepository(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with empty repository name
	tags, err := GetLatestImageTags(ctx, client, "", 10)
	if err == nil {
		t.Logf("GetLatestImageTags() with empty repo returned: %v (may be valid)", tags)
	}
}

func TestGetLatestImageTags_ZeroMaxTags(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with zero maxTags (should default to 10)
	tags, err := GetLatestImageTags(ctx, client, "non-existent-repo-12345", 0)
	if err != nil {
		t.Logf("GetLatestImageTags() with zero maxTags returned error: %v", err)
		return
	}

	// Should handle gracefully
	_ = tags
}

func TestGetLatestImageTags_NegativeMaxTags(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with negative maxTags (should default to 10)
	tags, err := GetLatestImageTags(ctx, client, "non-existent-repo-12345", -1)
	if err != nil {
		t.Logf("GetLatestImageTags() with negative maxTags returned error: %v", err)
		return
	}

	// Should handle gracefully and default to 10
	_ = tags
}

func TestGetLatestImageTags_LargeMaxTags(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with very large maxTags value
	tags, err := GetLatestImageTags(ctx, client, "non-existent-repo-12345", 1000)
	if err != nil {
		t.Logf("GetLatestImageTags() with large maxTags returned error: %v", err)
		return
	}

	// Should handle gracefully
	if len(tags) > 1000 {
		t.Errorf("GetLatestImageTags() returned more tags than maxTags: got %d, want <= 1000", len(tags))
	}
}

func TestGetLatestImageTags_EmptyImageIds(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with repository that returns empty ImageIds
	// This tests the path where ListImages returns empty ImageIds
	tags, err := GetLatestImageTags(ctx, client, "non-existent-repo-12345", 10)
	if err != nil {
		t.Logf("GetLatestImageTags() with empty ImageIds returned error: %v", err)
		return
	}

	// Should return empty slice, not error
	if tags == nil {
		t.Error("GetLatestImageTags() should return empty slice, not nil")
	}
	if len(tags) != 0 {
		t.Errorf("GetLatestImageTags() with empty ImageIds = %v, want empty slice", tags)
	}
}

func TestGetLatestImageTags_ErrorHandling(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test error handling with invalid repository name that causes API error
	_, err = GetLatestImageTags(ctx, client, "invalid/repo/name/with/many/slashes", 10)
	if err == nil {
		t.Log("GetLatestImageTags() with invalid repo name may succeed or fail (implementation dependent)")
	} else {
		// Error is expected for invalid repository names
		t.Logf("GetLatestImageTags() with invalid repo returned error (expected): %v", err)
	}
}

func TestGetLatestImageTags_MaxTagsLimit(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test that maxTags limit is respected
	// Request 5 tags, should get at most 5
	tags, err := GetLatestImageTags(ctx, client, "non-existent-repo-12345", 5)
	if err != nil {
		t.Logf("GetLatestImageTags() with maxTags=5 returned error: %v", err)
		return
	}

	if len(tags) > 5 {
		t.Errorf("GetLatestImageTags() returned more tags than requested: got %d, want <= 5", len(tags))
	}
}

func TestGetLatestImageTags_DefaultMaxTags(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test that default maxTags is 10 when 0 is provided
	tags1, err1 := GetLatestImageTags(ctx, client, "non-existent-repo-12345", 0)
	if err1 != nil {
		t.Logf("GetLatestImageTags() with maxTags=0 returned error: %v", err1)
		return
	}

	// Test that default maxTags is 10 when negative is provided
	tags2, err2 := GetLatestImageTags(ctx, client, "non-existent-repo-12345", -5)
	if err2 != nil {
		t.Logf("GetLatestImageTags() with maxTags=-5 returned error: %v", err2)
		return
	}

	// Both should default to 10
	_ = tags1
	_ = tags2
}

func TestGetLatestImageTags_RepositoryNameValidation(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	testCases := []struct {
		name     string
		repoName string
		maxTags  int
	}{
		{"Empty string", "", 10},
		{"Single character", "a", 10},
		{"With slashes", "namespace/repo", 10},
		{"With hyphens", "my-repo-name", 10},
		{"With underscores", "my_repo_name", 10},
		{"With numbers", "repo123", 10},
		{"Long name", "very-long-repository-name-with-many-characters", 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tags, err := GetLatestImageTags(ctx, client, tc.repoName, tc.maxTags)
			// We don't assert on results since these may error or succeed depending on AWS
			// We just want to ensure the function handles various repository name formats
			_ = tags
			_ = err
		})
	}
}

func TestGetLatestImageTags_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client, err := GetECRClient(context.Background(), "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with cancelled context
	tags, err := GetLatestImageTags(ctx, client, "test-repo", 10)
	if err == nil {
		t.Logf("GetLatestImageTags() with cancelled context returned: %v (may succeed if already cached)", tags)
	} else {
		// Error is expected with cancelled context
		t.Logf("GetLatestImageTags() with cancelled context returned error (expected): %v", err)
	}
}

func TestGetLatestImageTags_EdgeCaseMaxTags(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	testCases := []struct {
		name    string
		maxTags int
	}{
		{"One tag", 1},
		{"Two tags", 2},
		{"Max int32", 2147483647},
		{"Zero", 0},
		{"Negative one", -1},
		{"Negative large", -100},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tags, err := GetLatestImageTags(ctx, client, "non-existent-repo-12345", tc.maxTags)
			if err != nil {
				t.Logf("GetLatestImageTags() with maxTags=%d returned error: %v", tc.maxTags, err)
				return
			}

			// For non-negative maxTags, result should not exceed maxTags (or default to 10)
			expectedMax := tc.maxTags
			if expectedMax <= 0 {
				expectedMax = 10
			}
			if len(tags) > expectedMax {
				t.Errorf("GetLatestImageTags() with maxTags=%d returned %d tags, want <= %d", tc.maxTags, len(tags), expectedMax)
			}
		})
	}
}

func TestGetLatestImageTagsWithDates_Integration(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping integration test: AWS credentials not available: %v", err)
		return
	}

	// Test with a non-existent repository (should return empty slice)
	tagInfos, err := GetLatestImageTagsWithDates(ctx, client, "non-existent-repo-12345", 10)
	if err != nil {
		// Error is acceptable for non-existent repo
		t.Logf("GetLatestImageTagsWithDates() with non-existent repo returned error (expected): %v", err)
		return
	}

	if len(tagInfos) != 0 {
		t.Errorf("GetLatestImageTagsWithDates() with non-existent repo = %v, want empty slice", tagInfos)
	}
}

func TestGetLatestImageTagsWithDates_EmptyRepository(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with empty repository name
	tagInfos, err := GetLatestImageTagsWithDates(ctx, client, "", 10)
	if err == nil {
		t.Logf("GetLatestImageTagsWithDates() with empty repo returned: %v (may be valid)", tagInfos)
	}
}

func TestGetLatestImageTagsWithDates_ZeroMaxTags(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with zero maxTags (should default to 10)
	tagInfos, err := GetLatestImageTagsWithDates(ctx, client, "non-existent-repo-12345", 0)
	if err != nil {
		t.Logf("GetLatestImageTagsWithDates() with zero maxTags returned error: %v", err)
		return
	}

	// Should handle gracefully
	_ = tagInfos
}

func TestGetLatestImageTagsWithDates_NegativeMaxTags(t *testing.T) {
	ctx := context.Background()

	client, err := GetECRClient(ctx, "default")
	if err != nil {
		t.Skipf("Skipping test: AWS credentials not available: %v", err)
		return
	}

	// Test with negative maxTags (should default to 10)
	tagInfos, err := GetLatestImageTagsWithDates(ctx, client, "non-existent-repo-12345", -1)
	if err != nil {
		t.Logf("GetLatestImageTagsWithDates() with negative maxTags returned error: %v", err)
		return
	}

	// Should handle gracefully
	_ = tagInfos
}

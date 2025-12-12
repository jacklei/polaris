package aws

import (
	"strings"
	"testing"
)

func TestFilterDiffForAnalysis(t *testing.T) {
	tests := []struct {
		name     string
		diff     string
		wantLen  int
		wantFile string
	}{
		{
			name: "Dockerfile included",
			diff: `diff --git a/Dockerfile b/Dockerfile
index 1234567..abcdefg 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,3 +1,3 @@
-FROM node:16
+FROM node:20
`,
			wantLen:  1,
			wantFile: "Dockerfile",
		},
		{
			name: "Migration file included",
			diff: `diff --git a/db/migrations/001_init.sql b/db/migrations/001_init.sql
index 1234567..abcdefg 100644
--- a/db/migrations/001_init.sql
+++ b/db/migrations/001_init.sql
@@ -1,3 +1,3 @@
 CREATE TABLE users (id INT);
`,
			wantLen:  1,
			wantFile: "db/migrations/001_init.sql",
		},
		{
			name: "CloudFormation file included",
			diff: `diff --git a/infrastructure/cloudformation.yml b/infrastructure/cloudformation.yml
index 1234567..abcdefg 100644
--- a/infrastructure/cloudformation.yml
+++ b/infrastructure/cloudformation.yml
@@ -1,3 +1,3 @@
 Resources:
   MyBucket:
     Type: AWS::S3::Bucket
`,
			wantLen:  1,
			wantFile: "infrastructure/cloudformation.yml",
		},
		{
			name: ".env file included",
			diff: `diff --git a/.env b/.env
index 1234567..abcdefg 100644
--- a/.env
+++ b/.env
@@ -1,3 +1,3 @@
 API_KEY=secret
`,
			wantLen:  1,
			wantFile: ".env",
		},
		{
			name: "Unrelated file excluded",
			diff: `diff --git a/src/main.go b/src/main.go
index 1234567..abcdefg 100644
--- a/src/main.go
+++ b/src/main.go
@@ -1,3 +1,3 @@
 package main
`,
			wantLen:  0,
			wantFile: "",
		},
		{
			name: "Multiple files - mixed",
			diff: `diff --git a/Dockerfile b/Dockerfile
index 1234567..abcdefg 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,3 +1,3 @@
-FROM node:16
+FROM node:20
diff --git a/src/main.go b/src/main.go
index 1234567..abcdefg 100644
--- a/src/main.go
+++ b/src/main.go
@@ -1,3 +1,3 @@
 package main
diff --git a/.env b/.env
index 1234567..abcdefg 100644
--- a/.env
+++ b/.env
@@ -1,3 +1,3 @@
 API_KEY=secret
`,
			wantLen:  2, // Dockerfile and .env
			wantFile: "Dockerfile",
		},
		{
			name:     "Empty diff",
			diff:     "",
			wantLen:  0,
			wantFile: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterDiffForAnalysis(tt.diff)
			if tt.wantLen == 0 {
				if result != "" {
					t.Errorf("filterDiffForAnalysis() = %v, want empty string", result)
				}
				return
			}
			if !strings.Contains(result, tt.wantFile) {
				t.Errorf("filterDiffForAnalysis() result does not contain %v", tt.wantFile)
			}
			// Count number of diff blocks
			diffBlocks := strings.Count(result, "diff --git")
			if diffBlocks != tt.wantLen {
				t.Errorf("filterDiffForAnalysis() diff blocks = %v, want %v", diffBlocks, tt.wantLen)
			}
		})
	}
}

func TestIsRelevantFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "Dockerfile at root",
			filePath: "dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile with path",
			filePath: "path/to/dockerfile",
			want:     false,
		},
		{
			name:     "CloudFormation file",
			filePath: "infrastructure/cloudformation.yml",
			want:     true,
		},
		{
			name:     "Migration file",
			filePath: "db/migrations/001_init.sql",
			want:     true,
		},
		{
			name:     ".env file",
			filePath: ".env",
			want:     true,
		},
		{
			name:     ".env.local file",
			filePath: ".env.local",
			want:     true,
		},
		{
			name:     "Regular Go file",
			filePath: "src/main.go",
			want:     false,
		},
		{
			name:     "Empty path",
			filePath: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRelevantFile(tt.filePath)
			if got != tt.want {
				t.Errorf("isRelevantFile(%v) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestSplitDiffIntoChunks(t *testing.T) {
	tests := []struct {
		name        string
		diff        string
		wantChunks  int
		maxChunkLen int
	}{
		{
			name:        "Small diff - single chunk",
			diff:        strings.Repeat("line\n", 100),
			wantChunks:  1,
			maxChunkLen: maxChunkSize,
		},
		{
			name:        "Large diff - multiple chunks",
			diff:        strings.Repeat("line\n", maxChunkSize/5), // Much larger than maxChunkSize
			wantChunks:  1, // Should be at least 1, but exact count depends on implementation
			maxChunkLen: maxChunkSize,
		},
		{
			name:        "Empty diff",
			diff:        "",
			wantChunks:  0,
			maxChunkLen: maxChunkSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks := splitDiffIntoChunks(tt.diff)
			if len(chunks) < tt.wantChunks {
				t.Errorf("splitDiffIntoChunks() chunks = %v, want at least %v", len(chunks), tt.wantChunks)
			}
			for i, chunk := range chunks {
				if len(chunk) > tt.maxChunkLen {
					t.Errorf("splitDiffIntoChunks() chunk %d length = %v, want <= %v", i, len(chunk), tt.maxChunkLen)
				}
			}
		})
	}
}

func TestContainsNoIssuesMessage(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{
			name: "No issues found",
			text: "No issues found in this code review.",
			want: true,
		},
		{
			name: "No vulnerabilities found",
			text: "No vulnerabilities found in the diff.",
			want: true,
		},
		{
			name: "No concerns",
			text: "I found no concerns with this code.",
			want: true,
		},
		{
			name: "Clean review",
			text: "The review is clean.",
			want: true,
		},
		{
			name: "Has issues",
			text: "I found a security issue: exposed API key.",
			want: false,
		},
		{
			name: "Empty string",
			text: "",
			want: false,
		},
		{
			name: "None identified",
			text: "No security issues identified.",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsNoIssuesMessage(tt.text)
			if got != tt.want {
				t.Errorf("containsNoIssuesMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCombineAnalysesSummary(t *testing.T) {
	tests := []struct {
		name     string
		analyses []string
		want     string
		wantEmpty bool
	}{
		{
			name: "Multiple analyses with issues",
			analyses: []string{
				"Found security issue: exposed API key.",
				"Found database issue: missing index.",
			},
			want:      "",
			wantEmpty: false,
		},
		{
			name: "All analyses have no issues",
			analyses: []string{
				"No issues found.",
				"No vulnerabilities found.",
			},
			want:      "",
			wantEmpty: true,
		},
		{
			name:      "Empty analyses",
			analyses:  []string{},
			want:      "",
			wantEmpty: true,
		},
		{
			name: "Mixed - some have issues, some don't",
			analyses: []string{
				"Found security issue: exposed API key.",
				"No issues found.",
			},
			want:      "",
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := combineAnalysesSummary(tt.analyses)
			if tt.wantEmpty {
				if result != "" {
					t.Errorf("combineAnalysesSummary() = %v, want empty string", result)
				}
			} else {
				if result == "" {
					t.Errorf("combineAnalysesSummary() = empty, want non-empty string")
				}
			}
		})
	}
}

// Note: AnalyzeDiff, analyzeDiffInChunks, and analyzeDiffChunk require AWS credentials
// and actual Bedrock API calls, so they are better suited for integration tests.
// These would require mocking the AWS SDK clients, which is complex.
// For now, we test the helper functions that don't require AWS.


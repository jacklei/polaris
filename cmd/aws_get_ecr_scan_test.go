package cmd

import (
	"testing"
)

func TestParseImageTag(t *testing.T) {
	tests := []struct {
		name           string
		imageArg       string
		wantRepo       string
		wantTag        string
		wantErr        bool
		expectedErrMsg string
	}{
		{
			name:     "Simple repository:tag",
			imageArg: "my-repo:v1.0.0",
			wantRepo: "my-repo",
			wantTag:  "v1.0.0",
			wantErr:  false,
		},
		{
			name:     "Repository without tag",
			imageArg: "my-repo",
			wantRepo: "my-repo",
			wantTag:  "",
			wantErr:  false,
		},
		{
			name:     "Namespace/repository:tag",
			imageArg: "namespace/my-repo:v1.0.0",
			wantRepo: "my-repo",
			wantTag:  "v1.0.0",
			wantErr:  false,
		},
		{
			name:     "ECR host prefix with repository:tag",
			imageArg: "255479557906.dkr.ecr.us-east-1.amazonaws.com/my-repo:v1.0.0",
			wantRepo: "my-repo",
			wantTag:  "v1.0.0",
			wantErr:  false,
		},
		{
			name:     "ECR host prefix without tag",
			imageArg: "255479557906.dkr.ecr.us-east-1.amazonaws.com/my-repo",
			wantRepo: "my-repo",
			wantTag:  "",
			wantErr:  false,
		},
		{
			name:     "Multiple slashes",
			imageArg: "registry.example.com/namespace/my-repo:v1.0.0",
			wantRepo: "my-repo",
			wantTag:  "v1.0.0",
			wantErr:  false,
		},
		{
			name:     "Tag with colon",
			imageArg: "my-repo:tag:with:colons",
			wantRepo: "my-repo",
			wantTag:  "tag:with:colons",
			wantErr:  false,
		},
		{
			name:           "Empty repository name",
			imageArg:       ":tag",
			wantRepo:       "",
			wantTag:        "",
			wantErr:        true,
			expectedErrMsg: "repository name cannot be empty",
		},
		{
			name:           "Empty string",
			imageArg:       "",
			wantRepo:       "",
			wantTag:        "",
			wantErr:        true,
			expectedErrMsg: "repository name cannot be empty",
		},
		{
			name:     "Repository ending with slash",
			imageArg: "namespace/",
			wantRepo: "namespace/", // The function doesn't strip trailing slashes, only extracts after last slash if not at end
			wantTag:  "",
			wantErr:  false, // This doesn't error, it just uses the whole string
		},
		{
			name:     "Just slash",
			imageArg: "/",
			wantRepo: "/", // The function doesn't strip trailing slashes
			wantTag:  "",
			wantErr:  false, // This doesn't error, it just uses the whole string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRepo, gotTag, err := parseImageTag(tt.imageArg)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseImageTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotRepo != tt.wantRepo {
				t.Errorf("parseImageTag() gotRepo = %v, want %v", gotRepo, tt.wantRepo)
			}
			if gotTag != tt.wantTag {
				t.Errorf("parseImageTag() gotTag = %v, want %v", gotTag, tt.wantTag)
			}
			if tt.wantErr && tt.expectedErrMsg != "" {
				if err == nil || err.Error() != tt.expectedErrMsg {
					t.Errorf("parseImageTag() error = %v, want error message %v", err, tt.expectedErrMsg)
				}
			}
		})
	}
}


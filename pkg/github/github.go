package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ParseGitHubURL parses a GitHub URL and extracts owner, repo, and diff information
func ParseGitHubURL(urlStr string) (owner, repo, diffType, identifier string, err error) {
	// Parse the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid URL: %w", err)
	}

	// Check if it's a GitHub URL
	if parsedURL.Host != "github.com" && !strings.HasSuffix(parsedURL.Host, ".github.com") {
		return "", "", "", "", fmt.Errorf("not a GitHub URL")
	}

	// Extract path components
	path := strings.Trim(parsedURL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", "", "", "", fmt.Errorf("invalid GitHub URL format")
	}

	owner = parts[0]
	repo = parts[1]

	// Determine diff type and identifier
	if len(parts) >= 3 {
		switch parts[2] {
		case "pull":
			if len(parts) >= 4 {
				diffType = "pull_request"
				identifier = parts[3]
				return owner, repo, diffType, identifier, nil
			}
		case "commit":
			if len(parts) >= 4 {
				diffType = "commit"
				identifier = parts[3]
				return owner, repo, diffType, identifier, nil
			}
		case "compare":
			if len(parts) >= 4 {
				diffType = "compare"
				identifier = strings.Join(parts[3:], "/")
				return owner, repo, diffType, identifier, nil
			}
		}
	}

	return "", "", "", "", fmt.Errorf("unsupported GitHub URL type")
}

// FetchDiff fetches the diff from GitHub API
func FetchDiff(ctx context.Context, token, owner, repo, diffType, identifier string) (string, error) {
	var apiURL string

	switch diffType {
	case "pull_request":
		// Fetch PR diff
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%s", owner, repo, identifier)
	case "commit":
		// Fetch commit diff
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", owner, repo, identifier)
	case "compare":
		// Fetch compare diff
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s", owner, repo, identifier)
	default:
		return "", fmt.Errorf("unsupported diff type: %s", diffType)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/vnd.github.v3.diff")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("User-Agent", "polaris")

	// Make request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	// Read response body
	diffBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(diffBytes), nil
}

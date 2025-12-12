package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jacklei/polaris/pkg/claude"
	"github.com/jacklei/polaris/pkg/output"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var useClaude bool
var claudeProfile string

// githubCheckDiffCmd represents the check-diff command
var githubCheckDiffCmd = &cobra.Command{
	Use:   "check-diff",
	Short: "Check a GitHub diff",
	Long: `Checks a GitHub diff from a pull request or commit URL.
	
The diff link can be:
  - A pull request URL (e.g., https://github.com/owner/repo/pull/123)
  - A commit URL (e.g., https://github.com/owner/repo/commit/abc123)
  - A compare URL (e.g., https://github.com/owner/repo/compare/main...feature)`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		diffURL := args[0]

		// Parse the GitHub URL
		owner, repo, diffType, identifier, err := parseGitHubURL(diffURL)
		if err != nil {
			log.Error().Err(err).Str("url", diffURL).Msg("Failed to parse GitHub URL")
			return
		}

		log.Info().
			Str("owner", owner).
			Str("repo", repo).
			Str("type", diffType).
			Str("identifier", identifier).
			Msg("Parsed GitHub URL")

		// Get GitHub token
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			log.Error().Msg("GITHUB_TOKEN environment variable is required")
			return
		}

		// Fetch the diff
		diff, err := fetchGitHubDiff(ctx, token, owner, repo, diffType, identifier)
		if err != nil {
			log.Error().Err(err).Msg("Failed to fetch GitHub diff")
			return
		}

		// If Claude analysis is enabled, analyze the diff
		var claudeAnalysis string
		if useClaude {
			log.Info().Str("profile", claudeProfile).Msg("Analyzing diff with Claude via AWS Bedrock...")
			claudeAnalysis, err = claude.AnalyzeDiff(ctx, claudeProfile, diff)
			if err != nil {
				log.Error().Err(err).Msg("Failed to analyze diff with Claude")
				return
			}
			log.Info().
				Int("analysis_length", len(claudeAnalysis)).
				Bool("is_empty", claudeAnalysis == "").
				Msg("Claude analysis complete")
		}

		// Prepare output
		if useClaude {
			// Check if analysis indicates no issues - if so, don't print anything
			if claudeAnalysis == "" {
				// Empty analysis means no concerns found
				return
			}

			// Always show output for Claude analysis (output layer will filter if no concerns)
			result := map[string]interface{}{
				"url":             diffURL,
				"owner":           owner,
				"repo":            repo,
				"type":            diffType,
				"diff_size":       len(diff),
				"claude_analysis": claudeAnalysis,
			}

			if err := output.Print(result, outputType, "", false, ""); err != nil {
				log.Error().Err(err).Msg("Failed to print output")
			}
		} else {
			// Not using Claude, show diff as normal
			result := map[string]interface{}{
				"url":       diffURL,
				"owner":     owner,
				"repo":      repo,
				"type":      diffType,
				"diff_size": len(diff),
				"diff":      diff,
			}

			if err := output.Print(result, outputType, "", false, ""); err != nil {
				log.Error().Err(err).Msg("Failed to print output")
			}
		}
	},
}

func init() {
	githubCmd.AddCommand(githubCheckDiffCmd)

	// Add Claude analysis flag
	githubCheckDiffCmd.Flags().BoolVar(&useClaude, "claude", false, "Use Claude AI to analyze the diff for SRE technical review (security, database queries, exposed secrets)")
	githubCheckDiffCmd.Flags().StringVar(&claudeProfile, "claude-profile", "default", "AWS profile to use for Claude via Bedrock (when --claude is enabled)")
}

// parseGitHubURL parses a GitHub URL and extracts owner, repo, and diff information
func parseGitHubURL(urlStr string) (owner, repo, diffType, identifier string, err error) {
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

// fetchGitHubDiff fetches the diff from GitHub API
func fetchGitHubDiff(ctx context.Context, token, owner, repo, diffType, identifier string) (string, error) {
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

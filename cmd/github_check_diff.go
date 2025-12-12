package cmd

import (
	"context"
	"os"

	"github.com/jacklei/polaris/pkg/aws"
	"github.com/jacklei/polaris/pkg/github"
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
		owner, repo, diffType, identifier, err := github.ParseGitHubURL(diffURL)
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
		diff, err := github.FetchDiff(ctx, token, owner, repo, diffType, identifier)
		if err != nil {
			log.Error().Err(err).Msg("Failed to fetch GitHub diff")
			return
		}

		// If Claude analysis is enabled, analyze the diff
		var claudeAnalysis string
		if useClaude {
			log.Info().Str("profile", claudeProfile).Msg("Analyzing diff with Claude via AWS Bedrock...")
			claudeAnalysis, err = aws.AnalyzeDiff(ctx, claudeProfile, diff)
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

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jacklei/polaris/pkg/github"
	"github.com/jacklei/polaris/pkg/output"
	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var orgName string
var reposList []string
var repoLimit int

// githubCheckDeprecationsCmd represents the check-deprecations command
var githubCheckDeprecationsCmd = &cobra.Command{
	Use:   "check-deprecations",
	Short: "Check Dockerfiles for deprecated language versions",
	Long: `Checks Dockerfiles across repositories for deprecated language versions.
	
You can specify repositories either by:
  - Providing an organization name (--org) to check all repos in that org (defaults to Acornsgrow)
  - Providing a comma-separated list of repository names (--repos repo1,repo2) which will use the org from --org`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		// Get GitHub token
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			log.Error().Msg("GITHUB_TOKEN environment variable is required")
			return
		}

		var repos []string
		if len(reposList) > 0 {
			// Use explicitly provided repos - prepend org if not already included
			for _, repo := range reposList {
				if strings.Contains(repo, "/") {
					// Already has org/repo format
					repos = append(repos, repo)
				} else {
					// Just repo name, prepend org
					repos = append(repos, fmt.Sprintf("%s/%s", orgName, repo))
				}
			}
		} else if orgName != "" {
			// Fetch repos from organization (defaults to Acornsgrow)
			log.Info().Str("org", orgName).Msg("Fetching repositories from organization")
			orgRepos, err := github.ListOrgRepos(ctx, token, orgName)
			if err != nil {
				log.Error().Err(err).Str("org", orgName).Msg("Failed to fetch repositories")
				return
			}
			repos = orgRepos

			// Apply limit if specified
			if repoLimit > 0 && len(repos) > repoLimit {
				repos = repos[:repoLimit]
			}

			log.Info().Int("count", len(repos)).Msg("Found repositories")
		} else {
			log.Error().Msg("Either --org or --repos must be specified")
			return
		}

		// Initialize progress bar
		pw := progress.NewWriter()
		pw.SetOutputWriter(os.Stderr)
		pw.SetStyle(progress.StyleDefault)
		pw.SetTrackerPosition(progress.PositionRight)
		pw.SetUpdateFrequency(time.Millisecond * 50)

		tracker := &progress.Tracker{
			Message: fmt.Sprintf("Checking %d repositories for deprecations", len(repos)),
			Total:   int64(len(repos)),
			Units:   progress.UnitsDefault,
		}
		pw.AppendTracker(tracker)

		// Start progress bar rendering
		go pw.Render()
		defer pw.Stop()

		// Check deprecations for each repo in parallel
		var allDeprecations []map[string]interface{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		maxConcurrent := 10 // Limit concurrent API calls to avoid rate limits
		semaphore := make(chan struct{}, maxConcurrent)

		for _, repo := range repos {
			wg.Add(1)
			go func(repoName string) {
				defer wg.Done()

				// Acquire semaphore
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				deprecations, err := github.CheckDockerfileDeprecations(ctx, token, repoName)
				if err != nil {
					log.Warn().Err(err).Str("repo", repoName).Msg("Failed to check repository")
					tracker.Increment(1)
					return
				}

				if len(deprecations) > 0 {
					mu.Lock()
					allDeprecations = append(allDeprecations, deprecations...)
					mu.Unlock()
				}

				tracker.Increment(1)
			}(repo)
		}

		wg.Wait()

		// Prepare output
		if len(allDeprecations) > 0 {
			result := map[string]interface{}{
				"deprecations": allDeprecations,
			}
			if err := output.Print(result, outputType, "", false, ""); err != nil {
				log.Error().Err(err).Msg("Failed to print output")
			}
		} else {
			log.Info().Msg("No deprecated language versions found")
		}
	},
}

func init() {
	githubCmd.AddCommand(githubCheckDeprecationsCmd)

	githubCheckDeprecationsCmd.Flags().StringVar(&orgName, "org", "Acornsgrow", "GitHub organization name to check all repositories")
	githubCheckDeprecationsCmd.Flags().StringSliceVar(&reposList, "repos", []string{}, "Comma-separated list of repository names to check (will use org from --org, or specify as org/repo)")
	githubCheckDeprecationsCmd.Flags().IntVar(&repoLimit, "limit", 0, "Limit the number of repositories to check (0 = no limit)")
}

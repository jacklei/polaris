package claude

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/rs/zerolog/log"
)

const (
	// maxChunkSize is the maximum size of a diff chunk to send to Claude (in characters)
	// Claude 3 Sonnet has a 200k token input limit. Code diffs can be token-dense (2-3 chars/token).
	// We use 50k chars to be conservative, accounting for:
	// - Prompt overhead (~1k tokens)
	// - Response space (4k tokens)
	// - Token density of code diffs (could be 2-3 chars/token)
	// This gives us roughly: 50k/2.5 = ~20k tokens for diff + 1k prompt = ~21k tokens total
	// If you still hit "input too long" errors, reduce to 40k. If you want faster processing, increase to 60k.
	maxChunkSize = 50000
	// maxConcurrentChunks is the maximum number of chunks to analyze in parallel
	// Set to 10 as a balance between speed and AWS Bedrock rate limits.
	// Standard tier accounts typically allow 5-10 req/sec, higher tiers allow more.
	// If you hit rate limits, reduce this to 5. If you have a higher tier account, increase to 15-20.
	maxConcurrentChunks = 10
)

// AnalyzeDiff analyzes a diff using Claude via AWS Bedrock with the specified AWS profile
// If the diff is too large, it will be split into chunks and analyzed separately
// Only analyzes Dockerfiles, database/migration files, and infrastructure/CloudFormation files
func AnalyzeDiff(ctx context.Context, profile, diff string) (string, error) {
	// Load AWS config
	var cfg aws.Config
	var err error

	if profile == "" || profile == "default" {
		cfg, err = awsconfig.LoadDefaultConfig(ctx)
	} else {
		cfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithSharedConfigProfile(profile),
		)
	}

	if err != nil {
		return "", fmt.Errorf("failed to load AWS config for profile %s: %w", profile, err)
	}

	// Create Bedrock Runtime client
	client := bedrockruntime.NewFromConfig(cfg)

	// Filter diff to only include relevant files
	filteredDiff := filterDiffForAnalysis(diff)
	if filteredDiff == "" {
		// No relevant files found, return empty (no concerns)
		return "", nil
	}

	log.Info().
		Int("original_size", len(diff)).
		Int("filtered_size", len(filteredDiff)).
		Msg("Filtered diff to relevant files only")

	// Check if diff needs to be chunked
	if len(filteredDiff) > maxChunkSize {
		log.Info().Int("diff_size", len(filteredDiff)).Msg("Diff is too large, splitting into chunks")
		return analyzeDiffInChunks(ctx, client, filteredDiff)
	}

	return analyzeDiffChunk(ctx, client, filteredDiff, 1, 1)
}

// filterDiffForAnalysis filters a diff to only include:
// - Dockerfiles
// - Database/migration files
// - Infrastructure/CloudFormation files
func filterDiffForAnalysis(diff string) string {
	lines := strings.Split(diff, "\n")
	var filteredLines []string
	var inRelevantFile bool
	var fileHunk strings.Builder

	for _, line := range lines {
		// Check for file header (diff --git or similar)
		if strings.HasPrefix(line, "diff --git") {
			// Save previous file if it was relevant
			if inRelevantFile && fileHunk.Len() > 0 {
				filteredLines = append(filteredLines, strings.TrimRight(fileHunk.String(), "\n"))
				fileHunk.Reset()
			}
			inRelevantFile = false
			fileHunk.WriteString(line)
			fileHunk.WriteString("\n")
			continue
		}

		// Check for file path indicators (+++ or ---)
		if strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") {
			fileHunk.WriteString(line)
			fileHunk.WriteString("\n")

			// Extract filename from +++ b/path/to/file or --- a/path/to/file
			parts := strings.Fields(line)
			if len(parts) > 1 {
				filePath := parts[1]
				// Remove a/ or b/ prefix
				if len(filePath) > 2 && (filePath[0:2] == "a/" || filePath[0:2] == "b/") {
					filePath = filePath[2:]
				}

				// Check if file is relevant
				filePathLower := strings.ToLower(filePath)
				if isRelevantFile(filePathLower) {
					inRelevantFile = true
				}
			}
			continue
		}

		// Include index lines and hunk headers for all files (needed for diff structure)
		if strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "@@") {
			fileHunk.WriteString(line)
			fileHunk.WriteString("\n")
			continue
		}

		// If we're in a relevant file, include all lines
		if inRelevantFile {
			fileHunk.WriteString(line)
			fileHunk.WriteString("\n")
		} else {
			// Not a relevant file, reset the hunk
			fileHunk.Reset()
		}
	}

	// Don't forget the last file
	if inRelevantFile && fileHunk.Len() > 0 {
		filteredLines = append(filteredLines, strings.TrimRight(fileHunk.String(), "\n"))
	}

	if len(filteredLines) == 0 {
		return ""
	}

	return strings.Join(filteredLines, "\n")
}

// isRelevantFile checks if a file path is relevant for SRE analysis
func isRelevantFile(filePath string) bool {
	// Normalize path separators
	filePath = strings.ReplaceAll(filePath, "\\", "/")

	// Dockerfile is always at project root (exact match)
	if filePath == "Dockerfile" || filePath == "dockerfile" {
		return true
	}

	// CloudFormation file is always at infrastructure/cloudformation.yml (exact match)
	if filePath == "infrastructure/cloudformation.yml" ||
		filePath == "infrastructure/cloudformation.yaml" {
		return true
	}

	// .env files (including .env.local, .env.production, etc.)
	if strings.HasPrefix(filePath, ".env") || strings.Contains(filePath, "/.env") {
		return true
	}

	// Database and migration files
	if strings.Contains(filePath, "migration") ||
		strings.Contains(filePath, "migrate") ||
		strings.Contains(filePath, "schema") ||
		strings.Contains(filePath, "database") ||
		strings.Contains(filePath, "db/") ||
		strings.Contains(filePath, "/db/") ||
		strings.HasSuffix(filePath, ".sql") ||
		strings.HasSuffix(filePath, ".migration") {
		return true
	}

	return false
}

// analyzeDiffInChunks splits a large diff into chunks and analyzes each separately in parallel
func analyzeDiffInChunks(ctx context.Context, client *bedrockruntime.Client, diff string) (string, error) {
	chunks := splitDiffIntoChunks(diff)
	log.Info().Int("chunk_count", len(chunks)).Int("max_concurrent", maxConcurrentChunks).Msg("Split diff into chunks, analyzing in parallel")

	// Use a semaphore to limit concurrent requests
	semaphore := make(chan struct{}, maxConcurrentChunks)
	var wg sync.WaitGroup
	mu := sync.Mutex{}
	allAnalyses := make([]string, len(chunks))
	var firstError error

	for i, chunk := range chunks {
		wg.Add(1)
		go func(chunkIndex int, chunkContent string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			log.Info().Int("chunk", chunkIndex+1).Int("total_chunks", len(chunks)).Msg("Analyzing chunk")
			analysis, err := analyzeDiffChunk(ctx, client, chunkContent, chunkIndex+1, len(chunks))

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				if firstError == nil {
					firstError = fmt.Errorf("failed to analyze chunk %d/%d: %w", chunkIndex+1, len(chunks), err)
				}
				return
			}

			allAnalyses[chunkIndex] = analysis
		}(i, chunk)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	if firstError != nil {
		return "", firstError
	}

	// Combine all analyses into a high-level summary
	return combineAnalysesSummary(allAnalyses), nil
}

// splitDiffIntoChunks splits a diff into chunks, trying to split at file boundaries when possible
func splitDiffIntoChunks(diff string) []string {
	// Try to split by file boundaries first (look for "diff --git" markers)
	lines := strings.Split(diff, "\n")
	var chunks []string
	var currentChunk strings.Builder
	currentSize := 0

	for _, line := range lines {
		lineSize := len(line) + 1 // +1 for newline

		// Check if we've hit a file boundary and current chunk is substantial
		if strings.HasPrefix(line, "diff --git") && currentSize > maxChunkSize/2 {
			// Save current chunk and start a new one
			if currentChunk.Len() > 0 {
				chunks = append(chunks, currentChunk.String())
				currentChunk.Reset()
				currentSize = 0
			}
		}

		// If adding this line would exceed the limit, save current chunk
		if currentSize+lineSize > maxChunkSize && currentChunk.Len() > 0 {
			chunks = append(chunks, currentChunk.String())
			currentChunk.Reset()
			currentSize = 0
		}

		// Add line to current chunk
		if currentChunk.Len() > 0 {
			currentChunk.WriteString("\n")
		}
		currentChunk.WriteString(line)
		currentSize += lineSize
	}

	// Add the last chunk if it has content
	if currentChunk.Len() > 0 {
		chunks = append(chunks, currentChunk.String())
	}

	// If we didn't create any chunks (diff was small), return the original
	if len(chunks) == 0 {
		return []string{diff}
	}

	return chunks
}

// analyzeDiffChunk analyzes a single chunk of a diff
func analyzeDiffChunk(ctx context.Context, client *bedrockruntime.Client, diffChunk string, chunkNum, totalChunks int) (string, error) {
	chunkInfo := ""
	if totalChunks > 1 {
		chunkInfo = fmt.Sprintf("\n\nNote: This is chunk %d of %d. Please analyze this portion of the diff.", chunkNum, totalChunks)
	}

	// Prepare the prompt for SRE technical review
	prompt := fmt.Sprintf(`You are an SRE performing a technical review of a code diff. Provide direct, actionable feedback focusing on real issues that need to be addressed. Be concise and specific.

Review the following areas:

**Security & Secrets:**
- Exposed secrets, credentials, API keys, passwords, or tokens
- Security vulnerabilities or insecure coding practices
- Missing authentication or authorization checks

**Database & Migrations:**
- SQL injection vulnerabilities
- Inefficient queries (missing indexes, full table scans, N+1 queries)
- Database type choices: In PostgreSQL, prefer JSONB over JSON. Per Postgres docs: "In general, most applications should prefer to store JSON data as jsonb, unless there are quite specialized needs, such as legacy assumptions about ordering of object keys." Even if JSON seems fine now, JSONB will be more performant in the future or during incidents.
- Migration anti-patterns: 
  * Migrations should only handle schema changes (adding columns, indexes, constraints, etc.)
  * Data changes and transformations should be broken out into separate scripts, not migrations
  * Migrations that process every row individually should be one-off tasks/scripts
  * Migrations must be fast and idempotent
  * If there are no new features, there shouldn't be migrations
  * Never use foreign key constraints
  * Never alter database timezone (e.g., "ALTER DATABASE set timezone"). Always use UTC in application code, do not alter the database timezone
- Index requirements:
  * Any "id" column should have an index
  * Any "nonce" column should have a unique index, otherwise it's not actually unique/nonce
  * Be careful of new indexes on large databases - prefer "CREATE INDEX CONCURRENTLY" instead of blocking "CREATE INDEX" to avoid locking tables during index creation
- Missing indexes on frequently queried columns
- Database schema issues that could cause performance problems

**Dockerfile:**
- Layer optimization: Consolidate related operations into single RUN commands to minimize layers
  * Example: Install dependencies AND remove sensitive files (like .npmrc) in the SAME layer, not separate RUN commands
  * Commands that don't do anything useful (e.g., "rm" in separate RUN that gets cached and doesn't actually remove anything)
  * Each RUN command creates a new layer - group related operations together
- Security: non-root user, specific image tags (not 'latest'), unnecessary packages, exposed ports
- Secrets in layers (use multi-stage builds or build args properly)

**CloudFormation/Infrastructure:**
- Security misconfigurations, overly permissive IAM policies
- Missing encryption, exposed resources
- Infrastructure security concerns
- Web services need to have more than 1 task (for high availability and redundancy)

**General:**
- Performance issues
- Best practice violations
- Code that will cause operational problems

Provide direct feedback like: "Why did you do X? Y would be better because Z." or "Switch it to JSONB. You may not need it now, but in the future or in an incident, the JSONB will be more performant." Be specific about what's wrong and what should be done instead. Only report actual issues - if there are no concerns, don't mention it.%s

Here is the diff to review:

%s`, chunkInfo, diffChunk)

	// Prepare the request body for Claude Opus 4.5 via Bedrock
	// Bedrock uses a different format than the direct API
	requestBody := map[string]interface{}{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        4096,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": prompt,
					},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Invoke Claude via Bedrock
	// Use Claude Opus 4.5, fallback to Claude 3 Sonnet if needed
	modelID := "anthropic.claude-opus-4-5-20250514-v1:0"

	output, err := client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(modelID),
		ContentType: aws.String("application/json"),
		Body:        jsonBody,
	})

	if err != nil {
		// Try Claude 3 Sonnet as fallback
		modelID = "anthropic.claude-3-sonnet-20240229-v1:0"
		output, err = client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
			ModelId:     aws.String(modelID),
			ContentType: aws.String("application/json"),
			Body:        jsonBody,
		})
		if err != nil {
			return "", fmt.Errorf("failed to invoke Claude model: %w", err)
		}
	}

	// Parse the response
	var response struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(output.Body, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(response.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude")
	}

	return response.Content[0].Text, nil
}

// combineAnalysesSummary creates a high-level summary from multiple chunk analyses
func combineAnalysesSummary(analyses []string) string {
	if len(analyses) == 0 {
		return ""
	}

	// Check single analysis for "no issues" messages
	if len(analyses) == 1 {
		analysis := analyses[0]
		if containsNoIssuesMessage(analysis) {
			return ""
		}
		return analysis
	}

	// Combine all analyses into one text for summary extraction
	var allText strings.Builder
	for _, analysis := range analyses {
		allText.WriteString(analysis)
		allText.WriteString("\n\n")
	}

	combinedText := allText.String()

	// Ask Claude to create a high-level summary
	// For now, we'll create a simple summary by extracting key findings
	// In a more sophisticated implementation, we could send this back to Claude for summarization

	var summary strings.Builder
	summary.WriteString("# SRE Technical Review Summary\n\n")
	summary.WriteString(fmt.Sprintf("Analyzed %d chunks of diff. Key findings:\n\n", len(analyses)))

	// Extract key findings from combined text
	lines := strings.Split(combinedText, "\n")
	var findings []string
	var currentFinding strings.Builder
	inFinding := false

	for _, line := range lines {
		lineLower := strings.ToLower(strings.TrimSpace(line))

		// Detect finding markers
		if strings.Contains(lineLower, "security") ||
			strings.Contains(lineLower, "vulnerability") ||
			strings.Contains(lineLower, "sql injection") ||
			strings.Contains(lineLower, "secret") ||
			strings.Contains(lineLower, "credential") ||
			strings.Contains(lineLower, "cloudformation") ||
			strings.Contains(lineLower, "dockerfile") ||
			strings.Contains(lineLower, "iam") ||
			strings.Contains(lineLower, "encryption") {
			if currentFinding.Len() > 0 {
				findings = append(findings, strings.TrimSpace(currentFinding.String()))
				currentFinding.Reset()
			}
			inFinding = true
			currentFinding.WriteString(line)
			currentFinding.WriteString(" ")
		} else if inFinding && len(strings.TrimSpace(line)) > 0 {
			currentFinding.WriteString(line)
			currentFinding.WriteString(" ")
		} else if len(strings.TrimSpace(line)) == 0 {
			if currentFinding.Len() > 0 {
				findings = append(findings, strings.TrimSpace(currentFinding.String()))
				currentFinding.Reset()
				inFinding = false
			}
		}
	}

	if currentFinding.Len() > 0 {
		findings = append(findings, strings.TrimSpace(currentFinding.String()))
	}

	// Check if analysis says no issues
	if containsNoIssuesMessage(combinedText) && len(findings) == 0 {
		// Return empty string to indicate no concerns (will be handled by output layer)
		log.Debug().Msg("Analysis contains 'no issues' message and no findings extracted, returning empty")
		return ""
	}

	// Add unique findings (deduplicate)
	seen := make(map[string]bool)
	for _, finding := range findings {
		if len(finding) > 20 && !seen[finding] {
			seen[finding] = true
			summary.WriteString(fmt.Sprintf("- %s\n", finding))
		}
	}

	// If we didn't extract good findings, check if the analysis contains actual issues
	// Only include analysis text if it doesn't say "no issues"
	if len(findings) == 0 {
		// Check if any analysis contains actual issues (not just "no issues" messages)
		hasActualIssues := false
		for _, analysis := range analyses {
			if !containsNoIssuesMessage(analysis) && len(strings.TrimSpace(analysis)) > 0 {
				hasActualIssues = true
				break
			}
		}

		if hasActualIssues {
			summary.WriteString("\n## Analysis\n\n")
			summary.WriteString(analyses[0])
		} else {
			// All analyses say "no issues", return empty
			return ""
		}
	}

	return summary.String()
}

// containsNoIssuesMessage checks if text contains messages indicating no issues were found
func containsNoIssuesMessage(text string) bool {
	lowerText := strings.ToLower(text)
	return strings.Contains(lowerText, "no issues") ||
		strings.Contains(lowerText, "no problems") ||
		strings.Contains(lowerText, "no concerns") ||
		strings.Contains(lowerText, "no security") ||
		strings.Contains(lowerText, "no vulnerabilities") ||
		strings.Contains(lowerText, "no exposed secrets") ||
		strings.Contains(lowerText, "no database issues") ||
		strings.Contains(lowerText, "no cloudformation") ||
		strings.Contains(lowerText, "no dockerfile") ||
		strings.Contains(lowerText, "no issues found") ||
		strings.Contains(lowerText, "nothing found") ||
		strings.Contains(lowerText, "no findings") ||
		strings.Contains(lowerText, "none identified") ||
		strings.Contains(lowerText, "none found") ||
		strings.Contains(lowerText, "no issues identified") ||
		strings.Contains(lowerText, "clean review") ||
		strings.Contains(lowerText, "review is clean")
}

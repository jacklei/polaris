package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	awspkg "github.com/jacklei/polaris/pkg/aws"
	"github.com/jacklei/polaris/pkg/github"
	"github.com/rs/zerolog/log"
)

const (
	// JiraDomain is the default Jira domain for Acorns
	JiraDomain = "https://acorns.atlassian.net"
)

// Ticket represents a Jira ticket
type Ticket struct {
	Key    string `json:"key"`
	Fields struct {
		Summary     string      `json:"summary"`
		Description interface{} `json:"description"` // Can be string, null, or ADF object
		Status      struct {
			Name string `json:"name"`
		} `json:"status"`
		IssueType struct {
			Name string `json:"name"`
		} `json:"issuetype"`
		Assignee struct {
			DisplayName  string `json:"displayName"`
			EmailAddress string `json:"emailAddress"`
		} `json:"assignee"`
		Reporter struct {
			DisplayName  string `json:"displayName"`
			EmailAddress string `json:"emailAddress"`
		} `json:"reporter"`
		Created    string `json:"created"`
		Updated    string `json:"updated"`
		Resolution struct {
			Name string `json:"name"`
		} `json:"resolution"`
		Priority struct {
			Name string `json:"name"`
		} `json:"priority"`
		Labels []string               `json:"labels"`
		Custom map[string]interface{} `json:"-"` // For custom fields
	} `json:"fields"`
}

// CABTicketInfo contains information about a CAB ticket for the overdue-cabs command
type CABTicketInfo struct {
	Key           string `json:"key"`
	URL           string `json:"url"`
	Summary       string `json:"summary"`
	Assignee      string `json:"assignee"`
	AssigneeEmail string `json:"assignee_email,omitempty"`
	Status        string `json:"status"`
	PlannedStart  string `json:"planned_start,omitempty"`
	TeamName      string `json:"team_name,omitempty"`
}

// CABTicketsByTeam groups CAB tickets by team name
type CABTicketsByTeam map[string][]CABTicketInfo

// ParseTicketKey extracts the ticket key from various input formats
func ParseTicketKey(ticketArg string) (string, error) {
	// If it's a URL, extract the key
	if strings.HasPrefix(ticketArg, "http://") || strings.HasPrefix(ticketArg, "https://") {
		parsedURL, err := url.Parse(ticketArg)
		if err != nil {
			return "", fmt.Errorf("invalid URL: %w", err)
		}

		// Check if it's a Jira URL (e.g., https://acorns.atlassian.net/browse/PROJ-123)
		if strings.Contains(parsedURL.Path, "/browse/") {
			parts := strings.Split(parsedURL.Path, "/browse/")
			if len(parts) == 2 {
				return parts[1], nil
			}
		}
		return "", fmt.Errorf("could not extract ticket key from URL")
	}

	// Otherwise, assume it's already a ticket key (e.g., "PROJ-123")
	return ticketArg, nil
}

// FetchTicket fetches ticket details from Jira API
func FetchTicket(ctx context.Context, username, token, ticketKey string) (*Ticket, error) {
	// Parse ticket key from input
	key, err := ParseTicketKey(ticketKey)
	if err != nil {
		return nil, err
	}

	// Build API URL
	apiURL := fmt.Sprintf("%s/rest/api/3/issue/%s", JiraDomain, key)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication (Basic Auth with email:token)
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + token))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Make request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Jira API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var ticket Ticket
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, &ticket); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &ticket, nil
}

// LinkedResources contains information about resources linked from a Jira ticket
type LinkedResources struct {
	DevTickets     []TicketInfo   `json:"dev_tickets"`
	GitHubPRs      []GitHubPRInfo `json:"github_prs"`
	CommitMessages []string       `json:"commit_messages"`
	GitTags        []GitTagInfo   `json:"git_tags"`
}

// TicketInfo contains summary info about a linked Jira ticket
type TicketInfo struct {
	Key     string `json:"key"`
	Summary string `json:"summary"`
	Status  string `json:"status"`
	Type    string `json:"type"`
}

// GitHubPRInfo contains info about a linked GitHub PR
type GitHubPRInfo struct {
	URL         string `json:"url"`
	Title       string `json:"title"`
	Description string `json:"description"`
	State       string `json:"state"`
	Author      string `json:"author"`
}

// GitTagInfo contains info about a git tag/release
type GitTagInfo struct {
	URL     string `json:"url"`
	Tag     string `json:"tag"`
	Message string `json:"message"`
}

// extractDescriptionText extracts text from description which can be string, null, or ADF object
func extractDescriptionText(description interface{}) string {
	if description == nil {
		return ""
	}

	// If it's already a string, return it
	if str, ok := description.(string); ok {
		return str
	}

	// If it's an ADF object, try to extract text content
	if descMap, ok := description.(map[string]interface{}); ok {
		// Try to extract text from ADF format
		if content, ok := descMap["content"].([]interface{}); ok {
			var textParts []string
			extractTextFromADF(content, &textParts)
			return strings.Join(textParts, "\n")
		}
		// Try direct text extraction
		if text, ok := descMap["text"].(string); ok {
			return text
		}
		// Try plain text field
		if plain, ok := descMap["plain"].(string); ok {
			return plain
		}
	}

	// Fallback: convert to string
	return fmt.Sprintf("%v", description)
}

// extractTextFromADF recursively extracts text from ADF content structure
func extractTextFromADF(content []interface{}, textParts *[]string) {
	for _, item := range content {
		if itemMap, ok := item.(map[string]interface{}); ok {
			// Check for text content
			if content, ok := itemMap["content"].([]interface{}); ok {
				extractTextFromADF(content, textParts)
			}
			// Check for text field
			if text, ok := itemMap["text"].(string); ok {
				*textParts = append(*textParts, text)
			}
		}
	}
}

// parseLinks extracts links from the ticket description
func parseLinks(description string) ([]string, error) {
	var links []string

	// Match URLs (http://, https://, or jira ticket keys like PROJ-123)
	urlRegex := regexp.MustCompile(`(https?://[^\s\)]+|(?:[A-Z]+-\d+))`)
	matches := urlRegex.FindAllString(description, -1)

	for _, match := range matches {
		// Skip if it's just a ticket key without context (we'll handle those separately)
		if !strings.HasPrefix(match, "http") {
			// Check if it's a valid ticket key format
			if matched, _ := regexp.MatchString(`^[A-Z]+-\d+$`, match); matched {
				links = append(links, match)
			}
		} else {
			links = append(links, match)
		}
	}

	return links, nil
}

// fetchLinkedDevTickets fetches information about linked Jira dev tickets
func fetchLinkedDevTickets(ctx context.Context, username, token string, ticketKeys []string) []TicketInfo {
	var tickets []TicketInfo

	for _, key := range ticketKeys {
		ticket, err := FetchTicket(ctx, username, token, key)
		if err != nil {
			log.Warn().Err(err).Str("ticket_key", key).Msg("Failed to fetch linked dev ticket")
			continue
		}

		tickets = append(tickets, TicketInfo{
			Key:     ticket.Key,
			Summary: ticket.Fields.Summary,
			Status:  ticket.Fields.Status.Name,
			Type:    ticket.Fields.IssueType.Name,
		})
	}

	return tickets
}

// fetchGitHubPRInfo fetches information about a GitHub PR
func fetchGitHubPRInfo(ctx context.Context, githubToken, prURL string) (*GitHubPRInfo, error) {
	owner, repo, diffType, identifier, err := github.ParseGitHubURL(prURL)
	if err != nil {
		return nil, err
	}

	if diffType != "pull_request" {
		return nil, fmt.Errorf("not a pull request URL")
	}

	// Fetch PR details from GitHub API
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%s", owner, repo, identifier)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", githubToken))
	req.Header.Set("User-Agent", "polaris")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	var pr struct {
		Title string `json:"title"`
		Body  string `json:"body"`
		State string `json:"state"`
		User  struct {
			Login string `json:"login"`
		} `json:"user"`
		HTMLURL string `json:"html_url"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, &pr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &GitHubPRInfo{
		URL:         pr.HTMLURL,
		Title:       pr.Title,
		Description: pr.Body,
		State:       pr.State,
		Author:      pr.User.Login,
	}, nil
}

// extractCommitMessages extracts commit messages from a git diff
func extractCommitMessages(ctx context.Context, githubToken, diffURL string) ([]string, error) {
	owner, repo, diffType, identifier, err := github.ParseGitHubURL(diffURL)
	if err != nil {
		return nil, err
	}

	var apiURL string
	switch diffType {
	case "commit":
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", owner, repo, identifier)
	case "compare":
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s", owner, repo, identifier)
	default:
		return nil, fmt.Errorf("unsupported diff type for commit extraction: %s", diffType)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", githubToken))
	req.Header.Set("User-Agent", "polaris")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var messages []string

	if diffType == "commit" {
		// Single commit
		var commit struct {
			Commit struct {
				Message string `json:"message"`
			} `json:"commit"`
		}
		if err := json.Unmarshal(body, &commit); err != nil {
			return nil, fmt.Errorf("failed to unmarshal commit: %w", err)
		}
		messages = append(messages, commit.Commit.Message)
	} else {
		// Compare (multiple commits)
		var compare struct {
			Commits []struct {
				Commit struct {
					Message string `json:"message"`
				} `json:"commit"`
			} `json:"commits"`
		}
		if err := json.Unmarshal(body, &compare); err != nil {
			return nil, fmt.Errorf("failed to unmarshal compare: %w", err)
		}
		for _, c := range compare.Commits {
			messages = append(messages, c.Commit.Message)
		}
	}

	return messages, nil
}

// fetchGitTagInfo fetches information about a git tag/release
func fetchGitTagInfo(ctx context.Context, githubToken, tagURL string) (*GitTagInfo, error) {
	// Parse the tag URL - could be a release URL or tag URL
	parsedURL, err := url.Parse(tagURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	path := strings.Trim(parsedURL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid tag/release URL format")
	}

	owner := parts[0]
	repo := parts[1]

	var tagName string
	var apiURL string

	if parts[2] == "releases" && len(parts) >= 4 {
		// Release URL: /owner/repo/releases/tag/v1.0.0
		tagName = parts[3]
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, tagName)
	} else if parts[2] == "tree" && len(parts) >= 4 {
		// Tag URL: /owner/repo/tree/v1.0.0
		tagName = parts[3]
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs/tags/%s", owner, repo, tagName)
	} else {
		return nil, fmt.Errorf("unsupported tag/release URL format")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", githubToken))
	req.Header.Set("User-Agent", "polaris")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Try release API if tag API failed
		if strings.Contains(apiURL, "/git/refs/tags/") {
			apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, tagName)
			req, _ = http.NewRequestWithContext(ctx, "GET", apiURL, nil)
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("Authorization", fmt.Sprintf("token %s", githubToken))
			req.Header.Set("User-Agent", "polaris")
			resp, err = client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("failed to make request: %w", err)
			}
			defer resp.Body.Close()
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
		Body    string `json:"body"`
		HTMLURL string `json:"html_url"`
	}

	if err := json.Unmarshal(body, &release); err != nil {
		// Might be a tag ref, not a release
		var tagRef struct {
			Object struct {
				Message string `json:"message"`
			} `json:"object"`
		}
		if err2 := json.Unmarshal(body, &tagRef); err2 != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
		return &GitTagInfo{
			URL:     tagURL,
			Tag:     tagName,
			Message: tagRef.Object.Message,
		}, nil
	}

	return &GitTagInfo{
		URL:     release.HTMLURL,
		Tag:     release.TagName,
		Message: release.Body,
	}, nil
}

// collectLinkedResources collects information from all linked resources
func collectLinkedResources(ctx context.Context, jiraUsername, jiraToken, githubToken, description string) (*LinkedResources, error) {
	links, err := parseLinks(description)
	if err != nil {
		return nil, fmt.Errorf("failed to parse links: %w", err)
	}

	resources := &LinkedResources{
		DevTickets:     []TicketInfo{},
		GitHubPRs:      []GitHubPRInfo{},
		CommitMessages: []string{},
		GitTags:        []GitTagInfo{},
	}

	var devTicketKeys []string

	for _, link := range links {
		// Check if it's a Jira ticket key
		if matched, _ := regexp.MatchString(`^[A-Z]+-\d+$`, link); matched {
			devTicketKeys = append(devTicketKeys, link)
			continue
		}

		// Check if it's a Jira URL
		if strings.Contains(link, "atlassian.net") || strings.Contains(link, "jira") {
			key, err := ParseTicketKey(link)
			if err == nil {
				devTicketKeys = append(devTicketKeys, key)
			}
			continue
		}

		// Check if it's a GitHub PR
		if strings.Contains(link, "github.com") && strings.Contains(link, "/pull/") {
			prInfo, err := fetchGitHubPRInfo(ctx, githubToken, link)
			if err != nil {
				log.Warn().Err(err).Str("url", link).Msg("Failed to fetch GitHub PR")
				continue
			}
			resources.GitHubPRs = append(resources.GitHubPRs, *prInfo)
			continue
		}

		// Check if it's a git diff/commit
		if strings.Contains(link, "github.com") && (strings.Contains(link, "/commit/") || strings.Contains(link, "/compare/")) {
			messages, err := extractCommitMessages(ctx, githubToken, link)
			if err != nil {
				log.Warn().Err(err).Str("url", link).Msg("Failed to extract commit messages")
				continue
			}
			resources.CommitMessages = append(resources.CommitMessages, messages...)
			continue
		}

		// Check if it's a git tag/release
		if strings.Contains(link, "github.com") && (strings.Contains(link, "/releases/") || strings.Contains(link, "/tree/")) {
			tagInfo, err := fetchGitTagInfo(ctx, githubToken, link)
			if err != nil {
				log.Warn().Err(err).Str("url", link).Msg("Failed to fetch git tag")
				continue
			}
			resources.GitTags = append(resources.GitTags, *tagInfo)
			continue
		}
	}

	// Fetch all dev tickets
	if len(devTicketKeys) > 0 {
		resources.DevTickets = fetchLinkedDevTickets(ctx, jiraUsername, jiraToken, devTicketKeys)
	}

	return resources, nil
}

// generateSummariesWithClaude generates business and technical summaries using Claude
func generateSummariesWithClaude(ctx context.Context, awsProfile string, ticket *Ticket, resources *LinkedResources) (string, string, error) {
	// Build context for Claude
	var contextBuilder strings.Builder
	descriptionText := extractDescriptionText(ticket.Fields.Description)
	contextBuilder.WriteString(fmt.Sprintf("Jira Ticket: %s\n", ticket.Key))
	contextBuilder.WriteString(fmt.Sprintf("Summary: %s\n", ticket.Fields.Summary))
	contextBuilder.WriteString(fmt.Sprintf("Description: %s\n\n", descriptionText))

	if len(resources.DevTickets) > 0 {
		contextBuilder.WriteString("Linked Dev Tickets:\n")
		for _, dt := range resources.DevTickets {
			contextBuilder.WriteString(fmt.Sprintf("- %s: %s (Status: %s, Type: %s)\n", dt.Key, dt.Summary, dt.Status, dt.Type))
		}
		contextBuilder.WriteString("\n")
	}

	if len(resources.GitHubPRs) > 0 {
		contextBuilder.WriteString("Linked GitHub Pull Requests:\n")
		for _, pr := range resources.GitHubPRs {
			contextBuilder.WriteString(fmt.Sprintf("- %s: %s\n  State: %s, Author: %s\n  Description: %s\n", pr.URL, pr.Title, pr.State, pr.Author, pr.Description))
		}
		contextBuilder.WriteString("\n")
	}

	if len(resources.CommitMessages) > 0 {
		contextBuilder.WriteString("Commit Messages:\n")
		for _, msg := range resources.CommitMessages {
			contextBuilder.WriteString(fmt.Sprintf("- %s\n", msg))
		}
		contextBuilder.WriteString("\n")
	}

	if len(resources.GitTags) > 0 {
		contextBuilder.WriteString("Git Tags/Releases:\n")
		for _, tag := range resources.GitTags {
			contextBuilder.WriteString(fmt.Sprintf("- %s: %s\n  Message: %s\n", tag.Tag, tag.URL, tag.Message))
		}
		contextBuilder.WriteString("\n")
	}

	context := contextBuilder.String()

	// Generate business summary
	businessPrompt := fmt.Sprintf(`Based on the following Jira ticket and its linked resources, generate a concise, business-friendly summary (2-3 paragraphs) that:
- Explains what was done in non-technical terms
- Highlights the business value and impact
- Mentions key deliverables and outcomes
- Is suitable for stakeholders and executives

%s`, context)

	businessSummary, err := invokeClaude(ctx, awsProfile, businessPrompt)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate business summary: %w", err)
	}

	// Generate technical summary
	technicalPrompt := fmt.Sprintf(`Based on the following Jira ticket and its linked resources, generate a technical summary (2-3 paragraphs) that:
- Explains the technical implementation details
- Describes the changes made (code, infrastructure, etc.)
- Mentions technologies, frameworks, or tools used
- Highlights any technical challenges overcome
- Is suitable for engineering teams

%s`, context)

	technicalSummary, err := invokeClaude(ctx, awsProfile, technicalPrompt)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate technical summary: %w", err)
	}

	return businessSummary, technicalSummary, nil
}

// invokeClaude invokes Claude via AWS Bedrock with a prompt
func invokeClaude(ctx context.Context, awsProfile, prompt string) (string, error) {
	// Load AWS config
	cfg, err := awspkg.LoadAWSConfig(ctx, awsProfile)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Use the existing Claude function from pkg/aws
	return awspkg.InvokeClaude(ctx, cfg, prompt)
}

// GenerateSummary generates a formatted summary for a Jira ticket
// It collects information from linked resources and generates business/technical summaries using Claude
func GenerateSummary(ctx context.Context, username, token, ticketArg, githubToken, awsProfile string) (map[string]interface{}, error) {
	// Fetch ticket details
	ticket, err := FetchTicket(ctx, username, token, ticketArg)
	if err != nil {
		return nil, err
	}

	// Format dates - try multiple formats
	var createdTime, updatedTime time.Time
	dateFormats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000Z0700",
		"2006-01-02T15:04:05Z0700",
	}

	for _, format := range dateFormats {
		if t, err := time.Parse(format, ticket.Fields.Created); err == nil {
			createdTime = t
			break
		}
	}

	for _, format := range dateFormats {
		if t, err := time.Parse(format, ticket.Fields.Updated); err == nil {
			updatedTime = t
			break
		}
	}

	// Format labels as comma-separated string
	labelsStr := strings.Join(ticket.Fields.Labels, ", ")
	if labelsStr == "" {
		labelsStr = "None"
	}

	// Extract description text
	descriptionText := extractDescriptionText(ticket.Fields.Description)

	// Collect linked resources
	var resources *LinkedResources
	if githubToken != "" {
		resources, err = collectLinkedResources(ctx, username, token, githubToken, descriptionText)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to collect linked resources, continuing without them")
			resources = &LinkedResources{}
		}
	} else {
		resources = &LinkedResources{}
	}

	// Generate summaries with Claude if AWS profile is provided
	var businessSummary, technicalSummary string
	if awsProfile != "" {
		businessSummary, technicalSummary, err = generateSummariesWithClaude(ctx, awsProfile, ticket, resources)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to generate Claude summaries, continuing without them")
		}
	}

	// Build summary
	summary := map[string]interface{}{
		"key":         ticket.Key,
		"url":         fmt.Sprintf("%s/browse/%s", JiraDomain, ticket.Key),
		"summary":     ticket.Fields.Summary,
		"description": descriptionText,
		"status":      ticket.Fields.Status.Name,
		"type":        ticket.Fields.IssueType.Name,
		"priority":    ticket.Fields.Priority.Name,
		"created":     createdTime.Format("2006-01-02 15:04:05"),
		"updated":     updatedTime.Format("2006-01-02 15:04:05"),
		"labels":      labelsStr,
	}

	if ticket.Fields.Assignee.DisplayName != "" {
		summary["assignee"] = ticket.Fields.Assignee.DisplayName
		if ticket.Fields.Assignee.EmailAddress != "" {
			summary["assignee_email"] = ticket.Fields.Assignee.EmailAddress
		}
	}

	if ticket.Fields.Reporter.DisplayName != "" {
		summary["reporter"] = ticket.Fields.Reporter.DisplayName
		if ticket.Fields.Reporter.EmailAddress != "" {
			summary["reporter_email"] = ticket.Fields.Reporter.EmailAddress
		}
	}

	if ticket.Fields.Resolution.Name != "" {
		summary["resolution"] = ticket.Fields.Resolution.Name
	}

	// Add linked resources
	if len(resources.DevTickets) > 0 {
		summary["linked_dev_tickets"] = resources.DevTickets
	}
	if len(resources.GitHubPRs) > 0 {
		summary["linked_github_prs"] = resources.GitHubPRs
	}
	if len(resources.CommitMessages) > 0 {
		summary["commit_messages"] = resources.CommitMessages
	}
	if len(resources.GitTags) > 0 {
		summary["linked_git_tags"] = resources.GitTags
	}

	// Add Claude-generated summaries
	if businessSummary != "" {
		summary["business_summary"] = businessSummary
	}
	if technicalSummary != "" {
		summary["technical_summary"] = technicalSummary
	}

	return summary, nil
}

// SearchCABTickets searches for open CAB tickets using Jira search API
func SearchCABTickets(ctx context.Context, username, token string) ([]Ticket, error) {
	// JQL query to find CAB tickets that are still open
	// CAB is the project key for "Change Advisory Board"
	jql := `project = CAB AND status != Cancel AND status != Success AND status != Rollback`

	// URL encode the JQL query
	encodedJQL := url.QueryEscape(jql)

	// Build API URL - using the new search/jql API endpoint
	apiURL := fmt.Sprintf("%s/rest/api/3/search/jql?jql=%s&maxResults=1000&fields=summary,status,issuetype,assignee,labels,customfield_*,duedate,startdate", JiraDomain, encodedJQL)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + token))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Make request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Jira API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var searchResult struct {
		Issues []Ticket `json:"issues"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, &searchResult); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return searchResult.Issues, nil
}

// extractCustomField extracts a custom field value from a ticket's raw JSON
func extractCustomField(ticketJSON map[string]interface{}, fieldName string) string {
	fields, ok := ticketJSON["fields"].(map[string]interface{})
	if !ok {
		return ""
	}

	// Try exact field name first
	if val, ok := fields[fieldName]; ok {
		if str, ok := val.(string); ok {
			return str
		}
		if val != nil {
			return fmt.Sprintf("%v", val)
		}
	}

	// Try common variations
	variations := []string{
		fieldName,
		strings.ToLower(fieldName),
		strings.ReplaceAll(fieldName, " ", ""),
		strings.ReplaceAll(strings.ToLower(fieldName), " ", ""),
	}

	for _, variation := range variations {
		if val, ok := fields[variation]; ok {
			if str, ok := val.(string); ok {
				return str
			}
			if val != nil {
				return fmt.Sprintf("%v", val)
			}
		}
	}

	return ""
}

// extractTeamName extracts team name from ticket (from custom field or labels)
func extractTeamName(ticket *Ticket, ticketJSON map[string]interface{}) string {
	// Try common custom field names for team
	teamFields := []string{
		"customfield_10000", // Common team field ID pattern
		"Team",
		"Team Name",
		"team",
		"team_name",
	}

	for _, fieldName := range teamFields {
		if team := extractCustomField(ticketJSON, fieldName); team != "" {
			return team
		}
	}

	// Try to find team in labels (common pattern: "team-*" or "Team:*")
	for _, label := range ticket.Fields.Labels {
		if strings.HasPrefix(strings.ToLower(label), "team-") {
			return strings.TrimPrefix(label, "team-")
		}
		if strings.HasPrefix(label, "Team:") {
			return strings.TrimPrefix(label, "Team:")
		}
	}

	return "Unassigned"
}

// extractPlannedStartDate extracts planned start date from ticket
func extractPlannedStartDate(ticket *Ticket, ticketJSON map[string]interface{}) string {
	// Try common custom field names for planned start date
	dateFields := []string{
		"customfield_10001", // Common planned start field ID pattern
		"Planned Start Date",
		"planned_start_date",
		"Start Date",
		"startdate",
		"Planned Start",
		"planned_start",
	}

	for _, fieldName := range dateFields {
		if dateStr := extractCustomField(ticketJSON, fieldName); dateStr != "" {
			// Try to parse and format the date
			dateFormats := []string{
				time.RFC3339,
				time.RFC3339Nano,
				"2006-01-02T15:04:05.000Z0700",
				"2006-01-02T15:04:05Z0700",
				"2006-01-02",
			}
			for _, format := range dateFormats {
				if t, err := time.Parse(format, dateStr); err == nil {
					return t.Format("2006-01-02")
				}
			}
			return dateStr
		}
	}

	return ""
}

// GetOverdueCABTickets fetches open CAB tickets and groups them by team
func GetOverdueCABTickets(ctx context.Context, username, token string) (CABTicketsByTeam, error) {
	// Try multiple JQL queries - first with status category, then with specific status names
	jqlQueries := []string{
		`project = CAB AND statusCategory != Done`,                                        // Try status category first (more reliable)
		`project = CAB AND status != Cancel AND status != Success AND status != Rollback`, // User's specific filter
		`project = CAB`, // Fallback: get all tickets to debug
	}

	var searchResult struct {
		Issues []map[string]interface{} `json:"issues"`
		Total  int                      `json:"total"`
	}
	var lastErr error

	for i, jql := range jqlQueries {
		log.Debug().Int("attempt", i+1).Str("jql", jql).Msg("Trying JQL query")

		// URL encode the JQL query
		encodedJQL := url.QueryEscape(jql)

		// Build API URL - using the new search/jql API endpoint
		// The new API doesn't return fields by default, so we must explicitly request them
		// Using *all to get all fields
		apiURL := fmt.Sprintf("%s/rest/api/3/search/jql?jql=%s&maxResults=1000&fields=*all", JiraDomain, encodedJQL)
		log.Debug().Int("attempt", i+1).Str("api_url", apiURL).Msg("API URL")

		// Create HTTP request
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}

		// Set authentication
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + token))
		req.Header.Set("Authorization", "Basic "+auth)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		// Make request
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to make request: %w", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			lastErr = fmt.Errorf("Jira API returned status %d: %s", resp.StatusCode, string(body))
			log.Warn().Err(lastErr).Int("attempt", i+1).Msg("Query failed, trying next")
			continue
		}

		// Parse response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		previewLen := 500
		if len(body) < previewLen {
			previewLen = len(body)
		}
		log.Debug().Int("attempt", i+1).Str("response_preview", string(body[:previewLen])).Msg("Raw API response preview")

		if err := json.Unmarshal(body, &searchResult); err != nil {
			log.Warn().Err(err).Int("attempt", i+1).Str("response_body", string(body)).Msg("Failed to parse response, trying next query")
			lastErr = fmt.Errorf("failed to unmarshal response: %w", err)
			continue
		}

		log.Debug().Int("attempt", i+1).Int("total", searchResult.Total).Int("issues_count", len(searchResult.Issues)).Msg("Query succeeded")

		// If we got results (or if this is the fallback query), break
		if len(searchResult.Issues) > 0 || i == len(jqlQueries)-1 {
			break
		}
	}

	if lastErr != nil && len(searchResult.Issues) == 0 {
		return nil, lastErr
	}

	log.Debug().Int("ticket_count", len(searchResult.Issues)).Msg("Found CAB tickets")

	// Debug: log first few tickets to see what we're getting
	if len(searchResult.Issues) > 0 {
		for i, issue := range searchResult.Issues {
			if i >= 3 { // Only log first 3 for debugging
				break
			}
			if key, ok := issue["key"].(string); ok {
				if fields, ok := issue["fields"].(map[string]interface{}); ok {
					status := "unknown"
					if statusObj, ok := fields["status"].(map[string]interface{}); ok {
						if s, ok := statusObj["name"].(string); ok {
							status = s
						}
					}
					log.Debug().Str("ticket", key).Str("status", status).Msg("Sample CAB ticket")
				}
			}
		}
	} else {
		log.Warn().Int("total_in_project", searchResult.Total).Msg("No CAB tickets found matching filter, but total tickets in project")
	}

	result := make(CABTicketsByTeam)

	log.Debug().Int("total_issues_to_process", len(searchResult.Issues)).Msg("Processing tickets")

	processedCount := 0
	skippedCount := 0

	for i, issueJSON := range searchResult.Issues {
		// Extract key
		key, ok := issueJSON["key"].(string)
		if !ok {
			log.Debug().Int("issue_index", i).Msg("Skipping issue: no key found")
			skippedCount++
			continue
		}

		// Extract fields
		fields, ok := issueJSON["fields"].(map[string]interface{})
		if !ok {
			log.Debug().Str("ticket_key", key).Msg("Skipping issue: no fields found")
			// Debug: log what keys are actually in the issue
			if i < 3 {
				var keys []string
				for k := range issueJSON {
					keys = append(keys, k)
				}
				log.Debug().Strs("available_keys", keys).Str("ticket_key", key).Msg("Issue structure")
				// Also log the raw issue JSON for first ticket
				if i == 0 {
					issueJSONBytes, _ := json.Marshal(issueJSON)
					previewLen := 1000
					if len(issueJSONBytes) < previewLen {
						previewLen = len(issueJSONBytes)
					}
					log.Debug().Str("raw_issue_json", string(issueJSONBytes[:previewLen])).Msg("First issue raw JSON")
				}
			}
			skippedCount++
			continue
		}

		processedCount++

		// Extract basic fields
		summary := ""
		if s, ok := fields["summary"].(string); ok {
			summary = s
		}

		status := ""
		if statusObj, ok := fields["status"].(map[string]interface{}); ok {
			if s, ok := statusObj["name"].(string); ok {
				status = s
			}
		}

		assignee := "Unassigned"
		assigneeEmail := ""
		if assigneeObj, ok := fields["assignee"].(map[string]interface{}); ok && assigneeObj != nil {
			if name, ok := assigneeObj["displayName"].(string); ok {
				assignee = name
			}
			if email, ok := assigneeObj["emailAddress"].(string); ok {
				assigneeEmail = email
			}
		}

		// Extract team name
		teamName := extractTeamNameFromFields(fields)

		// Extract planned start date
		plannedStart := extractPlannedStartDateFromFields(fields)

		// Build CAB ticket info
		cabTicket := CABTicketInfo{
			Key:           key,
			URL:           fmt.Sprintf("%s/browse/%s", JiraDomain, key),
			Summary:       summary,
			Status:        status,
			PlannedStart:  plannedStart,
			TeamName:      teamName,
			Assignee:      assignee,
			AssigneeEmail: assigneeEmail,
		}

		// Group by team
		if result[teamName] == nil {
			result[teamName] = []CABTicketInfo{}
		}
		result[teamName] = append(result[teamName], cabTicket)
	}

	log.Debug().Int("processed", processedCount).Int("skipped", skippedCount).Int("teams", len(result)).Msg("Finished processing tickets")

	return result, nil
}

// extractTeamNameFromFields extracts team name from fields map
func extractTeamNameFromFields(fields map[string]interface{}) string {
	// First, try the specific team field: customfield_13154
	if teamField, ok := fields["customfield_13154"]; ok && teamField != nil {
		// Handle different possible structures
		if str, ok := teamField.(string); ok && str != "" {
			return str
		}
		// Object with name/value/displayName
		if obj, ok := teamField.(map[string]interface{}); ok {
			if name, ok := obj["name"].(string); ok && name != "" {
				return name
			}
			if value, ok := obj["value"].(string); ok && value != "" {
				return value
			}
			if displayName, ok := obj["displayName"].(string); ok && displayName != "" {
				return displayName
			}
		}
		// Array of objects (multi-select)
		if arr, ok := teamField.([]interface{}); ok && len(arr) > 0 {
			if firstItem, ok := arr[0].(map[string]interface{}); ok {
				if name, ok := firstItem["name"].(string); ok && name != "" {
					return name
				}
				if value, ok := firstItem["value"].(string); ok && value != "" {
					return value
				}
				if displayName, ok := firstItem["displayName"].(string); ok && displayName != "" {
					return displayName
				}
			}
		}
	}

	// Fallback: Try to find team in labels (common pattern: "team-*" or "Team:*")
	if labelsVal, ok := fields["labels"].([]interface{}); ok {
		for _, labelVal := range labelsVal {
			if label, ok := labelVal.(string); ok {
				labelLower := strings.ToLower(label)
				if strings.HasPrefix(labelLower, "team-") {
					return strings.TrimPrefix(label, "team-")
				}
				if strings.HasPrefix(label, "Team:") {
					return strings.TrimPrefix(label, "Team:")
				}
			}
		}
	}

	// Fallback: Try common custom field names/patterns for team
	teamFieldNames := []string{
		"team",
		"team_name",
		"teamName",
		"team name",
		"Team",
		"Team Name",
		"assignee_team",
		"owner_team",
	}

	for _, fieldName := range teamFieldNames {
		if val, ok := fields[fieldName]; ok && val != nil {
			if str, ok := val.(string); ok && str != "" {
				return str
			}
			if obj, ok := val.(map[string]interface{}); ok {
				if name, ok := obj["name"].(string); ok && name != "" {
					return name
				}
				if value, ok := obj["value"].(string); ok && value != "" {
					return value
				}
				if displayName, ok := obj["displayName"].(string); ok && displayName != "" {
					return displayName
				}
			}
		}
	}

	return "Unassigned"
}

// extractPlannedStartDateFromFields extracts planned start date from fields map
func extractPlannedStartDateFromFields(fields map[string]interface{}) string {
	// Try common date field names
	dateFieldNames := []string{
		"startdate",
		"duedate",
		"customfield_10020", // Common planned start field ID
		"customfield_10021",
	}

	for _, fieldName := range dateFieldNames {
		if val, ok := fields[fieldName]; ok && val != nil {
			if dateStr, ok := val.(string); ok && dateStr != "" {
				// Try to parse and format the date
				dateFormats := []string{
					time.RFC3339,
					time.RFC3339Nano,
					"2006-01-02T15:04:05.000Z0700",
					"2006-01-02T15:04:05Z0700",
					"2006-01-02",
				}
				for _, format := range dateFormats {
					if t, err := time.Parse(format, dateStr); err == nil {
						return t.Format("2006-01-02")
					}
				}
				return dateStr
			}
		}
	}

	// Try to find any field with "planned" or "start" in the name
	for key, val := range fields {
		keyLower := strings.ToLower(key)
		if (strings.Contains(keyLower, "planned") || strings.Contains(keyLower, "start")) && val != nil {
			if dateStr, ok := val.(string); ok && dateStr != "" {
				dateFormats := []string{
					time.RFC3339,
					time.RFC3339Nano,
					"2006-01-02T15:04:05.000Z0700",
					"2006-01-02T15:04:05Z0700",
					"2006-01-02",
				}
				for _, format := range dateFormats {
					if t, err := time.Parse(format, dateStr); err == nil {
						return t.Format("2006-01-02")
					}
				}
				return dateStr
			}
		}
	}

	return ""
}

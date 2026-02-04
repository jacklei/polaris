package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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

// ListOrgRepos lists all repositories in a GitHub organization
func ListOrgRepos(ctx context.Context, token, org string) ([]string, error) {
	var repos []string
	page := 1
	perPage := 100

	for {
		apiURL := fmt.Sprintf("https://api.github.com/orgs/%s/repos?page=%d&per_page=%d", org, page, perPage)

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
		req.Header.Set("User-Agent", "polaris")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, resp.Status)
		}

		var pageRepos []struct {
			FullName string `json:"full_name"`
			Archived bool   `json:"archived"`
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		if err := json.Unmarshal(body, &pageRepos); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}

		if len(pageRepos) == 0 {
			break
		}

		for _, repo := range pageRepos {
			// Only include non-archived repositories
			if !repo.Archived {
				repos = append(repos, repo.FullName)
			}
		}

		if len(pageRepos) < perPage {
			break
		}

		page++
	}

	return repos, nil
}

// CheckDockerfileDeprecations checks a repository for deprecated language versions in various files
func CheckDockerfileDeprecations(ctx context.Context, token, repo string) ([]map[string]interface{}, error) {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository format: %s", repo)
	}
	owner := parts[0]
	repoName := parts[1]

	var allDeprecations []map[string]interface{}

	// Check Dockerfile
	dockerfileContent, err := FetchFileContent(ctx, token, owner, repoName, "Dockerfile")
	if err == nil {
		deprecations := parseDockerfileForDeprecations(ctx, repo, dockerfileContent)
		allDeprecations = append(allDeprecations, deprecations...)
	}

	// Check package.json for Node.js version
	packageJSONContent, err := FetchFileContent(ctx, token, owner, repoName, "package.json")
	if err == nil {
		deprecations := parsePackageJSONForDeprecations(ctx, repo, packageJSONContent)
		allDeprecations = append(allDeprecations, deprecations...)
	}

	// Check .nvmrc for Node.js version
	nvmrcContent, err := FetchFileContent(ctx, token, owner, repoName, ".nvmrc")
	if err == nil {
		deprecations := parseNvmrcForDeprecations(ctx, repo, nvmrcContent)
		allDeprecations = append(allDeprecations, deprecations...)
	}

	// Check .tool-versions for various tool versions
	toolVersionsContent, err := FetchFileContent(ctx, token, owner, repoName, ".tool-versions")
	if err == nil {
		deprecations := parseToolVersionsForDeprecations(ctx, repo, toolVersionsContent)
		allDeprecations = append(allDeprecations, deprecations...)
	}

	// Check go.mod for Golang version
	goModContent, err := FetchFileContent(ctx, token, owner, repoName, "go.mod")
	if err == nil {
		deprecations := parseGoModForDeprecations(ctx, repo, goModContent)
		allDeprecations = append(allDeprecations, deprecations...)
	}

	// Check .python-version for Python version
	pythonVersionContent, err := FetchFileContent(ctx, token, owner, repoName, ".python-version")
	if err == nil {
		deprecations := parsePythonVersionForDeprecations(ctx, repo, pythonVersionContent)
		allDeprecations = append(allDeprecations, deprecations...)
	}

	// Check .ruby-version for Ruby version
	rubyVersionContent, err := FetchFileContent(ctx, token, owner, repoName, ".ruby-version")
	if err == nil {
		deprecations := parseRubyVersionForDeprecations(ctx, repo, rubyVersionContent)
		allDeprecations = append(allDeprecations, deprecations...)
	}

	return allDeprecations, nil
}

// FetchFileContent fetches the content of a file from a GitHub repository
func FetchFileContent(ctx context.Context, token, owner, repo, filePath string) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, filePath)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("User-Agent", "polaris")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var fileContent struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, &fileContent); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Decode base64 content
	if fileContent.Encoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(fileContent.Content)
		if err != nil {
			return "", fmt.Errorf("failed to decode base64 content: %w", err)
		}
		return string(decoded), nil
	}

	return fileContent.Content, nil
}

// DeprecatedVersion represents a deprecated language version
type DeprecatedVersion struct {
	Version string
}

// endoflifeCycle represents a cycle from endoflife.date API
type endoflifeCycle struct {
	Cycle        string      `json:"cycle"`
	ReleaseDate  string      `json:"releaseDate"`
	EOL          interface{} `json:"eol"` // Can be string (date) or bool (true for EOL)
	Latest       string      `json:"latest"`
	Link         string      `json:"link"`
	LTS          interface{} `json:"lts"`     // Can be string or bool
	Support      interface{} `json:"support"` // Can be string (date) or bool
	Discontinued string      `json:"discontinued"`
}

// deprecationCache caches deprecation data from endoflife.date API
var (
	deprecationCache     = make(map[string][]DeprecatedVersion)
	deprecationCacheMu   sync.RWMutex
	deprecationCacheTime = make(map[string]time.Time)
	cacheTTL             = 24 * time.Hour // Cache for 24 hours
)

// clearDeprecationCache clears the deprecation cache (useful for testing/debugging)
func clearDeprecationCache() {
	deprecationCacheMu.Lock()
	defer deprecationCacheMu.Unlock()
	deprecationCache = make(map[string][]DeprecatedVersion)
	deprecationCacheTime = make(map[string]time.Time)
}

// languageToEndOfLifeProduct maps our internal language names to endoflife.date product names
var languageToEndOfLifeProduct = map[string]string{
	"node":           "nodejs",
	"golang":         "go",
	"python":         "python",
	"ruby":           "ruby",
	"java":           "java",
	"amazoncorretto": "amazon-corretto",
	"alpine":         "alpinelinux",
	"ubuntu":         "ubuntu",
	"debian":         "debian",
	"nodejs":         "nodejs",
}

// getDeprecatedVersions fetches deprecated versions from endoflife.date API with caching
func getDeprecatedVersions(ctx context.Context, language string) []DeprecatedVersion {
	product, ok := languageToEndOfLifeProduct[strings.ToLower(language)]
	if !ok {
		// Language not supported by API, return empty list
		return []DeprecatedVersion{}
	}

	// Check cache first
	deprecationCacheMu.RLock()
	cached, exists := deprecationCache[product]
	cacheTime, timeExists := deprecationCacheTime[product]
	deprecationCacheMu.RUnlock()

	if exists && timeExists && time.Since(cacheTime) < cacheTTL {
		return cached
	}

	// Fetch from API
	apiURL := fmt.Sprintf("https://endoflife.date/api/%s.json", product)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return []DeprecatedVersion{}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []DeprecatedVersion{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []DeprecatedVersion{}
	}

	var cycles []endoflifeCycle
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []DeprecatedVersion{}
	}

	if err := json.Unmarshal(body, &cycles); err != nil {
		return []DeprecatedVersion{}
	}

	// Convert to DeprecatedVersion format, include all versions with EOL set
	// If endoflife.date says it's EOL, we trust that regardless of date
	var deprecated []DeprecatedVersion
	for _, cycle := range cycles {
		var isEOL bool

		// Handle EOL field which can be a string (date) or bool (true for EOL)
		switch v := cycle.EOL.(type) {
		case bool:
			if v {
				isEOL = true
			} else {
				continue // Not EOL
			}
		case string:
			if v == "" || v == "false" {
				continue // Not EOL
			}
			// If EOL is a string (date), it means it's EOL - trust the API
			isEOL = true
		default:
			continue // Unknown format
		}

		// Include all versions marked as EOL by the API
		if isEOL {
			deprecated = append(deprecated, DeprecatedVersion{
				Version: cycle.Cycle,
			})
		}
	}

	// Update cache
	deprecationCacheMu.Lock()
	deprecationCache[product] = deprecated
	deprecationCacheTime[product] = time.Now()
	deprecationCacheMu.Unlock()

	return deprecated
}

// parseDockerfileForDeprecations parses a Dockerfile and checks for deprecated language versions
func parseDockerfileForDeprecations(ctx context.Context, repo, content string) []map[string]interface{} {
	var deprecations []map[string]interface{}
	lines := strings.Split(content, "\n")

	// Languages to check in Dockerfile FROM statements
	languagesToCheck := []string{"node", "python", "golang", "ruby", "java", "amazoncorretto", "alpine", "ubuntu", "debian"}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "FROM") {
			// Parse FROM line: FROM node:18 or FROM python:3.9-slim
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}

			image := parts[1]
			// Extract base image and version
			if strings.Contains(image, ":") {
				imageParts := strings.Split(image, ":")
				if len(imageParts) != 2 {
					continue
				}

				baseImage := strings.ToLower(imageParts[0])
				version := imageParts[1]

				// Check for deprecated versions for each language
				for _, lang := range languagesToCheck {
					if strings.Contains(baseImage, lang) {
						deprecatedVersions := getDeprecatedVersions(ctx, lang)

						// Extract version parts for comparison
						// Handle versions like "16", "16-alpine", "16.20.2", "16-alpine3.18"
						// First, remove any suffix after "-" (like "-alpine", "-slim")
						baseVersion := version
						if dashIdx := strings.Index(version, "-"); dashIdx != -1 {
							baseVersion = version[:dashIdx]
						}

						versionParts := strings.Split(baseVersion, ".")

						// For Ruby, compare major.minor (e.g., "2.7"), for others compare major only
						var versionToCompare string
						if lang == "ruby" && len(versionParts) >= 2 {
							versionToCompare = versionParts[0] + "." + versionParts[1]
						} else if len(versionParts) > 0 {
							versionToCompare = versionParts[0]
						} else {
							versionToCompare = baseVersion
						}

						// Check against deprecated versions
						for _, depVersion := range deprecatedVersions {
							// Match if version matches exactly, or starts with the deprecated version
							if versionToCompare == depVersion.Version ||
								strings.HasPrefix(baseVersion, depVersion.Version+".") ||
								strings.HasPrefix(version, depVersion.Version+"-") ||
								version == depVersion.Version {
								deprecations = append(deprecations, map[string]interface{}{
									"repository": repo,
									"language":   lang,
									"version":    version,
									"image":      image,
									"file":       "Dockerfile",
								})
								break
							}
						}
						break // Found a matching language, no need to check others
					}
				}
			}
		}
	}

	return deprecations
}

// parsePackageJSONForDeprecations parses package.json and checks for deprecated Node.js versions
func parsePackageJSONForDeprecations(ctx context.Context, repo, content string) []map[string]interface{} {
	var deprecations []map[string]interface{}

	// Parse JSON
	var pkgJSON struct {
		Engines struct {
			Node string `json:"node"`
		} `json:"engines"`
	}

	if err := json.Unmarshal([]byte(content), &pkgJSON); err != nil {
		return deprecations
	}

	if pkgJSON.Engines.Node == "" {
		return deprecations
	}

	// Extract version (handle ranges like ">=18.0.0", "^16.0.0", "18.x", etc.)
	nodeVersion := strings.TrimSpace(pkgJSON.Engines.Node)
	originalVersion := nodeVersion

	// Check if it's a range that allows newer versions (>=, >, ^, ~)
	// These ranges can be satisfied by non-deprecated versions, so we shouldn't flag them
	isRangeAllowingNewer := strings.HasPrefix(nodeVersion, ">=") ||
		strings.HasPrefix(nodeVersion, ">") ||
		strings.HasPrefix(nodeVersion, "^") ||
		strings.HasPrefix(nodeVersion, "~")

	// If it's a range allowing newer versions, skip checking (not a false positive)
	// because the range can be satisfied by non-deprecated versions
	if isRangeAllowingNewer {
		return deprecations
	}

	// Remove range operators to extract base version (for exact versions or <=, < ranges)
	nodeVersion = strings.TrimPrefix(nodeVersion, "<=")
	nodeVersion = strings.TrimPrefix(nodeVersion, "<")
	nodeVersion = strings.TrimPrefix(nodeVersion, "=")
	nodeVersion = strings.TrimSpace(nodeVersion)

	// Extract major version (e.g., "18.0.0" -> "18", "16.x" -> "16")
	parts := strings.Split(nodeVersion, ".")
	if len(parts) == 0 {
		return deprecations
	}

	majorVersion := parts[0]

	// Check against deprecated Node.js versions from API
	deprecatedNodeVersions := getDeprecatedVersions(ctx, "node")

	for _, depVersion := range deprecatedNodeVersions {
		if majorVersion == depVersion.Version {
			// Only flag exact versions or ranges that restrict to deprecated versions (<=, <)
			deprecations = append(deprecations, map[string]interface{}{
				"repository": repo,
				"language":   "node",
				"version":    originalVersion,
				"file":       "package.json",
			})
			break
		}
	}

	return deprecations
}

// parseNvmrcForDeprecations parses .nvmrc and checks for deprecated Node.js versions
func parseNvmrcForDeprecations(ctx context.Context, repo, content string) []map[string]interface{} {
	var deprecations []map[string]interface{}

	version := strings.TrimSpace(content)
	if version == "" {
		return deprecations
	}

	// Remove 'v' prefix if present
	version = strings.TrimPrefix(version, "v")

	// Extract major version
	parts := strings.Split(version, ".")
	if len(parts) > 0 {
		majorVersion := parts[0]

		// Check against deprecated Node.js versions from API
		deprecatedNodeVersions := getDeprecatedVersions(ctx, "node")

		for _, depVersion := range deprecatedNodeVersions {
			if majorVersion == depVersion.Version {
				deprecations = append(deprecations, map[string]interface{}{
					"repository": repo,
					"language":   "node",
					"version":    version,
					"file":       ".nvmrc",
				})
				break
			}
		}
	}

	return deprecations
}

// parseToolVersionsForDeprecations parses .tool-versions and checks for deprecated versions
func parseToolVersionsForDeprecations(ctx context.Context, repo, content string) []map[string]interface{} {
	var deprecations []map[string]interface{}
	lines := strings.Split(content, "\n")

	// Supported tools that can be checked via API
	supportedTools := []string{"nodejs", "golang", "python", "ruby", "java"}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: toolname version (e.g., "nodejs 18.0.0" or "golang 1.21")
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		toolName := strings.ToLower(parts[0])
		version := parts[1]

		// Check if this tool is supported
		isSupported := false
		for _, supported := range supportedTools {
			if toolName == supported {
				isSupported = true
				break
			}
		}

		if isSupported {
			// Get deprecated versions from API
			deprecatedVersions := getDeprecatedVersions(ctx, toolName)

			// Extract version for comparison
			versionParts := strings.Split(version, ".")

			// For Ruby, compare major.minor (e.g., "2.7"), for others compare major only
			var versionToCompare string
			if toolName == "ruby" && len(versionParts) >= 2 {
				versionToCompare = versionParts[0] + "." + versionParts[1]
			} else if len(versionParts) > 0 {
				versionToCompare = versionParts[0]
			} else {
				versionToCompare = version
			}

			for _, depVersion := range deprecatedVersions {
				if versionToCompare == depVersion.Version || strings.HasPrefix(version, depVersion.Version+".") {
					deprecations = append(deprecations, map[string]interface{}{
						"repository": repo,
						"language":   toolName,
						"version":    version,
						"file":       ".tool-versions",
					})
					break
				}
			}
		}
	}

	return deprecations
}

// parseGoModForDeprecations parses go.mod and checks for deprecated Golang versions
func parseGoModForDeprecations(ctx context.Context, repo, content string) []map[string]interface{} {
	var deprecations []map[string]interface{}
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for "go 1.21" or "go 1.20" etc.
		if strings.HasPrefix(line, "go ") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}

			version := parts[1]
			// Remove any suffix after space or comment
			if idx := strings.Index(version, " "); idx != -1 {
				version = version[:idx]
			}
			if idx := strings.Index(version, "//"); idx != -1 {
				version = version[:idx]
			}
			version = strings.TrimSpace(version)

			if version == "" {
				continue
			}

			// Extract major.minor version (e.g., "1.21" -> "1.21", "1.20.5" -> "1.20")
			versionParts := strings.Split(version, ".")
			var versionToCompare string
			if len(versionParts) >= 2 {
				// For Go, compare major.minor (e.g., "1.21")
				versionToCompare = versionParts[0] + "." + versionParts[1]
			} else if len(versionParts) > 0 {
				versionToCompare = versionParts[0]
			} else {
				versionToCompare = version
			}

			// Check against deprecated Golang versions from API
			deprecatedGoVersions := getDeprecatedVersions(ctx, "golang")

			for _, depVersion := range deprecatedGoVersions {
				// Compare major.minor for Go versions
				if versionToCompare == depVersion.Version || strings.HasPrefix(version, depVersion.Version+".") {
					deprecations = append(deprecations, map[string]interface{}{
						"repository": repo,
						"language":   "golang",
						"version":    version,
						"file":       "go.mod",
					})
					break
				}
			}
			break // Only one "go" directive per go.mod file
		}
	}

	return deprecations
}

// parsePythonVersionForDeprecations parses .python-version and checks for deprecated Python versions
func parsePythonVersionForDeprecations(ctx context.Context, repo, content string) []map[string]interface{} {
	var deprecations []map[string]interface{}

	version := strings.TrimSpace(content)
	if version == "" {
		return deprecations
	}

	// Remove 'v' prefix if present
	version = strings.TrimPrefix(version, "v")

	// Extract major.minor version for Python (e.g., "3.9" from "3.9.18")
	versionParts := strings.Split(version, ".")
	var versionToCompare string
	if len(versionParts) >= 2 {
		// For Python, compare major.minor (e.g., "3.9")
		versionToCompare = versionParts[0] + "." + versionParts[1]
	} else if len(versionParts) > 0 {
		versionToCompare = versionParts[0]
	} else {
		versionToCompare = version
	}

	// Check against deprecated Python versions from API
	deprecatedPythonVersions := getDeprecatedVersions(ctx, "python")

	for _, depVersion := range deprecatedPythonVersions {
		// Compare major.minor for Python versions
		if versionToCompare == depVersion.Version || strings.HasPrefix(version, depVersion.Version+".") {
			deprecations = append(deprecations, map[string]interface{}{
				"repository": repo,
				"language":   "python",
				"version":    version,
				"file":       ".python-version",
			})
			break
		}
	}

	return deprecations
}

// parseRubyVersionForDeprecations parses .ruby-version and checks for deprecated Ruby versions
func parseRubyVersionForDeprecations(ctx context.Context, repo, content string) []map[string]interface{} {
	var deprecations []map[string]interface{}

	version := strings.TrimSpace(content)
	if version == "" {
		return deprecations
	}

	// Remove 'v' prefix if present
	version = strings.TrimPrefix(version, "v")

	// Extract major.minor version for Ruby (e.g., "2.7" from "2.7.8")
	versionParts := strings.Split(version, ".")
	var versionToCompare string
	if len(versionParts) >= 2 {
		// For Ruby, compare major.minor (e.g., "2.7")
		versionToCompare = versionParts[0] + "." + versionParts[1]
	} else if len(versionParts) > 0 {
		versionToCompare = versionParts[0]
	} else {
		versionToCompare = version
	}

	// Check against deprecated Ruby versions from API
	deprecatedRubyVersions := getDeprecatedVersions(ctx, "ruby")

	for _, depVersion := range deprecatedRubyVersions {
		// Compare major.minor for Ruby versions
		if versionToCompare == depVersion.Version || strings.HasPrefix(version, depVersion.Version+".") {
			deprecations = append(deprecations, map[string]interface{}{
				"repository": repo,
				"language":   "ruby",
				"version":    version,
				"file":       ".ruby-version",
			})
			break
		}
	}

	return deprecations
}

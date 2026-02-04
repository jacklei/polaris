package output

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jacklei/polaris/pkg/aws"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/rs/zerolog/log"
)

// Print formats and prints data based on the configured output type
func Print(data interface{}, outputType string, sortColumn string, sortDescending bool, filter string) error {
	if outputType == "json" {
		return PrintJSON(data)
	}
	if outputType == "table" {
		return PrintTable(data, sortColumn, sortDescending, filter)
	}
	return PrintText(data)
}

// PrintJSON prints data as JSON
func PrintJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// PrintText prints data as plain text using zerolog
func PrintText(data interface{}) error {
	// Check if data is a map
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		log.Info().Interface("data", data).Send()
		return nil
	}

	// Check if it's Jira summary data (has "summary" key with ticket info)
	summaryKey := val.MapIndex(reflect.ValueOf("summary"))
	if summaryKey.IsValid() {
		summaryVal := summaryKey.Interface()
		if summaryMap, ok := summaryVal.(map[string]interface{}); ok {
			if _, hasKey := summaryMap["key"]; hasKey {
				return printJiraSummaryText(data)
			}
		}
	}

	// Check if it's ECR scan data (has "scans" key for multiple scans)
	scansKey := val.MapIndex(reflect.ValueOf("scans"))
	if scansKey.IsValid() {
		repositoryKey := val.MapIndex(reflect.ValueOf("repository"))
		repository := ""
		if repositoryKey.IsValid() {
			repository = fmt.Sprintf("%v", repositoryKey.Interface())
		}

		scansVal := scansKey.Interface()
		scansSlice := reflect.ValueOf(scansVal)
		if scansSlice.Kind() == reflect.Slice {
			for i := 0; i < scansSlice.Len(); i++ {
				scanVal := scansSlice.Index(i).Interface()
				if scanMap, ok := scanVal.(map[string]interface{}); ok {
					tag := fmt.Sprintf("%v", scanMap["tag"])
					cveCountStr := fmt.Sprintf("%v", scanMap["cve_count"])
					pushedAt := fmt.Sprintf("%v", scanMap["pushed_at"])

					// Parse CVE count to determine log level
					cveCount := 0
					if count, err := strconv.Atoi(cveCountStr); err == nil {
						cveCount = count
					}

					logger := log.Info()
					if cveCount > 0 {
						logger = log.Error()
					}

					logger.
						Str("repository", repository).
						Str("tag", tag).
						Str("pushed_at", pushedAt).
						Int("cve_critical_count", cveCount).
						Msg("ECR scan result")
				}
			}
			return nil
		}
	}

	// Check if it's single ECR scan data (has "cve_count" key)
	cveCountKey := val.MapIndex(reflect.ValueOf("cve_count"))
	if cveCountKey.IsValid() {
		repository := ""
		tag := ""
		pushedAt := ""
		cveCountStr := fmt.Sprintf("%v", cveCountKey.Interface())

		// Parse CVE count to determine log level
		cveCount := 0
		if count, err := strconv.Atoi(cveCountStr); err == nil {
			cveCount = count
		}

		if repoKey := val.MapIndex(reflect.ValueOf("repository")); repoKey.IsValid() {
			repository = fmt.Sprintf("%v", repoKey.Interface())
		}
		if tagKey := val.MapIndex(reflect.ValueOf("tag")); tagKey.IsValid() {
			tag = fmt.Sprintf("%v", tagKey.Interface())
		}
		if pushedAtKey := val.MapIndex(reflect.ValueOf("pushed_at")); pushedAtKey.IsValid() {
			pushedAt = fmt.Sprintf("%v", pushedAtKey.Interface())
		}

		logger := log.Info()
		if cveCount > 0 {
			logger = log.Error()
		}

		logger.
			Str("repository", repository).
			Str("tag", tag).
			Str("pushed_at", pushedAt).
			Int("cve_critical_count", cveCount).
			Msg("ECR scan result")
		return nil
	}

	// Check if it's CAB tickets grouped by team (has "tickets_by_team" key)
	ticketsByTeamKey := val.MapIndex(reflect.ValueOf("tickets_by_team"))
	if ticketsByTeamKey.IsValid() {
		return printCABTicketsText(data)
	}

	// For other data types, use zerolog's interface logging
	log.Info().Interface("data", data).Send()
	return nil
}

// Printf formats and prints text (only for text output mode)
func Printf(format string, outputType string, args ...interface{}) error {
	// Printf always outputs as text regardless of output type
	_, err := fmt.Fprintf(os.Stdout, format, args...)
	return err
}

// Println prints a line (only for text output mode)
func Println(outputType string, args ...interface{}) error {
	// Println always outputs as text regardless of output type
	_, err := fmt.Fprintln(os.Stdout, args...)
	return err
}

// PrintTable prints data as a formatted table
func PrintTable(data interface{}, sortColumn string, sortDescending bool, filter string) error {
	// Check if data is a map
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return PrintText(data)
	}

	// Check if this is deprecations output
	if val.MapIndex(reflect.ValueOf("deprecations")).IsValid() {
		return printDeprecationsTable(data)
	}

	// Check if it's Jira summary data (has "summary" key with ticket info)
	summaryKey := val.MapIndex(reflect.ValueOf("summary"))
	if summaryKey.IsValid() {
		summaryVal := summaryKey.Interface()
		if summaryMap, ok := summaryVal.(map[string]interface{}); ok {
			if _, hasKey := summaryMap["key"]; hasKey {
				return printJiraSummaryTable(data)
			}
		}
	}

	// Check if it's Claude analysis data (has "claude_analysis" key)
	claudeAnalysisKey := val.MapIndex(reflect.ValueOf("claude_analysis"))
	if claudeAnalysisKey.IsValid() {
		return printClaudeAnalysisTable(data)
	}

	// Check if it's CAB tickets grouped by team (has "tickets_by_team" key)
	ticketsByTeamKey := val.MapIndex(reflect.ValueOf("tickets_by_team"))
	if ticketsByTeamKey.IsValid() {
		return printCABTicketsTable(data)
	}

	// Check if it's ECR scan data (has "scans" key for multiple scans, or "cve_count" for single scan)
	scansKey := val.MapIndex(reflect.ValueOf("scans"))
	if scansKey.IsValid() {
		return printEcrScansTable(data)
	}

	cveCountKey := val.MapIndex(reflect.ValueOf("cve_count"))
	if cveCountKey.IsValid() {
		return printEcrScanTable(data)
	}

	// Check if it's ECS services data (has "services" key)
	servicesKey := val.MapIndex(reflect.ValueOf("services"))
	if !servicesKey.IsValid() {
		return PrintText(data)
	}

	servicesVal := servicesKey.Interface()
	servicesSlice := reflect.ValueOf(servicesVal)
	if servicesSlice.Kind() != reflect.Slice {
		return PrintText(data)
	}

	// Convert to []ECSService
	var services []aws.ECSService
	for i := 0; i < servicesSlice.Len(); i++ {
		serviceVal := servicesSlice.Index(i).Interface()
		if service, ok := serviceVal.(aws.ECSService); ok {
			services = append(services, service)
		}
	}

	return printServicesTable(services, sortColumn, sortDescending, filter)
}

func printServicesTable(services []aws.ECSService, sortColumn string, sortDescending bool, filter string) error {
	// Filter services if filter is specified
	if filter != "" {
		filtered := make([]aws.ECSService, 0, len(services))

		// Check if filter is "cve" (special case - no threshold needed)
		if strings.TrimSpace(filter) == "cve" {
			// Show only services with critical CVEs
			for _, svc := range services {
				if svc.CVECriticalCount > 0 {
					filtered = append(filtered, svc)
				}
			}
			services = filtered
		} else {
			// Parse filter: "column:threshold"
			parts := strings.Split(filter, ":")
			if len(parts) != 2 {
				return fmt.Errorf("invalid filter format: expected 'column:threshold' (e.g., 'count:100' or 'delta:0') or 'cve'")
			}

			filterCol := strings.TrimSpace(parts[0])
			thresholdStr := strings.TrimSpace(parts[1])
			threshold, err := strconv.ParseFloat(thresholdStr, 64)
			if err != nil {
				return fmt.Errorf("invalid threshold value '%s': %w", thresholdStr, err)
			}

			for _, svc := range services {
				var shouldInclude bool

				switch filterCol {
				case "count":
					// Filter by desired count: show services where desired count < threshold
					shouldInclude = float64(svc.DesiredCount) < threshold
				case "delta":
					// Filter by delta: show services where delta < threshold
					delta := svc.RunningCount - svc.DesiredCount
					shouldInclude = float64(delta) < threshold
				case "running":
					// Filter by running count: show services where running count < threshold
					shouldInclude = float64(svc.RunningCount) < threshold
				default:
					// Unknown column, skip filtering for this service
					shouldInclude = true
				}

				if shouldInclude {
					filtered = append(filtered, svc)
				}
			}
			services = filtered
		}
	}

	// Sort services if sort column is specified
	if sortColumn != "" {
		sort.Slice(services, func(i, j int) bool {
			var less bool
			switch sortColumn {
			case "name":
				less = services[i].Name < services[j].Name
			case "count":
				// Sort by desired count first, then running count
				if services[i].DesiredCount != services[j].DesiredCount {
					less = services[i].DesiredCount < services[j].DesiredCount
				} else {
					less = services[i].RunningCount < services[j].RunningCount
				}
			case "delta":
				// Sort by delta (running - desired)
				deltaI := services[i].RunningCount - services[i].DesiredCount
				deltaJ := services[j].RunningCount - services[j].DesiredCount
				less = deltaI < deltaJ
			case "cve":
				// Sort by CVE critical count
				less = services[i].CVECriticalCount < services[j].CVECriticalCount
			default:
				return false // Unknown column, don't sort
			}
			if sortDescending {
				return !less
			}
			return less
		})
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	// Check if any service has CVE data (scanning was enabled)
	hasCVEData := false
	for _, svc := range services {
		if svc.CVECriticalCount > 0 {
			hasCVEData = true
			break
		}
	}

	// Build header based on whether CVE data exists
	if hasCVEData {
		t.AppendHeader(table.Row{"Name", "Image", "Version", "Pushed At", "CVE Critical", "Count", "Delta"})
	} else {
		t.AppendHeader(table.Row{"Name", "Image", "Version", "Pushed At", "Count", "Delta"})
	}

	for _, svc := range services {
		// Count column: show desired if running>=desired, otherwise show desired/running/pending
		var countStr string
		var countColor text.Color
		if svc.RunningCount >= svc.DesiredCount {
			countStr = fmt.Sprintf("%d", svc.DesiredCount)
			countColor = text.FgGreen
		} else {
			countStr = fmt.Sprintf("%d/%d/%d", svc.DesiredCount, svc.RunningCount, svc.PendingCount)
			countColor = text.FgWhite
		}

		// Delta column: difference between running and desired, with percentage
		delta := svc.RunningCount - svc.DesiredCount
		percent := float64(svc.RunningCount) / float64(svc.DesiredCount) * 100

		var deltaStr string
		var deltaColor text.Color
		if delta >= 0 {
			deltaStr = fmt.Sprintf("%+d (%.0f%%)", delta, percent)
			deltaColor = text.FgGreen
		} else {
			deltaStr = fmt.Sprintf("%+d (%.0f%%)", delta, percent)
			if percent < 70 {
				deltaColor = text.FgRed
			} else if percent < 100 {
				deltaColor = text.FgYellow
			} else {
				deltaColor = text.FgWhite
			}
		}

		// Format pushed at date (show shorter format if available)
		pushedAtStr := svc.PushedAt
		if pushedAtStr != "" {
			// Try to parse and format as shorter date
			if t, err := time.Parse(time.RFC3339, pushedAtStr); err == nil {
				pushedAtStr = t.Format("2006-01-02 15:04")
			}
		}

		// Build row based on whether CVE data exists
		if hasCVEData {
			cveStr := fmt.Sprintf("%d", svc.CVECriticalCount)
			cveColor := text.FgWhite
			if svc.CVECriticalCount > 0 {
				cveColor = text.FgRed
			}

			t.AppendRow(table.Row{
				svc.Name,
				svc.Image,
				svc.Version,
				pushedAtStr,
				text.Colors{cveColor}.Sprint(cveStr),
				text.Colors{countColor}.Sprint(countStr),
				text.Colors{deltaColor}.Sprint(deltaStr),
			})
		} else {
			t.AppendRow(table.Row{
				svc.Name,
				svc.Image,
				svc.Version,
				pushedAtStr,
				text.Colors{countColor}.Sprint(countStr),
				text.Colors{deltaColor}.Sprint(deltaStr),
			})
		}
	}

	t.Render()
	return nil
}

func printEcrScanTable(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return PrintText(data)
	}

	// Extract values from the map
	repositoryKey := val.MapIndex(reflect.ValueOf("repository"))
	tagKey := val.MapIndex(reflect.ValueOf("tag"))
	pushedAtKey := val.MapIndex(reflect.ValueOf("pushed_at"))
	cveCountKey := val.MapIndex(reflect.ValueOf("cve_count"))

	var repository, tag, pushedAt string
	var cveCount int

	if repositoryKey.IsValid() {
		if repoVal, ok := repositoryKey.Interface().(string); ok {
			repository = repoVal
		}
	}
	if tagKey.IsValid() {
		if tagVal, ok := tagKey.Interface().(string); ok {
			tag = tagVal
		}
	}
	if pushedAtKey.IsValid() {
		if pushedAtVal, ok := pushedAtKey.Interface().(string); ok {
			pushedAt = pushedAtVal
		}
	}
	if cveCountKey.IsValid() {
		// Handle both int and float64 (JSON unmarshaling can produce float64)
		switch v := cveCountKey.Interface().(type) {
		case int:
			cveCount = v
		case int64:
			cveCount = int(v)
		case float64:
			cveCount = int(v)
		}
	}

	// Format pushed at date
	pushedAtStr := pushedAt
	if pushedAtStr != "" {
		if t, err := time.Parse(time.RFC3339, pushedAtStr); err == nil {
			pushedAtStr = t.Format("2006-01-02 15:04")
		}
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Repository", "Tag", "Pushed At", "CVE Critical Count"})

	// Color code based on CVE count
	var cveColor text.Color
	cveStr := fmt.Sprintf("%d", cveCount)
	if cveCount == 0 {
		cveColor = text.FgGreen
	} else if cveCount < 5 {
		cveColor = text.FgYellow
	} else {
		cveColor = text.FgRed
	}

	t.AppendRow(table.Row{
		repository,
		tag,
		pushedAtStr,
		text.Colors{cveColor}.Sprint(cveStr),
	})

	t.Render()
	return nil
}

func printEcrScansTable(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return PrintText(data)
	}

	// Extract repository and scans
	repositoryKey := val.MapIndex(reflect.ValueOf("repository"))
	scansKey := val.MapIndex(reflect.ValueOf("scans"))

	var repository string
	if repositoryKey.IsValid() {
		if repoVal, ok := repositoryKey.Interface().(string); ok {
			repository = repoVal
		}
	}

	if !scansKey.IsValid() {
		return PrintText(data)
	}

	scansVal := scansKey.Interface()
	scansSlice := reflect.ValueOf(scansVal)
	if scansSlice.Kind() != reflect.Slice {
		return PrintText(data)
	}

	// Extract all scan results into a slice for sorting
	type scanResult struct {
		tag      string
		pushedAt string
		cveCount int
	}
	scanResults := make([]scanResult, 0, scansSlice.Len())

	for i := 0; i < scansSlice.Len(); i++ {
		scanVal := scansSlice.Index(i).Interface()
		scanReflect := reflect.ValueOf(scanVal)

		var tag string
		var pushedAt string
		var cveCount int

		// Handle both maps and structs
		if scanReflect.Kind() == reflect.Map {
			// It's a map
			tagKey := scanReflect.MapIndex(reflect.ValueOf("tag"))
			if tagKey.IsValid() {
				if tagVal, ok := tagKey.Interface().(string); ok {
					tag = tagVal
				}
			}

			pushedAtKey := scanReflect.MapIndex(reflect.ValueOf("pushed_at"))
			if pushedAtKey.IsValid() {
				if pushedAtVal, ok := pushedAtKey.Interface().(string); ok {
					pushedAt = pushedAtVal
				}
			}

			cveCountKey := scanReflect.MapIndex(reflect.ValueOf("cve_count"))
			if cveCountKey.IsValid() {
				switch v := cveCountKey.Interface().(type) {
				case int:
					cveCount = v
				case int64:
					cveCount = int(v)
				case float64:
					cveCount = int(v)
				}
			}
		} else if scanReflect.Kind() == reflect.Struct {
			// It's a struct - access fields directly
			tagField := scanReflect.FieldByName("Tag")
			if tagField.IsValid() && tagField.Kind() == reflect.String {
				tag = tagField.String()
			}

			pushedAtField := scanReflect.FieldByName("PushedAt")
			if pushedAtField.IsValid() {
				if pushedAtField.Kind() == reflect.String {
					pushedAt = pushedAtField.String()
				}
			}

			cveCountField := scanReflect.FieldByName("CveCount")
			if cveCountField.IsValid() {
				switch cveCountField.Kind() {
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					cveCount = int(cveCountField.Int())
				case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					cveCount = int(cveCountField.Uint())
				case reflect.Float32, reflect.Float64:
					cveCount = int(cveCountField.Float())
				}
			}
		} else {
			// Skip if not map or struct
			continue
		}

		scanResults = append(scanResults, scanResult{
			tag:      tag,
			pushedAt: pushedAt,
			cveCount: cveCount,
		})
	}

	// Sort by pushed_at descending (newest first)
	sort.Slice(scanResults, func(i, j int) bool {
		if scanResults[i].pushedAt == "" && scanResults[j].pushedAt == "" {
			return false
		}
		if scanResults[i].pushedAt == "" {
			return false // Empty dates go to the end
		}
		if scanResults[j].pushedAt == "" {
			return true
		}
		// Parse and compare dates
		ti, err1 := time.Parse(time.RFC3339, scanResults[i].pushedAt)
		tj, err2 := time.Parse(time.RFC3339, scanResults[j].pushedAt)
		if err1 != nil || err2 != nil {
			return scanResults[i].pushedAt > scanResults[j].pushedAt // String comparison fallback
		}
		return ti.After(tj) // Descending order (newest first)
	})

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Repository", "Tag", "Pushed At", "CVE Critical Count"})

	// Render sorted results
	for _, result := range scanResults {
		// Format pushed at date
		pushedAtStr := result.pushedAt
		if pushedAtStr != "" {
			if t, err := time.Parse(time.RFC3339, pushedAtStr); err == nil {
				pushedAtStr = t.Format("2006-01-02 15:04")
			}
		}

		// Color code based on CVE count
		var cveColor text.Color
		cveStr := fmt.Sprintf("%d", result.cveCount)
		if result.cveCount == 0 {
			cveColor = text.FgGreen
		} else if result.cveCount < 5 {
			cveColor = text.FgYellow
		} else {
			cveColor = text.FgRed
		}

		t.AppendRow(table.Row{
			repository,
			result.tag,
			pushedAtStr,
			text.Colors{cveColor}.Sprint(cveStr),
		})
	}

	t.Render()
	return nil
}

// printClaudeAnalysisTable formats Claude analysis as a table
func printClaudeAnalysisTable(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return PrintText(data)
	}

	// Extract Claude analysis text
	claudeAnalysisKey := val.MapIndex(reflect.ValueOf("claude_analysis"))
	if !claudeAnalysisKey.IsValid() {
		return PrintText(data)
	}

	analysisText, ok := claudeAnalysisKey.Interface().(string)
	if !ok {
		return PrintText(data)
	}

	// Extract metadata
	urlKey := val.MapIndex(reflect.ValueOf("url"))
	ownerKey := val.MapIndex(reflect.ValueOf("owner"))
	repoKey := val.MapIndex(reflect.ValueOf("repo"))
	diffTypeKey := val.MapIndex(reflect.ValueOf("type"))

	url := ""
	owner := ""
	repo := ""
	diffType := ""

	if urlKey.IsValid() {
		url = fmt.Sprintf("%v", urlKey.Interface())
	}
	if ownerKey.IsValid() {
		owner = fmt.Sprintf("%v", ownerKey.Interface())
	}
	if repoKey.IsValid() {
		repo = fmt.Sprintf("%v", repoKey.Interface())
	}
	if diffTypeKey.IsValid() {
		diffType = fmt.Sprintf("%v", diffTypeKey.Interface())
	}

	// Parse analysis text to extract findings
	findings := parseClaudeAnalysis(analysisText)

	// Debug: log what we got
	preview := analysisText
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}
	log.Debug().
		Int("analysis_length", len(analysisText)).
		Int("findings_count", len(findings)).
		Str("analysis_preview", preview).
		Msg("Parsed Claude analysis")

	// Create table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.Style().Options.DrawBorder = true
	t.Style().Options.SeparateColumns = true
	t.Style().Options.SeparateHeader = true

	// Print header with metadata
	if url != "" || owner != "" || repo != "" {
		fmt.Println("\n📋 GitHub Diff Analysis")
		if url != "" {
			fmt.Printf("URL: %s\n", url)
		}
		if owner != "" && repo != "" {
			fmt.Printf("Repository: %s/%s\n", owner, repo)
		}
		if diffType != "" {
			fmt.Printf("Type: %s\n", diffType)
		}
		fmt.Println()
	}

	// If no findings, show the raw analysis text so user can see what Claude said
	if len(findings) == 0 {
		// If analysis text exists but no structured findings, show the raw text
		trimmedAnalysis := strings.TrimSpace(analysisText)
		isNoIssues := isNoIssuesMessage(trimmedAnalysis)
		log.Debug().
			Int("trimmed_length", len(trimmedAnalysis)).
			Bool("is_no_issues", isNoIssues).
			Msg("Checking if should show raw analysis")

		if len(trimmedAnalysis) > 0 && !isNoIssues {
			fmt.Println("📝 Analysis:")
			fmt.Println(strings.Repeat("─", 80))
			fmt.Println(analysisText)
			fmt.Println(strings.Repeat("─", 80))
			return nil
		}
		
		// Show success message when no issues found or analysis is empty
		if len(trimmedAnalysis) == 0 || isNoIssues {
			fmt.Println("\n✅ SRE Technical Review Complete")
			fmt.Println(strings.Repeat("─", 80))
			if url != "" {
				fmt.Printf("URL: %s\n", url)
			}
			if owner != "" && repo != "" {
				fmt.Printf("Repository: %s/%s\n", owner, repo)
			}
			fmt.Println("\n✅ No security, database, or infrastructure concerns found.")
			fmt.Println("The diff appears safe to proceed.")
			fmt.Println(strings.Repeat("─", 80))
			return nil
		}
		
		log.Debug().Msg("No findings extracted from Claude analysis, returning nil")
		return nil
	}

	// Print findings table
	t.AppendHeader(table.Row{"Category", "Severity", "Finding"})

	for _, finding := range findings {
		var severityColor text.Color
		var severityText string

		switch finding.Severity {
		case "CRITICAL":
			severityColor = text.FgRed
			severityText = "🔴 CRITICAL"
		case "HIGH":
			severityColor = text.FgRed
			severityText = "🔴 HIGH"
		case "MEDIUM":
			severityColor = text.FgYellow
			severityText = "🟡 MEDIUM"
		case "LOW":
			severityColor = text.FgYellow
			severityText = "🟡 LOW"
		default:
			severityColor = text.FgWhite
			severityText = finding.Severity
		}

		// Truncate long findings for table display
		findingText := finding.Description
		if len(findingText) > 100 {
			findingText = findingText[:97] + "..."
		}

		t.AppendRow(table.Row{
			finding.Category,
			text.Colors{severityColor}.Sprint(severityText),
			findingText,
		})
	}

	t.Render()

	// Extract and display risk assessment score
	riskScore := extractRiskScore(analysisText)
	if riskScore >= 0 {
		fmt.Println()
		fmt.Println(strings.Repeat("─", 80))
		fmt.Printf("🎯 Risk Assessment Score: %d/10", riskScore)
		if riskScore >= 9 {
			fmt.Printf(" - CRITICAL RISK - Blocking issues must be fixed before merge")
		} else if riskScore >= 6 {
			fmt.Printf(" - HIGH RISK - Significant issues need attention")
		} else if riskScore >= 3 {
			fmt.Printf(" - MEDIUM RISK - Some concerns should be addressed")
		} else {
			fmt.Printf(" - LOW RISK - Minor issues, no blocking concerns")
		}
		fmt.Println()
		fmt.Println(strings.Repeat("─", 80))
	}

	// Print full analysis text below the table
	fmt.Println("\n📝 Full Analysis:")
	fmt.Println(strings.Repeat("─", 80))
	fmt.Println(analysisText)
	fmt.Println(strings.Repeat("─", 80))

	return nil
}

// Finding represents a parsed finding from Claude analysis
type Finding struct {
	Category    string
	Severity    string
	Description string
}

// parseClaudeAnalysis parses the Claude analysis text to extract structured findings
func parseClaudeAnalysis(analysisText string) []Finding {
	var findings []Finding
	lines := strings.Split(analysisText, "\n")

	currentCategory := ""
	currentSeverity := "MEDIUM"
	var currentFinding strings.Builder

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Detect numbered list items (e.g., "- 1. **Layer Optimization**:")
		lineLower := strings.ToLower(line)
		if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "1.") {
			// Extract the finding from the list item
			findingText := strings.TrimPrefix(line, "-")
			findingText = strings.TrimPrefix(findingText, "*")
			findingText = strings.TrimSpace(findingText)
			// Remove leading numbers like "1. " or "**Category**:"
			if idx := strings.Index(findingText, "**"); idx != -1 {
				// Extract category from markdown bold
				categoryEnd := strings.Index(findingText[idx+2:], "**")
				if categoryEnd != -1 {
					category := findingText[idx+2 : idx+2+categoryEnd]
					findingText = strings.TrimSpace(findingText[idx+2+categoryEnd+2:])
					findingText = strings.TrimPrefix(findingText, ":")
					findingText = strings.TrimSpace(findingText)

					// Map category to our categories
					categoryLower := strings.ToLower(category)
					if strings.Contains(categoryLower, "layer") || strings.Contains(categoryLower, "dockerfile") || strings.Contains(categoryLower, "docker") {
						currentCategory = "Dockerfile"
					} else if strings.Contains(categoryLower, "database") || strings.Contains(categoryLower, "migration") || strings.Contains(categoryLower, "sql") {
						currentCategory = "Database"
					} else if strings.Contains(categoryLower, "security") || strings.Contains(categoryLower, "vulnerability") {
						currentCategory = "Security"
					} else if strings.Contains(categoryLower, "secret") || strings.Contains(categoryLower, "credential") {
						currentCategory = "Exposed Secrets"
					} else if strings.Contains(categoryLower, "cloudformation") || strings.Contains(categoryLower, "infrastructure") {
						currentCategory = "CloudFormation"
					} else {
						currentCategory = category
					}

					if len(findingText) > 0 {
						findings = append(findings, Finding{
							Category:    currentCategory,
							Severity:    detectSeverity(findingText),
							Description: findingText,
						})
					}
					continue
				}
			}
			// If no category found, treat as general finding
			if len(findingText) > 0 && !isNoIssuesMessage(findingText) {
				findings = append(findings, Finding{
					Category:    "General",
					Severity:    detectSeverity(findingText),
					Description: findingText,
				})
				continue
			}
		}

		// Detect category headers
		if strings.Contains(lineLower, "security concern") ||
			strings.Contains(lineLower, "security vulnerability") ||
			strings.Contains(lineLower, "security risk") {
			if currentFinding.Len() > 0 {
				findings = append(findings, Finding{
					Category:    currentCategory,
					Severity:    currentSeverity,
					Description: strings.TrimSpace(currentFinding.String()),
				})
				currentFinding.Reset()
			}
			currentCategory = "Security"
			currentSeverity = detectSeverity(line)
			continue
		}

		if strings.Contains(strings.ToLower(line), "database") ||
			strings.Contains(strings.ToLower(line), "sql injection") ||
			strings.Contains(strings.ToLower(line), "query") {
			if currentFinding.Len() > 0 {
				findings = append(findings, Finding{
					Category:    currentCategory,
					Severity:    currentSeverity,
					Description: strings.TrimSpace(currentFinding.String()),
				})
				currentFinding.Reset()
			}
			currentCategory = "Database"
			currentSeverity = detectSeverity(line)
			continue
		}

		if strings.Contains(strings.ToLower(line), "secret") ||
			strings.Contains(strings.ToLower(line), "credential") ||
			strings.Contains(strings.ToLower(line), "api key") ||
			strings.Contains(strings.ToLower(line), "password") ||
			strings.Contains(strings.ToLower(line), "token") {
			if currentFinding.Len() > 0 {
				findings = append(findings, Finding{
					Category:    currentCategory,
					Severity:    currentSeverity,
					Description: strings.TrimSpace(currentFinding.String()),
				})
				currentFinding.Reset()
			}
			currentCategory = "Exposed Secrets"
			currentSeverity = "CRITICAL" // Secrets are always critical
			continue
		}

		if strings.Contains(strings.ToLower(line), "cloudformation") ||
			strings.Contains(strings.ToLower(line), "cfn") ||
			strings.Contains(strings.ToLower(line), "iam policy") ||
			strings.Contains(strings.ToLower(line), "infrastructure") {
			if currentFinding.Len() > 0 {
				findings = append(findings, Finding{
					Category:    currentCategory,
					Severity:    currentSeverity,
					Description: strings.TrimSpace(currentFinding.String()),
				})
				currentFinding.Reset()
			}
			currentCategory = "CloudFormation"
			currentSeverity = detectSeverity(line)
			continue
		}

		if strings.Contains(strings.ToLower(line), "dockerfile") ||
			strings.Contains(strings.ToLower(line), "docker") ||
			strings.Contains(strings.ToLower(line), "container") {
			if currentFinding.Len() > 0 {
				findings = append(findings, Finding{
					Category:    currentCategory,
					Severity:    currentSeverity,
					Description: strings.TrimSpace(currentFinding.String()),
				})
				currentFinding.Reset()
			}
			currentCategory = "Dockerfile"
			currentSeverity = detectSeverity(line)
			continue
		}

		// Detect severity keywords
		if strings.Contains(strings.ToLower(line), "critical") ||
			strings.Contains(strings.ToLower(line), "severe") {
			currentSeverity = "CRITICAL"
		} else if strings.Contains(strings.ToLower(line), "high") {
			currentSeverity = "HIGH"
		} else if strings.Contains(strings.ToLower(line), "low") {
			currentSeverity = "LOW"
		}

		// Accumulate finding text
		if currentCategory != "" {
			if currentFinding.Len() > 0 {
				currentFinding.WriteString(" ")
			}
			currentFinding.WriteString(line)
		}
	}

	// Add last finding
	if currentFinding.Len() > 0 && currentCategory != "" {
		findingDesc := strings.TrimSpace(currentFinding.String())
		// Filter out findings that are just "none identified" messages
		if !isNoIssuesMessage(findingDesc) {
			findings = append(findings, Finding{
				Category:    currentCategory,
				Severity:    currentSeverity,
				Description: findingDesc,
			})
		}
	}

	// Filter out any findings that are just "none identified" messages
	filteredFindings := []Finding{}
	for _, finding := range findings {
		if !isNoIssuesMessage(finding.Description) {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	// If no structured findings, return empty slice (no output will be shown)
	return filteredFindings
}

// isNoIssuesMessage checks if a finding description is just a "no issues" message
func isNoIssuesMessage(text string) bool {
	lowerText := strings.ToLower(strings.TrimSpace(text))
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
		strings.Contains(lowerText, "review is clean") ||
		(lowerText == "none") ||
		(lowerText == "no issues") ||
		(lowerText == "no concerns")
}

// extractRiskScore extracts the risk assessment score from Claude's analysis text
func extractRiskScore(analysisText string) int {
	// Look for patterns like "Risk Assessment Score: X/10" or "Risk Score: X/10"
	lines := strings.Split(analysisText, "\n")
	for _, line := range lines {
		lineLower := strings.ToLower(strings.TrimSpace(line))

		// Check for "risk assessment score: X/10" pattern
		if strings.Contains(lineLower, "risk assessment score") || strings.Contains(lineLower, "risk score") {
			// Try to extract number before "/10"
			if idx := strings.Index(lineLower, "/10"); idx > 0 {
				// Look backwards for a number
				scoreStr := ""
				for i := idx - 1; i >= 0; i-- {
					if line[i] >= '0' && line[i] <= '9' {
						scoreStr = string(line[i]) + scoreStr
					} else if len(scoreStr) > 0 {
						break
					}
				}
				if scoreStr != "" {
					if score, err := strconv.Atoi(scoreStr); err == nil {
						if score >= 0 && score <= 10 {
							return score
						}
					}
				}
			}
		}

		// Also check for standalone "X/10" patterns near "risk"
		if strings.Contains(lineLower, "risk") {
			re := strings.NewReplacer("risk assessment score:", "", "risk score:", "", ":", "", " ", "")
			cleaned := re.Replace(lineLower)
			if idx := strings.Index(cleaned, "/10"); idx > 0 && idx < len(cleaned)-3 {
				scoreStr := cleaned[:idx]
				if score, err := strconv.Atoi(scoreStr); err == nil {
					if score >= 0 && score <= 10 {
						return score
					}
				}
			}
		}
	}

	// If no explicit score found, return -1 to indicate no score
	return -1
}

// printDeprecationsTable prints a table of deprecated language versions found in Dockerfiles
func printDeprecationsTable(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return fmt.Errorf("expected map for deprecations data")
	}

	deprecationsKey := val.MapIndex(reflect.ValueOf("deprecations"))
	if !deprecationsKey.IsValid() {
		return fmt.Errorf("deprecations key not found")
	}

	deprecations := deprecationsKey.Interface()
	deprecationsVal := reflect.ValueOf(deprecations)
	if deprecationsVal.Kind() != reflect.Slice {
		return fmt.Errorf("deprecations must be a slice")
	}

	if deprecationsVal.Len() == 0 {
		return nil
	}

	// Group deprecations by repository
	type deprecationRow struct {
		repo     string
		language string
		version  string
		file     string
	}

	repoGroups := make(map[string][]deprecationRow)

	// Collect all deprecations and group by repository
	for i := 0; i < deprecationsVal.Len(); i++ {
		deprecation := deprecationsVal.Index(i).Interface()
		deprecationVal := reflect.ValueOf(deprecation)
		if deprecationVal.Kind() != reflect.Map {
			continue
		}

		repo := ""
		language := ""
		version := ""
		file := ""

		if repoKey := deprecationVal.MapIndex(reflect.ValueOf("repository")); repoKey.IsValid() {
			repo = fmt.Sprintf("%v", repoKey.Interface())
		}
		if langKey := deprecationVal.MapIndex(reflect.ValueOf("language")); langKey.IsValid() {
			language = fmt.Sprintf("%v", langKey.Interface())
		}
		if versionKey := deprecationVal.MapIndex(reflect.ValueOf("version")); versionKey.IsValid() {
			version = fmt.Sprintf("%v", versionKey.Interface())
		}
		// Check for "file" key first (for package.json, .nvmrc, .tool-versions)
		if fileKey := deprecationVal.MapIndex(reflect.ValueOf("file")); fileKey.IsValid() {
			file = fmt.Sprintf("%v", fileKey.Interface())
		} else if imageKey := deprecationVal.MapIndex(reflect.ValueOf("image")); imageKey.IsValid() {
			// Fallback to "image" for Dockerfile entries
			file = fmt.Sprintf("%v", imageKey.Interface())
		}

		if repo != "" {
			repoGroups[repo] = append(repoGroups[repo], deprecationRow{
				repo:     repo,
				language: language,
				version:  version,
				file:     file,
			})
		}
	}

	// Sort repositories alphabetically
	repos := make([]string, 0, len(repoGroups))
	for repo := range repoGroups {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	// Create table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.Style().Options.DrawBorder = true
	t.Style().Options.SeparateColumns = true
	t.Style().Options.SeparateHeader = true

	t.AppendHeader(table.Row{"Repository", "Language", "Version", "File"})

	// Add rows grouped by repository
	for repoIdx, repo := range repos {
		deprecations := repoGroups[repo]
		for i, dep := range deprecations {
			repoCell := repo
			// Only show repository name on first row of each group
			if i > 0 {
				repoCell = ""
			}

			t.AppendRow(table.Row{
				repoCell,
				text.Colors{text.FgYellow}.Sprint(strings.ToUpper(dep.language)),
				text.Colors{text.FgRed}.Sprint(dep.version),
				dep.file,
			})
		}

		// Add separator row between repository groups (but not after the last one)
		if repoIdx < len(repos)-1 {
			t.AppendSeparator()
		}
	}

	t.Render()
	return nil
}

// printJiraSummaryTable prints a formatted table for Jira ticket summary
func printJiraSummaryTable(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return fmt.Errorf("expected map for Jira summary data")
	}

	summaryKey := val.MapIndex(reflect.ValueOf("summary"))
	if !summaryKey.IsValid() {
		return fmt.Errorf("summary key not found")
	}

	summary := summaryKey.Interface()
	summaryVal := reflect.ValueOf(summary)
	if summaryVal.Kind() != reflect.Map {
		return fmt.Errorf("summary must be a map")
	}

	// Create table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.Style().Options.DrawBorder = true
	t.Style().Options.SeparateColumns = true
	t.Style().Options.SeparateHeader = true

	// Extract fields
	getField := func(key string) string {
		if keyVal := summaryVal.MapIndex(reflect.ValueOf(key)); keyVal.IsValid() {
			return fmt.Sprintf("%v", keyVal.Interface())
		}
		return ""
	}

	// Build table rows
	t.AppendRow(table.Row{"Key", getField("key")})
	t.AppendRow(table.Row{"URL", getField("url")})
	t.AppendRow(table.Row{"Summary", getField("summary")})
	t.AppendRow(table.Row{"Status", getField("status")})
	t.AppendRow(table.Row{"Type", getField("type")})
	t.AppendRow(table.Row{"Priority", getField("priority")})

	if assignee := getField("assignee"); assignee != "" {
		t.AppendRow(table.Row{"Assignee", assignee})
	}
	if reporter := getField("reporter"); reporter != "" {
		t.AppendRow(table.Row{"Reporter", reporter})
	}
	if resolution := getField("resolution"); resolution != "" {
		t.AppendRow(table.Row{"Resolution", resolution})
	}

	t.AppendRow(table.Row{"Created", getField("created")})
	t.AppendRow(table.Row{"Updated", getField("updated")})

	if labels := getField("labels"); labels != "" && labels != "None" {
		t.AppendRow(table.Row{"Labels", labels})
	}

	// Description as a separate section
	if description := getField("description"); description != "" {
		t.AppendSeparator()
		// Wrap long descriptions for better readability
		descriptionLines := wrapText(description, 80)
		for i, line := range descriptionLines {
			if i == 0 {
				t.AppendRow(table.Row{"Description", line})
			} else {
				t.AppendRow(table.Row{"", line})
			}
		}
	}

	// Add linked resources if present
	if devTicketsVal := summaryVal.MapIndex(reflect.ValueOf("linked_dev_tickets")); devTicketsVal.IsValid() {
		devTickets := devTicketsVal.Interface()
		if tickets, ok := devTickets.([]interface{}); ok && len(tickets) > 0 {
			t.AppendSeparator()
			t.AppendRow(table.Row{"Linked Dev Tickets", ""})
			for _, ticket := range tickets {
				if tMap, ok := ticket.(map[string]interface{}); ok {
					key := fmt.Sprintf("%v", tMap["key"])
					summary := fmt.Sprintf("%v", tMap["summary"])
					t.AppendRow(table.Row{"", fmt.Sprintf("%s: %s", key, summary)})
				}
			}
		}
	}

	if prsVal := summaryVal.MapIndex(reflect.ValueOf("linked_github_prs")); prsVal.IsValid() {
		prs := prsVal.Interface()
		if prList, ok := prs.([]interface{}); ok && len(prList) > 0 {
			t.AppendSeparator()
			t.AppendRow(table.Row{"Linked GitHub PRs", ""})
			for _, pr := range prList {
				if prMap, ok := pr.(map[string]interface{}); ok {
					title := fmt.Sprintf("%v", prMap["title"])
					url := fmt.Sprintf("%v", prMap["url"])
					t.AppendRow(table.Row{"", fmt.Sprintf("%s - %s", title, url)})
				}
			}
		}
	}

	if commitsVal := summaryVal.MapIndex(reflect.ValueOf("commit_messages")); commitsVal.IsValid() {
		commits := commitsVal.Interface()
		if commitList, ok := commits.([]interface{}); ok && len(commitList) > 0 {
			t.AppendSeparator()
			t.AppendRow(table.Row{"Commit Messages", ""})
			for _, msg := range commitList {
				msgStr := fmt.Sprintf("%v", msg)
				// Truncate long commit messages
				if len(msgStr) > 100 {
					msgStr = msgStr[:100] + "..."
				}
				t.AppendRow(table.Row{"", msgStr})
			}
		}
	}

	if tagsVal := summaryVal.MapIndex(reflect.ValueOf("linked_git_tags")); tagsVal.IsValid() {
		tags := tagsVal.Interface()
		if tagList, ok := tags.([]interface{}); ok && len(tagList) > 0 {
			t.AppendSeparator()
			t.AppendRow(table.Row{"Git Tags/Releases", ""})
			for _, tag := range tagList {
				if tagMap, ok := tag.(map[string]interface{}); ok {
					tagName := fmt.Sprintf("%v", tagMap["tag"])
					url := fmt.Sprintf("%v", tagMap["url"])
					t.AppendRow(table.Row{"", fmt.Sprintf("%s - %s", tagName, url)})
				}
			}
		}
	}

	// Add Claude summaries if present
	if businessSummary := getField("business_summary"); businessSummary != "" {
		t.AppendSeparator()
		t.AppendRow(table.Row{"Business Summary", ""})
		// Split into multiple rows and wrap long lines
		lines := strings.Split(businessSummary, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				wrappedLines := wrapText(line, 80)
				for _, wrappedLine := range wrappedLines {
					t.AppendRow(table.Row{"", wrappedLine})
				}
			}
		}
	}
	if technicalSummary := getField("technical_summary"); technicalSummary != "" {
		t.AppendSeparator()
		t.AppendRow(table.Row{"Technical Summary", ""})
		// Split into multiple rows and wrap long lines
		lines := strings.Split(technicalSummary, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				wrappedLines := wrapText(line, 80)
				for _, wrappedLine := range wrappedLines {
					t.AppendRow(table.Row{"", wrappedLine})
				}
			}
		}
	}

	t.Render()
	return nil
}

// wrapText wraps text to a specified width, breaking on word boundaries
func wrapText(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}

	var lines []string
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}

	currentLine := words[0]
	for _, word := range words[1:] {
		if len(currentLine)+len(word)+1 <= width {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}

// printJiraSummaryText prints a human-readable text format for Jira ticket summary
func printJiraSummaryText(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return fmt.Errorf("expected map for Jira summary data")
	}

	summaryKey := val.MapIndex(reflect.ValueOf("summary"))
	if !summaryKey.IsValid() {
		return fmt.Errorf("summary key not found")
	}

	summary := summaryKey.Interface()
	summaryVal := reflect.ValueOf(summary)
	if summaryVal.Kind() != reflect.Map {
		return fmt.Errorf("summary must be a map")
	}

	// Extract fields
	getField := func(key string) string {
		if keyVal := summaryVal.MapIndex(reflect.ValueOf(key)); keyVal.IsValid() {
			return fmt.Sprintf("%v", keyVal.Interface())
		}
		return ""
	}

	// Print header
	fmt.Println("=" + strings.Repeat("=", 78) + "=")
	fmt.Printf("JIRA TICKET SUMMARY\n")
	fmt.Println("=" + strings.Repeat("=", 78) + "=")
	fmt.Println()

	// Basic ticket information
	fmt.Printf("Ticket:     %s\n", getField("key"))
	fmt.Printf("URL:        %s\n", getField("url"))
	fmt.Printf("Summary:    %s\n", getField("summary"))
	fmt.Printf("Status:     %s\n", getField("status"))
	fmt.Printf("Type:       %s\n", getField("type"))
	fmt.Printf("Priority:   %s\n", getField("priority"))

	if assignee := getField("assignee"); assignee != "" {
		fmt.Printf("Assignee:   %s", assignee)
		if email := getField("assignee_email"); email != "" {
			fmt.Printf(" (%s)", email)
		}
		fmt.Println()
	}

	if reporter := getField("reporter"); reporter != "" {
		fmt.Printf("Reporter:   %s", reporter)
		if email := getField("reporter_email"); email != "" {
			fmt.Printf(" (%s)", email)
		}
		fmt.Println()
	}

	if resolution := getField("resolution"); resolution != "" {
		fmt.Printf("Resolution: %s\n", resolution)
	}

	fmt.Printf("Created:    %s\n", getField("created"))
	fmt.Printf("Updated:    %s\n", getField("updated"))

	if labels := getField("labels"); labels != "" && labels != "None" {
		fmt.Printf("Labels:     %s\n", labels)
	}

	fmt.Println()

	// Description
	if description := getField("description"); description != "" {
		fmt.Println("-" + strings.Repeat("-", 78) + "-")
		fmt.Println("DESCRIPTION")
		fmt.Println("-" + strings.Repeat("-", 78) + "-")
		fmt.Println()
		wrappedLines := wrapText(description, 80)
		for _, line := range wrappedLines {
			fmt.Println(line)
		}
		fmt.Println()
	}

	// Linked Dev Tickets
	if devTicketsVal := summaryVal.MapIndex(reflect.ValueOf("linked_dev_tickets")); devTicketsVal.IsValid() {
		devTickets := devTicketsVal.Interface()
		if tickets, ok := devTickets.([]interface{}); ok && len(tickets) > 0 {
			fmt.Println("-" + strings.Repeat("-", 78) + "-")
			fmt.Println("LINKED DEV TICKETS")
			fmt.Println("-" + strings.Repeat("-", 78) + "-")
			fmt.Println()
			for _, ticket := range tickets {
				if tMap, ok := ticket.(map[string]interface{}); ok {
					key := fmt.Sprintf("%v", tMap["key"])
					summary := fmt.Sprintf("%v", tMap["summary"])
					status := fmt.Sprintf("%v", tMap["status"])
					fmt.Printf("  • %s [%s]\n", key, status)
					wrappedLines := wrapText(summary, 76)
					for _, line := range wrappedLines {
						fmt.Printf("    %s\n", line)
					}
					fmt.Println()
				}
			}
		}
	}

	// Linked GitHub PRs
	if prsVal := summaryVal.MapIndex(reflect.ValueOf("linked_github_prs")); prsVal.IsValid() {
		prs := prsVal.Interface()
		if prList, ok := prs.([]interface{}); ok && len(prList) > 0 {
			fmt.Println("-" + strings.Repeat("-", 78) + "-")
			fmt.Println("LINKED GITHUB PULL REQUESTS")
			fmt.Println("-" + strings.Repeat("-", 78) + "-")
			fmt.Println()
			for _, pr := range prList {
				if prMap, ok := pr.(map[string]interface{}); ok {
					title := fmt.Sprintf("%v", prMap["title"])
					url := fmt.Sprintf("%v", prMap["url"])
					state := fmt.Sprintf("%v", prMap["state"])
					author := fmt.Sprintf("%v", prMap["author"])
					fmt.Printf("  • %s [%s] by %s\n", title, state, author)
					fmt.Printf("    %s\n", url)
					if desc := fmt.Sprintf("%v", prMap["description"]); desc != "" && desc != "<nil>" {
						descLines := wrapText(desc, 76)
						if len(descLines) > 0 && len(descLines[0]) > 0 {
							fmt.Println()
							for _, line := range descLines[:min(3, len(descLines))] {
								fmt.Printf("    %s\n", line)
							}
							if len(descLines) > 3 {
								fmt.Printf("    ... (%d more lines)\n", len(descLines)-3)
							}
						}
					}
					fmt.Println()
				}
			}
		}
	}

	// Commit Messages
	if commitsVal := summaryVal.MapIndex(reflect.ValueOf("commit_messages")); commitsVal.IsValid() {
		commits := commitsVal.Interface()
		if commitList, ok := commits.([]interface{}); ok && len(commitList) > 0 {
			fmt.Println("-" + strings.Repeat("-", 78) + "-")
			fmt.Println("COMMIT MESSAGES")
			fmt.Println("-" + strings.Repeat("-", 78) + "-")
			fmt.Println()
			for i, msg := range commitList {
				msgStr := fmt.Sprintf("%v", msg)
				// Split multi-line commit messages
				lines := strings.Split(msgStr, "\n")
				firstLine := strings.TrimSpace(lines[0])
				if firstLine != "" {
					fmt.Printf("  %d. %s\n", i+1, firstLine)
					if len(lines) > 1 {
						for _, line := range lines[1:] {
							trimmed := strings.TrimSpace(line)
							if trimmed != "" {
								wrappedLines := wrapText(trimmed, 76)
								for _, wrappedLine := range wrappedLines {
									fmt.Printf("     %s\n", wrappedLine)
								}
							}
						}
					}
					fmt.Println()
				}
			}
		}
	}

	// Git Tags/Releases
	if tagsVal := summaryVal.MapIndex(reflect.ValueOf("linked_git_tags")); tagsVal.IsValid() {
		tags := tagsVal.Interface()
		if tagList, ok := tags.([]interface{}); ok && len(tagList) > 0 {
			fmt.Println("-" + strings.Repeat("-", 78) + "-")
			fmt.Println("GIT TAGS/RELEASES")
			fmt.Println("-" + strings.Repeat("-", 78) + "-")
			fmt.Println()
			for _, tag := range tagList {
				if tagMap, ok := tag.(map[string]interface{}); ok {
					tagName := fmt.Sprintf("%v", tagMap["tag"])
					url := fmt.Sprintf("%v", tagMap["url"])
					fmt.Printf("  • %s\n", tagName)
					fmt.Printf("    %s\n", url)
					if msg := fmt.Sprintf("%v", tagMap["message"]); msg != "" && msg != "<nil>" {
						msgLines := wrapText(msg, 76)
						if len(msgLines) > 0 && len(msgLines[0]) > 0 {
							fmt.Println()
							for _, line := range msgLines[:min(5, len(msgLines))] {
								fmt.Printf("    %s\n", line)
							}
							if len(msgLines) > 5 {
								fmt.Printf("    ... (%d more lines)\n", len(msgLines)-5)
							}
						}
					}
					fmt.Println()
				}
			}
		}
	}

	// Business Summary
	if businessSummary := getField("business_summary"); businessSummary != "" {
		fmt.Println("=" + strings.Repeat("=", 78) + "=")
		fmt.Println("BUSINESS SUMMARY")
		fmt.Println("=" + strings.Repeat("=", 78) + "=")
		fmt.Println()
		lines := strings.Split(businessSummary, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				wrappedLines := wrapText(line, 80)
				for _, wrappedLine := range wrappedLines {
					fmt.Println(wrappedLine)
				}
			} else {
				fmt.Println()
			}
		}
		fmt.Println()
	}

	// Technical Summary
	if technicalSummary := getField("technical_summary"); technicalSummary != "" {
		fmt.Println("=" + strings.Repeat("=", 78) + "=")
		fmt.Println("TECHNICAL SUMMARY")
		fmt.Println("=" + strings.Repeat("=", 78) + "=")
		fmt.Println()
		lines := strings.Split(technicalSummary, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				wrappedLines := wrapText(line, 80)
				for _, wrappedLine := range wrappedLines {
					fmt.Println(wrappedLine)
				}
			} else {
				fmt.Println()
			}
		}
		fmt.Println()
	}

	return nil
}

// printCABTicketsText prints CAB tickets grouped by team in text format
func printCABTicketsText(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return fmt.Errorf("expected map for CAB tickets data")
	}

	ticketsByTeamKey := val.MapIndex(reflect.ValueOf("tickets_by_team"))
	if !ticketsByTeamKey.IsValid() {
		return fmt.Errorf("tickets_by_team key not found")
	}

	ticketsByTeam := ticketsByTeamKey.Interface()
	ticketsMap := reflect.ValueOf(ticketsByTeam)
	if ticketsMap.Kind() != reflect.Map {
		return fmt.Errorf("tickets_by_team must be a map")
	}

	// Get all team names and sort them
	var teamNames []string
	for _, key := range ticketsMap.MapKeys() {
		teamNames = append(teamNames, key.String())
	}
	sort.Strings(teamNames)

	if len(teamNames) == 0 {
		fmt.Println("No open CAB tickets found.")
		return nil
	}

	fmt.Println("=" + strings.Repeat("=", 78) + "=")
	fmt.Println("OVERDUE CAB TICKETS BY TEAM")
	fmt.Println("=" + strings.Repeat("=", 78) + "=")
	fmt.Println()

	for _, teamName := range teamNames {
		teamTicketsVal := ticketsMap.MapIndex(reflect.ValueOf(teamName))
		if !teamTicketsVal.IsValid() {
			continue
		}

		teamTickets := teamTicketsVal.Interface()
		ticketsSlice := reflect.ValueOf(teamTickets)
		if ticketsSlice.Kind() != reflect.Slice {
			continue
		}

		fmt.Println("-" + strings.Repeat("-", 78) + "-")
		fmt.Printf("TEAM: %s (%d ticket(s))\n", teamName, ticketsSlice.Len())
		fmt.Println("-" + strings.Repeat("-", 78) + "-")
		fmt.Println()

		for i := 0; i < ticketsSlice.Len(); i++ {
			ticketVal := ticketsSlice.Index(i).Interface()
			ticketReflect := reflect.ValueOf(ticketVal)
			
			// Skip if not a struct or map
			if ticketReflect.Kind() != reflect.Struct && ticketReflect.Kind() != reflect.Map {
				continue
			}
			
			getField := func(fieldName string) string {
				if ticketReflect.Kind() == reflect.Struct {
					// Handle struct - use struct field name
					field := ticketReflect.FieldByName(fieldName)
					if field.IsValid() && field.CanInterface() {
						val := field.Interface()
						if val != nil {
							return fmt.Sprintf("%v", val)
						}
					}
				} else if ticketReflect.Kind() == reflect.Map {
					// Handle map - use key name
					keyVal := ticketReflect.MapIndex(reflect.ValueOf(fieldName))
					if keyVal.IsValid() {
						return fmt.Sprintf("%v", keyVal.Interface())
					}
					// Try lowercase version
					if len(fieldName) > 0 {
						keyLower := strings.ToLower(fieldName[:1]) + fieldName[1:]
						keyVal = ticketReflect.MapIndex(reflect.ValueOf(keyLower))
						if keyVal.IsValid() {
							return fmt.Sprintf("%v", keyVal.Interface())
						}
					}
				}
				return ""
			}

			// Use struct field names (capitalized)
			ticketKey := getField("Key")
			ticketURL := getField("URL")
			summary := getField("Summary")
			assignee := getField("Assignee")
			assigneeEmail := getField("AssigneeEmail")
			status := getField("Status")
			plannedStart := getField("PlannedStart")

			fmt.Printf("  Ticket:     %s\n", ticketKey)
			fmt.Printf("  URL:        %s\n", ticketURL)
			fmt.Printf("  Summary:    %s\n", summary)
			fmt.Printf("  Assignee:   %s", assignee)
			if assigneeEmail != "" {
				fmt.Printf(" (%s)", assigneeEmail)
			}
			fmt.Println()
			fmt.Printf("  Status:     %s\n", status)
			if plannedStart != "" {
				fmt.Printf("  Planned Start: %s\n", plannedStart)
			} else {
				fmt.Printf("  Planned Start: Not set\n")
			}
			fmt.Println()
		}
	}

	return nil
}

// printCABTicketsTable prints CAB tickets grouped by team in table format
func printCABTicketsTable(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return fmt.Errorf("expected map for CAB tickets data")
	}

	ticketsByTeamKey := val.MapIndex(reflect.ValueOf("tickets_by_team"))
	if !ticketsByTeamKey.IsValid() {
		return fmt.Errorf("tickets_by_team key not found")
	}

	ticketsByTeam := ticketsByTeamKey.Interface()
	ticketsMap := reflect.ValueOf(ticketsByTeam)
	if ticketsMap.Kind() != reflect.Map {
		return fmt.Errorf("tickets_by_team must be a map")
	}

	// Get all team names and sort them
	var teamNames []string
	for _, key := range ticketsMap.MapKeys() {
		teamNames = append(teamNames, key.String())
	}
	sort.Strings(teamNames)

	if len(teamNames) == 0 {
		fmt.Println("No open CAB tickets found.")
		return nil
	}

	for _, teamName := range teamNames {
		teamTicketsVal := ticketsMap.MapIndex(reflect.ValueOf(teamName))
		if !teamTicketsVal.IsValid() {
			continue
		}

		teamTickets := teamTicketsVal.Interface()
		ticketsSlice := reflect.ValueOf(teamTickets)
		if ticketsSlice.Kind() != reflect.Slice {
			continue
		}

		// Create table for this team
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.SetTitle(fmt.Sprintf("Team: %s (%d ticket(s))", teamName, ticketsSlice.Len()))
		t.AppendHeader(table.Row{"Ticket", "Summary", "Assignee", "Status", "Planned Start"})

		for i := 0; i < ticketsSlice.Len(); i++ {
			ticketVal := ticketsSlice.Index(i).Interface()
			ticketMap := reflect.ValueOf(ticketVal)
			if ticketMap.Kind() != reflect.Map {
				continue
			}

			getField := func(key string) string {
				if keyVal := ticketMap.MapIndex(reflect.ValueOf(key)); keyVal.IsValid() {
					return fmt.Sprintf("%v", keyVal.Interface())
				}
				return ""
			}

			ticketKey := getField("key")
			url := getField("url")
			summary := getField("summary")
			assignee := getField("assignee")
			if assignee == "" {
				assignee = "Unassigned"
			}
			status := getField("status")
			plannedStart := getField("planned_start")
			if plannedStart == "" {
				plannedStart = "Not set"
			}

			// Truncate summary if too long
			if len(summary) > 50 {
				summary = summary[:47] + "..."
			}

			// Create ticket link text
			ticketLink := fmt.Sprintf("%s\n%s", ticketKey, url)

			t.AppendRow(table.Row{ticketLink, summary, assignee, status, plannedStart})
		}

		t.SetStyle(table.StyleColoredBright)
		t.Render()
		fmt.Println()
	}

	return nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// detectSeverity detects severity from a line of text
func detectSeverity(text string) string {
	lower := strings.ToLower(text)
	if strings.Contains(lower, "critical") || strings.Contains(lower, "severe") {
		return "CRITICAL"
	}
	if strings.Contains(lower, "high") {
		return "HIGH"
	}
	if strings.Contains(lower, "low") {
		return "LOW"
	}
	return "MEDIUM"
}

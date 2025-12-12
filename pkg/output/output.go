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

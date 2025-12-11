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
	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
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

// PrintText prints data as plain text
func PrintText(data interface{}) error {
	_, err := fmt.Fprintf(os.Stdout, "%v\n", data)
	return err
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
	// Check if data is a map with "services" key
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return PrintText(data)
	}

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
	// Filter services if filter is specified (format: "column:threshold")
	if filter != "" {
		filtered := make([]aws.ECSService, 0, len(services))

		// Parse filter: "column:threshold"
		parts := strings.Split(filter, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid filter format: expected 'column:threshold' (e.g., 'count:100' or 'delta:0')")
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

	// Initialize progress bar
	pw := progress.NewWriter()
	pw.SetOutputWriter(os.Stderr)
	pw.SetStyle(progress.StyleDefault)
	pw.SetTrackerPosition(progress.PositionRight)
	pw.SetUpdateFrequency(time.Millisecond * 50)

	tracker := &progress.Tracker{
		Message: "Generating table",
		Total:   int64(len(services)),
		Units:   progress.UnitsDefault,
	}
	pw.AppendTracker(tracker)

	// Start progress bar rendering
	go pw.Render()
	defer pw.Stop()

	// Sort services if sort column is specified
	if sortColumn != "" {
		tracker.Message = "Sorting services"
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
			default:
				return false // Unknown column, don't sort
			}
			if sortDescending {
				return !less
			}
			return less
		})
	}

	tracker.Message = "Building table rows"
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Count", "Delta"})

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

		t.AppendRow(table.Row{
			svc.Name,
			text.Colors{countColor}.Sprint(countStr),
			text.Colors{deltaColor}.Sprint(deltaStr),
		})
		tracker.Increment(1)
	}

	tracker.MarkAsDone()
	time.Sleep(100 * time.Millisecond) // Give progress bar time to update

	t.Render()
	return nil
}

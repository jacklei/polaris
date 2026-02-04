package output

import (
	"testing"

	"github.com/jacklei/polaris/pkg/aws"
)

func TestPrintJSON(t *testing.T) {
	data := map[string]interface{}{
		"test": "value",
		"num":  42,
	}

	err := PrintJSON(data)
	if err != nil {
		t.Errorf("PrintJSON() error = %v", err)
	}
}

func TestPrintText(t *testing.T) {
	data := map[string]interface{}{
		"test": "value",
	}

	err := PrintText(data)
	if err != nil {
		t.Errorf("PrintText() error = %v", err)
	}
}

func TestPrintTable_FilterCVE(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1", CVECriticalCount: 5},
		{Name: "service2", CVECriticalCount: 0},
		{Name: "service3", CVECriticalCount: 10},
	}

	data := map[string]interface{}{
		"services": services,
	}

	// Test CVE filter - should only show services with CVEs
	err := PrintTable(data, "", false, "cve")
	if err != nil {
		t.Errorf("PrintTable() with CVE filter error = %v", err)
	}
}

func TestPrintTable_FilterCount(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1", DesiredCount: 5},
		{Name: "service2", DesiredCount: 10},
		{Name: "service3", DesiredCount: 15},
	}

	data := map[string]interface{}{
		"services": services,
	}

	// Test count filter - should only show services with count < 10
	err := PrintTable(data, "", false, "count:10")
	if err != nil {
		t.Errorf("PrintTable() with count filter error = %v", err)
	}
}

func TestPrintTable_FilterDelta(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1", DesiredCount: 10, RunningCount: 5},  // delta: -5
		{Name: "service2", DesiredCount: 10, RunningCount: 10}, // delta: 0
		{Name: "service3", DesiredCount: 10, RunningCount: 15}, // delta: +5
	}

	data := map[string]interface{}{
		"services": services,
	}

	// Test delta filter - should only show services with delta < 0
	err := PrintTable(data, "", false, "delta:0")
	if err != nil {
		t.Errorf("PrintTable() with delta filter error = %v", err)
	}
}

func TestPrintTable_FilterRunning(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1", RunningCount: 5},
		{Name: "service2", RunningCount: 10},
		{Name: "service3", RunningCount: 15},
	}

	data := map[string]interface{}{
		"services": services,
	}

	// Test running filter - should only show services with running < 10
	err := PrintTable(data, "", false, "running:10")
	if err != nil {
		t.Errorf("PrintTable() with running filter error = %v", err)
	}
}

func TestPrintTable_FilterInvalidFormat(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1"},
	}

	data := map[string]interface{}{
		"services": services,
	}

	// Test invalid filter format
	err := PrintTable(data, "", false, "invalid")
	if err == nil {
		t.Error("PrintTable() with invalid filter format should return error")
	}
}

func TestPrintTable_FilterInvalidThreshold(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1"},
	}

	data := map[string]interface{}{
		"services": services,
	}

	// Test invalid threshold
	err := PrintTable(data, "", false, "count:invalid")
	if err == nil {
		t.Error("PrintTable() with invalid threshold should return error")
	}
}

func TestPrintTable_SortByName(t *testing.T) {
	services := []aws.ECSService{
		{Name: "zebra"},
		{Name: "alpha"},
		{Name: "beta"},
	}

	data := map[string]interface{}{
		"services": services,
	}

	err := PrintTable(data, "name", false, "")
	if err != nil {
		t.Errorf("PrintTable() with name sort error = %v", err)
	}
}

func TestPrintTable_SortByNameDescending(t *testing.T) {
	services := []aws.ECSService{
		{Name: "alpha"},
		{Name: "zebra"},
		{Name: "beta"},
	}

	data := map[string]interface{}{
		"services": services,
	}

	err := PrintTable(data, "name", true, "")
	if err != nil {
		t.Errorf("PrintTable() with name sort descending error = %v", err)
	}
}

func TestPrintTable_SortByCount(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1", DesiredCount: 10, RunningCount: 5},
		{Name: "service2", DesiredCount: 5, RunningCount: 5},
		{Name: "service3", DesiredCount: 15, RunningCount: 10},
	}

	data := map[string]interface{}{
		"services": services,
	}

	err := PrintTable(data, "count", false, "")
	if err != nil {
		t.Errorf("PrintTable() with count sort error = %v", err)
	}
}

func TestPrintTable_SortByDelta(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1", DesiredCount: 10, RunningCount: 5},  // delta: -5
		{Name: "service2", DesiredCount: 10, RunningCount: 15}, // delta: +5
		{Name: "service3", DesiredCount: 10, RunningCount: 10}, // delta: 0
	}

	data := map[string]interface{}{
		"services": services,
	}

	err := PrintTable(data, "delta", false, "")
	if err != nil {
		t.Errorf("PrintTable() with delta sort error = %v", err)
	}
}

func TestPrintTable_SortByCVE(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1", CVECriticalCount: 10},
		{Name: "service2", CVECriticalCount: 5},
		{Name: "service3", CVECriticalCount: 15},
	}

	data := map[string]interface{}{
		"services": services,
	}

	err := PrintTable(data, "cve", false, "")
	if err != nil {
		t.Errorf("PrintTable() with CVE sort error = %v", err)
	}
}

func TestPrintTable_InvalidSortColumn(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1"},
	}

	data := map[string]interface{}{
		"services": services,
	}

	// Invalid sort column should not cause error, just not sort
	err := PrintTable(data, "invalid", false, "")
	if err != nil {
		t.Errorf("PrintTable() with invalid sort column should not error, got: %v", err)
	}
}

func TestPrintTable_NoServices(t *testing.T) {
	data := map[string]interface{}{
		"services": []aws.ECSService{},
	}

	err := PrintTable(data, "", false, "")
	if err != nil {
		t.Errorf("PrintTable() with no services error = %v", err)
	}
}

func TestPrintTable_WithCVEData(t *testing.T) {
	services := []aws.ECSService{
		{Name: "service1", CVECriticalCount: 5},
		{Name: "service2", CVECriticalCount: 0},
	}

	data := map[string]interface{}{
		"services": services,
	}

	err := PrintTable(data, "", false, "")
	if err != nil {
		t.Errorf("PrintTable() with CVE data error = %v", err)
	}
}

func TestPrintTable_InvalidData(t *testing.T) {
	// Test with non-map data
	err := PrintTable("not a map", "", false, "")
	if err != nil {
		t.Errorf("PrintTable() with invalid data should handle gracefully, got: %v", err)
	}

	// Test with map without services key
	data := map[string]interface{}{
		"not_services": []aws.ECSService{},
	}
	err = PrintTable(data, "", false, "")
	if err != nil {
		t.Errorf("PrintTable() with map without services should handle gracefully, got: %v", err)
	}
}

func TestPrint(t *testing.T) {
	data := map[string]interface{}{
		"test": "value",
	}

	// Test JSON output
	err := Print(data, "json", "", false, "")
	if err != nil {
		t.Errorf("Print() with json output error = %v", err)
	}

	// Test table output
	servicesData := map[string]interface{}{
		"services": []aws.ECSService{{Name: "test"}},
	}
	err = Print(servicesData, "table", "", false, "")
	if err != nil {
		t.Errorf("Print() with table output error = %v", err)
	}

	// Test text output (default)
	err = Print(data, "text", "", false, "")
	if err != nil {
		t.Errorf("Print() with text output error = %v", err)
	}
}

func TestPrintText_ECRScanMultiple(t *testing.T) {
	// Test PrintText with multiple ECR scans
	data := map[string]interface{}{
		"repository": "my-repo",
		"scans": []map[string]interface{}{
			{
				"repository": "my-repo",
				"tag":        "v1.0.0",
				"pushed_at":  "2024-01-01T00:00:00Z",
				"cve_count":  0,
			},
			{
				"repository": "my-repo",
				"tag":        "v2.0.0",
				"pushed_at":  "2024-01-02T00:00:00Z",
				"cve_count":  5,
			},
		},
	}

	err := PrintText(data)
	if err != nil {
		t.Errorf("PrintText() with multiple ECR scans error = %v", err)
	}
}

func TestPrintText_ECRScanSingle(t *testing.T) {
	// Test PrintText with single ECR scan
	data := map[string]interface{}{
		"repository": "my-repo",
		"tag":        "v1.0.0",
		"pushed_at":  "2024-01-01T00:00:00Z",
		"cve_count":  10,
	}

	err := PrintText(data)
	if err != nil {
		t.Errorf("PrintText() with single ECR scan error = %v", err)
	}
}

func TestPrintText_ECRScanWithZeroCVEs(t *testing.T) {
	// Test PrintText with zero CVEs
	data := map[string]interface{}{
		"repository": "my-repo",
		"tag":        "v1.0.0",
		"pushed_at":  "2024-01-01T00:00:00Z",
		"cve_count":  0,
	}

	err := PrintText(data)
	if err != nil {
		t.Errorf("PrintText() with zero CVEs error = %v", err)
	}
}

func TestPrintText_ECRScanWithInvalidCVECount(t *testing.T) {
	// Test PrintText with invalid CVE count (non-numeric)
	data := map[string]interface{}{
		"repository": "my-repo",
		"tag":        "v1.0.0",
		"pushed_at":  "2024-01-01T00:00:00Z",
		"cve_count":  "invalid",
	}

	err := PrintText(data)
	if err != nil {
		t.Errorf("PrintText() with invalid CVE count should handle gracefully, got: %v", err)
	}
}

func TestPrintText_NonMapData(t *testing.T) {
	// Test PrintText with non-map data
	err := PrintText("not a map")
	if err != nil {
		t.Errorf("PrintText() with non-map data error = %v", err)
	}
}

func TestPrintf(t *testing.T) {
	err := Printf("Test %s %d", "text", 42)
	if err != nil {
		t.Errorf("Printf() error = %v", err)
	}
}

func TestPrintln(t *testing.T) {
	err := Println("text", "arg1", "arg2", 42)
	if err != nil {
		t.Errorf("Println() error = %v", err)
	}
}

func TestPrintTable_ECRScanSingle(t *testing.T) {
	// Test PrintTable with single ECR scan
	data := map[string]interface{}{
		"repository": "my-repo",
		"tag":        "v1.0.0",
		"pushed_at":  "2024-01-01T00:00:00Z",
		"cve_count":  5,
	}

	err := PrintTable(data, "", false, "")
	if err != nil {
		t.Errorf("PrintTable() with single ECR scan error = %v", err)
	}
}

func TestPrintTable_ECRScanMultiple(t *testing.T) {
	// Test PrintTable with multiple ECR scans
	data := map[string]interface{}{
		"repository": "my-repo",
		"scans": []map[string]interface{}{
			{
				"repository": "my-repo",
				"tag":        "v1.0.0",
				"pushed_at":  "2024-01-01T00:00:00Z",
				"cve_count":  0,
			},
			{
				"repository": "my-repo",
				"tag":        "v2.0.0",
				"pushed_at":  "2024-01-02T00:00:00Z",
				"cve_count":  5,
			},
		},
	}

	err := PrintTable(data, "", false, "")
	if err != nil {
		t.Errorf("PrintTable() with multiple ECR scans error = %v", err)
	}
}


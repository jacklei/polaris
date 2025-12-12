# Polaris

Polaris guides your repositories and platform toward correct posture. It helps ensure best practices and compliance by providing insights into your AWS infrastructure, particularly ECS services and container security.

## Features

- **ECS Service Management**: Query and monitor active ECS services with detailed metrics
- **Container Security Scanning**: Scan ECR images for critical CVEs using AWS Inspector v2
- **Flexible Output Formats**: Support for text, JSON, and table output formats
- **Structured Logging**: Configurable logging levels with Zerolog
- **AWS Profile Support**: Seamless integration with AWS profiles and credentials

## Installation

### Prerequisites

- Go 1.25.1 or later
- **For AWS commands only**: AWS credentials configured (via `~/.aws/config` and `~/.aws/credentials`)

### Build from Source

```bash
git clone https://github.com/jacklei/polaris.git
cd polaris
go build -o polaris
```

## Usage

### Global Flags

- `-l, --log-level`: Set the logging level (trace, debug, info, warn, error, fatal, panic) (default: "info")
- `-o, --output`: Set the output format (text, json, table) (default: "text")

### AWS Commands

#### Get Active ECS Services

Retrieve active ECS services from a specified cluster with optional filtering, sorting, and CVE scanning.

```bash
polaris aws get-active-services [flags]
```

**Flags:**
- `-p, --profile`: AWS profile to use (default: "default")
- `-c, --cluster`: ECS cluster name (default: "ozark")
- `-n, --limit`: Limit the number of services to query (0 = no limit)
- `--sort`: Sort by column (name, count, delta, cve)
- `--desc`: Sort in descending order
- `--filter`: Filter by column and threshold (e.g., 'count:100', 'delta:0') or 'cve' to show only services with critical CVEs
- `--scan`: Enable container scanning to retrieve CVE critical counts
- `--scan-profile`: AWS profile to use for ECR scanning (default: "acorns-production")

**Examples:**

```bash
# List all active services in the ozark cluster
polaris aws get-active-services

# List services with table output, sorted by name
polaris aws get-active-services -o table --sort name

# Show only services with critical CVEs
polaris aws get-active-services --scan --filter cve

# Limit to 10 services and sort by delta descending
polaris aws get-active-services -n 10 --sort delta --desc

# Filter services with count less than 5
polaris aws get-active-services --filter count:5
```

**Output Columns:**
- **Name**: Service name
- **Image**: Container image name (without ECR host)
- **Version**: Image tag/version
- **Pushed At**: When the image was pushed to ECR
- **CVE Critical**: Number of critical CVEs (if scanning enabled)
- **Count**: Desired count (or desired/running/pending if different)
- **Delta**: Difference between running and desired count with percentage

#### Scan ECR Images for CVEs

Scan ECR images for critical CVEs using AWS Inspector v2.

```bash
polaris aws get-ecr-scan <repository[:tag]> [flags]
```

**Flags:**
- `-p, --profile`: AWS profile to use for ECR scanning (default: "acorns-production")
- `-o, --output`: Output format (text, json, table)

**Examples:**

```bash
# Scan a specific image tag
polaris aws get-ecr-scan my-repo:v1.0.0

# Scan latest 10 tags (if no tag specified)
polaris aws get-ecr-scan my-repo

# Scan with table output
polaris aws get-ecr-scan my-repo:v1.0.0 -o table

# Scan with JSON output
polaris aws get-ecr-scan my-repo:v1.0.0 -o json

# Scan with full ECR path
polaris aws get-ecr-scan 255479557906.dkr.ecr.us-east-1.amazonaws.com/my-repo:v1.0.0
```

**Exit Codes:**
- `0`: No critical CVEs found
- `1`: Critical CVEs found or error occurred

**Output:**
- Text output uses structured logging (zerolog) - errors are logged if CVEs are found
- Table output shows: Repository, Tag, Pushed At, CVE Critical Count
- Results are sorted by push date (newest first) when scanning multiple tags

## Configuration

### AWS Credentials (for AWS commands only)

AWS commands require AWS credentials. Polaris uses the AWS SDK's default credential chain, which checks:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. Shared config file (`~/.aws/config`)
4. EC2 instance profile (if running on EC2)

### Logging

Logging levels can be set via the `--log-level` flag:
- `trace`: Most verbose
- `debug`: Debug information
- `info`: Informational messages (default)
- `warn`: Warning messages
- `error`: Error messages only
- `fatal`: Fatal errors only
- `panic`: Panic level

### Output Formats

- **text**: Plain text output (uses structured logging for ECR scans)
- **json**: JSON formatted output
- **table**: Formatted table with colors and styling

## Development

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# View coverage in HTML
go tool cover -html=coverage.out
```

### Project Structure

```
polaris/
├── cmd/                    # CLI commands
│   ├── root.go            # Root command and global flags
│   ├── aws.go             # AWS command group
│   ├── aws_get_active_services.go  # ECS services command
│   └── aws_get_ecr_scan.go        # ECR scan command
├── pkg/
│   ├── aws/               # AWS SDK integration
│   │   ├── config.go      # AWS configuration loading
│   │   ├── ecs.go         # ECS service operations
│   │   └── ecr.go         # ECR and Inspector2 operations
│   ├── logger/            # Logging utilities
│   └── output/            # Output formatting
└── main.go                # Entry point
```

### Code Coverage

Current test coverage: **67.3%**

- `pkg/logger`: 100%
- `pkg/output`: 86.7%
- `pkg/aws`: 40.5%
- `cmd`: 30.1%

## Examples

### Monitor ECS Services

```bash
# Get all active services with CVE scanning
polaris aws get-active-services --scan -o table

# Filter services with issues (delta < 0 or CVEs)
polaris aws get-active-services --scan --filter delta:0 -o table
polaris aws get-active-services --scan --filter cve -o table
```

### Security Scanning

```bash
# Scan latest tags for a repository
polaris aws get-ecr-scan my-application -o table

# Check specific version
polaris aws get-ecr-scan my-application:v2.1.0 -o table

# Use in CI/CD pipeline (exit code indicates CVE status)
if ! polaris aws get-ecr-scan my-app:latest; then
  echo "Critical CVEs found!"
  exit 1
fi
```

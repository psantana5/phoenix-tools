# Phoenix Tools Security Scanner

A comprehensive security scanning tool for Linux systems that helps identify vulnerabilities, misconfigurations, and security risks.

## Features

- **Multiple Security Checks**: CIS benchmarks, vulnerability detection, SSH configuration analysis, firewall rules, and privilege escalation checks  
- **Severity Classification**: Findings categorized by CRITICAL, HIGH, MEDIUM, LOW, and INFO severity levels  
- **Detailed Remediation**: Clear instructions for fixing identified security issues  
- **API Integration**: RESTful API for integration with other security tools and pipelines  
- **Scan Management**: Create, list, retrieve, and delete security scans  
- **Filtering Capabilities**: Filter findings by severity, status, and check type  
- **Multi-Distribution Support**: Works with Debian, RedHat, SUSE, and Arch-based Linux distributions  

## Installation

### Prerequisites

- Go 1.16 or later  
- SSH client (for remote scanning)  
- Access to target Linux systems  

### From Source

```bash
# Clone the repository
git clone https://github.com/psantana5/phoenix-tools.git
cd phoenix-tools

# Build the binary
go build -o phoenix.exe ./cmd/phoenix

# For Linux build
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0
go build -o phoenix -ldflags="-s -w" ./cmd/phoenix
```

### Using Go Install

```bash
go install github.com/psantana5/phoenix-tools/cmd/phoenix
```

## Usage

### Basic Scanning

```bash
# Scan a remote Linux system
phoenix scan target your-linux-server --checks CIS,Vulnerability,SSH,Firewall,Privileges

# Scan with specific credentials
phoenix scan target your-linux-server --user admin --key /path/to/key.pem
```

### Report Generation

```bash
# Generate a report from scan results
phoenix report --format html --output-dir ./reports

# Generate a report for a specific target
phoenix report --target server1.example.com
```

### Configuration Management

```bash
# View current configuration
phoenix config view

# Set a configuration value
phoenix config set scan.parallel 5

# Reset configuration to defaults
phoenix config reset
```

### API Server

```bash
# Start the API server
phoenix api serve --port 8080

# Access the API documentation
open http://localhost:8080/docs
```

### API Client

```bash
# Check API server health
phoenix client health

# List all scans
phoenix client scans list

# Create a new scan
phoenix client scans create target-server --checks CIS,SSH,Firewall

# Get findings for a specific scan
phoenix client findings get scan-id-123
```

## Configuration

Phoenix uses a configuration file located at `%USERPROFILE%\.phoenix.yaml` by default. You can specify a different configuration file using the `--config` flag.

Example configuration:

```yaml
# API server configuration
api:
  port: 8080
  host: 0.0.0.0
  auth:
    enabled: true

# Scanning configuration
scan:
  parallel: 10
  timeout: 300
  checks:
    - CIS
    - Vulnerability
    - SSH
    - Firewall
    - Privileges

# Output configuration
output:
  format: json
  directory: ./reports
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository  
2. Create your feature branch (`git checkout -b feature/amazing-feature`)  
3. Commit your changes (`git commit -m 'Add some amazing feature'`)  
4. Push to the branch (`git push origin feature/amazing-feature`)  
5. Open a Pull Request  

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Center for Internet Security (CIS) for benchmark definitions  
- The Go community for excellent libraries and tools  

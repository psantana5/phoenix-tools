# Phoenix - Enterprise Linux Auditing Tool

Phoenix is a comprehensive, enterprise-grade tool designed to automate security and compliance auditing across multiple Linux distributions. It provides a robust framework for scanning systems against industry benchmarks, detecting vulnerabilities, and ensuring compliance with security best practices.

## Features

- **Multi-Distribution Support**: Works across various Linux distributions
- **Comprehensive Checks**: Includes CIS benchmarks, firewall, privileges, vulnerability, permissions, and SSH checks
- **Parallel Scanning**: Scan multiple systems simultaneously
- **Flexible Output**: Generate reports in multiple formats (JSON, XML, HTML, text)
- **Remote Scanning**: Connect to remote systems via SSH
- **Network Range Scanning**: Scan entire CIDR ranges
- **API Support**: Programmatic access to scanning functionality

## Installation

### Prerequisites

- Go 1.16 or later
- SSH client (for remote scanning)
- Access to target Linux systems

### From Source

```bash
# Clone the repository
git clone https://github.com/psantana5/phoenix-tools.git
cd phoenix

# Build the binary
go build -o phoenix ./cmd/phoenix

# Install to your PATH (optional)
sudo mv phoenix /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/psantana5/phoenix-tools/cmd/phoenix@latest
```

## Configuration

Phoenix uses a configuration file located at `$HOME/.phoenix.yaml` by default. You can specify a different configuration file using the `--config` flag.

### Sample Configuration

```yaml
# Phoenix Configuration File
scan:
  parallel: 10  # Number of parallel scans
  timeout: 300  # Scan timeout in seconds
  distributions:  # Limit scan to specific distributions
    - ubuntu
    - centos
    - rhel
  ssh:
    user: root
    key_file: ~/.ssh/id_rsa
    port: 22
  checks:
    cis: true
    firewall: true
    privileges: true
    vulnerability: true
    permissions: true
    ssh: true
output_format: text  # Default output format (json, xml, html, text)
```

## Usage

### Basic Scanning

```bash
# Scan the local system
phoenix scan localhost

# Scan a remote system
phoenix scan server1.example.com

# Scan multiple systems
phoenix scan server1.example.com server2.example.com

# Scan a network range
phoenix scan 192.168.1.0/24
```

### Advanced Options

```bash
# Specify checks to run
phoenix scan --checks cis,ssh,firewall server1.example.com

# Output results to a file in JSON format
phoenix scan --output-format json --output-file results.json server1.example.com

# Specify SSH credentials
phoenix scan --ssh-user admin --ssh-key ~/.ssh/custom_key server1.example.com

# Limit to specific distributions
phoenix scan --distributions ubuntu,centos server1.example.com

# Set parallel scan limit
phoenix scan --parallel 5 192.168.1.0/24
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

### Report Generation

```bash
# Generate a report from previous scan results
phoenix report generate --input results.json --format html --output report.html

# Compare two scan results
phoenix report compare --baseline baseline.json --current current.json --output diff.html
```

### API Server

```bash
# Start the API server
phoenix api serve --port 8080

# Access the API documentation
open http://localhost:8080/docs
```

## Security Checks

Phoenix includes several types of security checks:

- **CIS Benchmarks**: Center for Internet Security compliance checks
- **Firewall**: Firewall configuration and rule analysis
- **Privileges**: User and group privilege assessment
- **Vulnerability**: Known vulnerability detection
- **Permissions**: File and directory permission analysis
- **SSH**: SSH configuration security assessment

## Extending Phoenix

You can extend Phoenix with custom checks by implementing the `Check` interface in the `checks` package:

```go
type Check interface {
    // Name returns the name of the check
    Name() string

    // Description returns the description of the check
    Description() string

    // Run executes the check against the target
    Run(ctx context.Context, connection ssh.Connection, distroInfo distro.Info) ([]Finding, error)
}
```

## Architecture

Phoenix is built with a modular architecture:

- **CLI**: Command-line interface for user interaction
- **Scanner**: Core scanning engine
- **Checks**: Individual security checks
- **SSH**: Remote system connection handling
- **Reporting**: Result formatting and output
- **API**: RESTful API for programmatic access

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Center for Internet Security (CIS) for benchmark definitions
- The Go community for excellent libraries and tools
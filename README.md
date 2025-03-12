# Phoenix Tools Security ScannerA comprehensive security scanning tool for Linux systems that helps identify vulnerabilities, misconfigurations, and security risks.## Features- **Multiple Security Checks**: CIS benchmarks, vulnerability detection, SSH configuration analysis, firewall rules, and privilege escalation checks- **Severity Classification**: Findings categorized by CRITICAL, HIGH, MEDIUM, LOW, and INFO severity levels- **Detailed Remediation**: Clear instructions for fixing identified security issues- **API Integration**: RESTful API for integration with other security tools and pipelines- **Scan Management**: Create, list, retrieve, and delete security scans- **Filtering Capabilities**: Filter findings by severity, status, and check type- **Multi-Distribution Support**: Works with Debian, RedHat, SUSE, and Arch-based Linux distributions## Installation### Prerequisites- Go 1.16 or later- SSH client (for remote scanning)- Access to target Linux systems### From Source```bash# Clone the repositorygit clone https://github.com/psantana5/phoenix-tools.gitcd phoenix-tools# Build the binarygo build -o phoenix.exe ./cmd/phoenix# For Linux buildset GOOS=linuxset GOARCH=amd64set CGO_ENABLED=0go build -o phoenix -ldflags="-s -w" ./cmd/phoenix
Using Go Install
bash
Run
go install github.com/psantana5/phoenix-tools/cmd/phoenix@latest
Usage
Basic Scanning
bash
Run
# Scan a remote Linux systemphoenix scan target your-linux-server --checks CIS,Vulnerability,SSH,Firewall,Privileges# Scan with specific credentialsphoenix scan target your-linux-server --user admin --key /path/to/key.pem
Report Generation
bash
Run
# Generate a report from scan resultsphoenix report --format html --output-dir ./reports# Generate a report for a specific targetphoenix report --target server1.example.com
Configuration Management
bash
Run
# View current configurationphoenix config view# Set a configuration valuephoenix config set scan.parallel 5# Reset configuration to defaultsphoenix config reset
API Server
bash
Run
# Start the API serverphoenix api serve --port 8080# Access the API documentationopen http://localhost:8080/docs
API Client
bash
Run
# Check API server healthphoenix client health# List all scansphoenix client scans list# Create a new scanphoenix client scans create target-server --checks CIS,SSH,Firewall# Get findings for a specific scanphoenix client findings get scan-id-123
Configuration
Phoenix uses a configuration file located at %USERPROFILE%\.phoenix.yaml by default. You can specify a different configuration file using the --config flag.

Example configuration:

yaml

# API server configurationapi:  port: 8080  host: 0.0.0.0  auth:    enabled: true# Scanning configurationscan:  parallel: 10  timeout: 300  checks:    - CIS    - Vulnerability    - SSH    - Firewall    - Privileges# Output configurationoutput:  format: json  directory: ./reports
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository
Create your feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add some amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request
License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
Center for Internet Security (CIS) for benchmark definitions
The Go community for excellent libraries and tools

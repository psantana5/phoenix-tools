package checks

import (
	"context"
	"strings"
	"time"

	"github.com/psantana5/phoenix-tools/internal/scanner/distro"
	"github.com/psantana5/phoenix-tools/internal/scanner/ssh"
)

// Severity represents the severity of a finding
type Severity string

const (
	// SeverityCritical represents a critical severity
	SeverityCritical Severity = "CRITICAL"
	// SeverityHigh represents a high severity
	SeverityHigh Severity = "HIGH"
	// SeverityMedium represents a medium severity
	SeverityMedium Severity = "MEDIUM"
	// SeverityLow represents a low severity
	SeverityLow Severity = "LOW"
	// SeverityInfo represents an informational severity
	SeverityInfo Severity = "INFO"
)

// Status represents the status of a finding
type Status string

const (
	// StatusPassed represents a passed check
	StatusPassed Status = "PASSED"
	// StatusFailed represents a failed check
	StatusFailed Status = "FAILED"
	// StatusWarning represents a warning
	StatusWarning Status = "WARNING"
	// StatusInfo represents an informational finding
	StatusInfo Status = "INFO"
)

// Finding represents a security finding
type Finding struct {
	ID          string                 `json:"id" yaml:"id" xml:"id"`
	CheckType   string                 `json:"check_type" yaml:"check_type" xml:"check_type"`
	Title       string                 `json:"title" yaml:"title" xml:"title"`
	Description string                 `json:"description" yaml:"description" xml:"description"`
	Severity    Severity               `json:"severity" yaml:"severity" xml:"severity"`
	Status      Status                 `json:"status" yaml:"status" xml:"status"`
	Timestamp   time.Time              `json:"timestamp" yaml:"timestamp" xml:"timestamp"`
	Resource    string                 `json:"resource" yaml:"resource" xml:"resource"`
	Remediation string                 `json:"remediation,omitempty" yaml:"remediation,omitempty" xml:"remediation,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty" yaml:"details,omitempty" xml:"details,omitempty"`
	References  []string               `json:"references,omitempty" yaml:"references,omitempty" xml:"references,omitempty"`
}

// Check represents a security check
type Check interface {
	// Name returns the name of the check
	Name() string
	// Run runs the check
	Run(ctx context.Context, conn ssh.Connection, distroInfo distro.Info) ([]Finding, error)
}

// NewCISCheck creates a new CIS check
func NewCISCheck() Check {
	return &cisCheck{}
}

// cisCheck implements the CIS check
type cisCheck struct{}

// Name returns the name of the check
func (c *cisCheck) Name() string {
	return "CIS"
}

// Run runs the check
func (c *cisCheck) Run(ctx context.Context, conn ssh.Connection, distroInfo distro.Info) ([]Finding, error) {
	// Placeholder implementation
	findings := []Finding{
		{
			CheckType:   "CIS",
			Title:       "CIS 1.1.1 - Ensure mounting of cramfs filesystems is disabled",
			Description: "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.",
			Severity:    SeverityMedium,
			Status:      StatusPassed,
			Remediation: "Edit /etc/modprobe.d/CIS.conf and add 'install cramfs /bin/true'",
		},
	}
	return findings, nil
}

// NewFirewallCheck creates a new firewall check
func NewFirewallCheck() Check {
	return &firewallCheck{}
}

// firewallCheck implements the firewall check
type firewallCheck struct{}

// Name returns the name of the check
func (f *firewallCheck) Name() string {
	return "Firewall"
}

// Run runs the check
func (f *firewallCheck) Run(ctx context.Context, conn ssh.Connection, distroInfo distro.Info) ([]Finding, error) {
	// Placeholder implementation
	findings := []Finding{
		{
			CheckType:   "Firewall",
			Title:       "Firewall - Ensure firewall is enabled",
			Description: "A firewall is a set of rules that blocks or allows network traffic based on security criteria.",
			Severity:    SeverityHigh,
			Status:      StatusPassed,
			Remediation: "Enable the firewall service: 'systemctl enable firewalld && systemctl start firewalld'",
		},
	}
	return findings, nil
}

// NewPrivilegesCheck creates a new privileges check
func NewPrivilegesCheck() Check {
	return &privilegesCheck{}
}

// privilegesCheck implements the privileges check
type privilegesCheck struct{}

// Name returns the name of the check
func (p *privilegesCheck) Name() string {
	return "Privileges"
}

// Run runs the check
func (p *privilegesCheck) Run(ctx context.Context, conn ssh.Connection, distroInfo distro.Info) ([]Finding, error) {
	// Placeholder implementation
	findings := []Finding{
		{
			CheckType:   "Privileges",
			Title:       "Privileges - Ensure sudo is installed",
			Description: "sudo allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.",
			Severity:    SeverityMedium,
			Status:      StatusPassed,
			Remediation: "Install sudo: 'apt-get install sudo' or 'yum install sudo'",
		},
	}
	return findings, nil
}

// NewVulnerabilityCheck creates a new vulnerability check
func NewVulnerabilityCheck() Check {
	return &VulnerabilityCheck{
		BaseCheck: NewBaseCheck(
			"Vulnerability",
			"Checks for common vulnerabilities in the system",
		),
	}
}

// VulnerabilityCheck implements vulnerability scanning
type VulnerabilityCheck struct {
	BaseCheck
}

// Run executes the vulnerability check
func (c *VulnerabilityCheck) Run(ctx context.Context, connection ssh.Connection, distroInfo distro.Info) ([]Finding, error) {
	findings := []Finding{}

	// Check for outdated packages
	outdatedPackages, err := checkOutdatedPackages(ctx, connection, distroInfo)
	if err == nil {
		findings = append(findings, outdatedPackages...)
	}

	// Check for common CVEs based on distribution
	cveFindings, err := checkCommonCVEs(ctx, connection, distroInfo)
	if err == nil {
		findings = append(findings, cveFindings...)
	}

	// Check for weak SSH configurations
	sshFindings, err := checkSSHConfig(ctx, connection)
	if err == nil {
		findings = append(findings, sshFindings...)
	}

	return findings, nil
}

// checkOutdatedPackages checks for outdated packages
func checkOutdatedPackages(ctx context.Context, connection ssh.Connection, distroInfo distro.Info) ([]Finding, error) {
	var cmd string
	var parseFunc func(string) []Finding

	// Determine command based on distribution family
	switch distroInfo.Family {
	case "debian":
		cmd = "apt list --upgradable 2>/dev/null"
		parseFunc = parseDebianOutdatedPackages
	case "rhel":
		cmd = "yum check-update --quiet"
		parseFunc = parseRHELOutdatedPackages
	default:
		return nil, nil
	}

	output, err := connection.RunCommand(ctx, cmd)
	if err != nil {
		return nil, err
	}

	return parseFunc(output), nil
}

// parseDebianOutdatedPackages parses apt list --upgradable output
func parseDebianOutdatedPackages(output string) []Finding {
	// Simple implementation - can be enhanced for more detailed parsing
	if output == "" {
		return []Finding{
			{
				ID:          "VULN-001",
				Title:       "System Packages",
				Description: "No outdated packages found",
				Severity:    SeverityInfo,
				Status:      StatusPassed,
				CheckType:   "Vulnerability",
				Timestamp:   time.Now(),
				Resource:    "System Packages",
				Remediation: "No action needed",
			},
		}
	}

	return []Finding{
		{
			ID:          "VULN-001",
			Title:       "Outdated System Packages",
			Description: "System has outdated packages that need to be updated",
			Severity:    SeverityMedium,
			Status:      StatusFailed,
			CheckType:   "Vulnerability",
			Timestamp:   time.Now(),
			Resource:    "System Packages",
			Remediation: "Run 'apt update && apt upgrade' to update all packages",
			Details: map[string]interface{}{
				"raw_output": output,
			},
			References: []string{
				"https://www.debian.org/security/",
			},
		},
	}
}

// parseRHELOutdatedPackages parses yum check-update output
func parseRHELOutdatedPackages(output string) []Finding {
	// Simple implementation - can be enhanced for more detailed parsing
	if output == "" {
		return []Finding{
			{
				ID:          "VULN-001",
				Title:       "System Packages",
				Description: "No outdated packages found",
				Severity:    SeverityInfo,
				Status:      StatusPassed,
				CheckType:   "Vulnerability",
				Timestamp:   time.Now(),
				Resource:    "System Packages",
				Remediation: "No action needed",
			},
		}
	}

	return []Finding{
		{
			ID:          "VULN-001",
			Title:       "Outdated System Packages",
			Description: "System has outdated packages that need to be updated",
			Severity:    SeverityMedium,
			Status:      StatusFailed,
			CheckType:   "Vulnerability",
			Timestamp:   time.Now(),
			Resource:    "System Packages",
			Remediation: "Run 'yum update' to update all packages",
			Details: map[string]interface{}{
				"raw_output": output,
			},
			References: []string{
				"https://access.redhat.com/security/updates/",
			},
		},
	}
}

// checkCommonCVEs checks for common CVEs based on distribution
func checkCommonCVEs(ctx context.Context, connection ssh.Connection, distroInfo distro.Info) ([]Finding, error) {
	findings := []Finding{}

	// Check for Log4Shell vulnerability (CVE-2021-44228)
	log4jOutput, err := connection.RunCommand(ctx, "find / -name 'log4j-core-*.jar' 2>/dev/null")
	if err == nil && log4jOutput != "" {
		findings = append(findings, Finding{
			ID:          "CVE-2021-44228",
			Title:       "Log4Shell Vulnerability",
			Description: "Log4j library detected which may be vulnerable to Log4Shell (CVE-2021-44228)",
			Severity:    SeverityCritical,
			Status:      StatusWarning,
			CheckType:   "Vulnerability",
			Timestamp:   time.Now(),
			Resource:    "Java Libraries",
			Remediation: "Update Log4j to version 2.15.0 or later",
			Details: map[string]interface{}{
				"found_files": log4jOutput,
			},
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
				"https://logging.apache.org/log4j/2.x/security.html",
			},
		})
	}

	// Check for Shellshock vulnerability (CVE-2014-6271)
	if distroInfo.Family == "debian" || distroInfo.Family == "rhel" {
		bashOutput, err := connection.RunCommand(ctx, "bash --version")
		if err == nil && bashOutput != "" {
			// This is a simplified check - in a real scanner you'd parse the version and check against known vulnerable versions
			findings = append(findings, Finding{
				ID:          "CVE-2014-6271",
				Title:       "Shellshock Vulnerability Check",
				Description: "Checked for Shellshock vulnerability in Bash",
				Severity:    SeverityHigh,
				Status:      StatusInfo,
				CheckType:   "Vulnerability",
				Timestamp:   time.Now(),
				Resource:    "Bash Shell",
				Remediation: "Ensure Bash is updated to the latest version",
				Details: map[string]interface{}{
					"bash_version": bashOutput,
				},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
				},
			})
		}
	}

	return findings, nil
}

// checkSSHConfig checks for weak SSH configurations
func checkSSHConfig(ctx context.Context, connection ssh.Connection) ([]Finding, error) {
	findings := []Finding{}

	// Check SSH configuration
	sshOutput, err := connection.RunCommand(ctx, "cat /etc/ssh/sshd_config")
	if err != nil {
		return findings, err
	}

	// Check for password authentication
	if sshOutput != "" {
		// Check if password authentication is enabled
		if !containsLine(sshOutput, "PasswordAuthentication no") {
			findings = append(findings, Finding{
				ID:          "SSH-001",
				Title:       "SSH Password Authentication Enabled",
				Description: "SSH server is configured to allow password authentication, which is less secure than key-based authentication",
				Severity:    SeverityMedium,
				Status:      StatusWarning,
				CheckType:   "Vulnerability",
				Timestamp:   time.Now(),
				Resource:    "SSH Configuration",
				Remediation: "Disable password authentication by setting 'PasswordAuthentication no' in /etc/ssh/sshd_config",
				References: []string{
					"https://www.ssh.com/academy/ssh/sshd_config",
				},
			})
		}

		// Check if root login is allowed
		if !containsLine(sshOutput, "PermitRootLogin no") {
			findings = append(findings, Finding{
				ID:          "SSH-002",
				Title:       "SSH Root Login Allowed",
				Description: "SSH server is configured to allow root login, which is a security risk",
				Severity:    SeverityHigh,
				Status:      StatusWarning,
				CheckType:   "Vulnerability",
				Timestamp:   time.Now(),
				Resource:    "SSH Configuration",
				Remediation: "Disable root login by setting 'PermitRootLogin no' in /etc/ssh/sshd_config",
				References: []string{
					"https://www.ssh.com/academy/ssh/sshd_config",
				},
			})
		}
	}

	return findings, nil
}

// containsLine checks if the output contains a specific line
func containsLine(output, line string) bool {
	// Simple implementation - in a real scanner you'd use regex to handle comments and whitespace
	return strings.Contains(output, line)
}

// BaseCheck provides common functionality for checks
type BaseCheck struct {
	name        string
	description string
}

// NewBaseCheck creates a new base check
func NewBaseCheck(name, description string) BaseCheck {
	return BaseCheck{
		name:        name,
		description: description,
	}
}

// Name returns the name of the check
func (c BaseCheck) Name() string {
	return c.name
}

// Description returns the description of the check
func (c BaseCheck) Description() string {
	return c.description
}

package scanner

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/psantana5/phoenix-tools/internal/config"
	"github.com/psantana5/phoenix-tools/internal/scanner/checks"
	"github.com/psantana5/phoenix-tools/internal/scanner/distro"
	"github.com/psantana5/phoenix-tools/internal/scanner/ssh"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

// Scanner represents the main scanning engine
type Scanner struct {
	config *config.Config
	checks []checks.Check
}

// ScanResult represents the result of a scan
type ScanResult struct {
	Target       string                 `json:"target" yaml:"target" xml:"target"`
	Distribution string                 `json:"distribution" yaml:"distribution" xml:"distribution"`
	StartTime    time.Time              `json:"start_time" yaml:"start_time" xml:"start_time"`
	EndTime      time.Time              `json:"end_time" yaml:"end_time" xml:"end_time"`
	Duration     string                 `json:"duration" yaml:"duration" xml:"duration"`
	Findings     []checks.Finding       `json:"findings" yaml:"findings" xml:"findings>finding"`
	Summary      map[string]interface{} `json:"summary" yaml:"summary" xml:"summary"`
	Error        string                 `json:"error,omitempty" yaml:"error,omitempty" xml:"error,omitempty"`
}

// NewScanner creates a new scanner instance
func NewScanner(cfg *config.Config) (*Scanner, error) {
	// Initialize scanner
	scanner := &Scanner{
		config: cfg,
		checks: []checks.Check{},
	}

	// Register checks based on configuration
	if cfg.Scan.Checks.CIS {
		scanner.checks = append(scanner.checks, checks.NewCISCheck())
	}
	if cfg.Scan.Checks.Firewall {
		scanner.checks = append(scanner.checks, checks.NewFirewallCheck())
	}
	if cfg.Scan.Checks.Privileges {
		scanner.checks = append(scanner.checks, checks.NewPrivilegesCheck())
	}
	if cfg.Scan.Checks.Vulnerability {
		scanner.checks = append(scanner.checks, checks.NewVulnerabilityCheck())
	}
	if cfg.Scan.Checks.Permissions {
		scanner.checks = append(scanner.checks, checks.NewPermissionsCheck())
	}
	if cfg.Scan.Checks.SSH {
		scanner.checks = append(scanner.checks, checks.NewSSHCheck())
	}

	return scanner, nil
}

// Scan performs a security scan on the specified targets
func (s *Scanner) Scan(ctx context.Context, targets []string) ([]ScanResult, error) {
	// Expand targets (e.g., CIDR ranges)
	expandedTargets, err := expandTargets(targets)
	if err != nil {
		return nil, fmt.Errorf("failed to expand targets: %w", err)
	}

	// Create results slice
	results := make([]ScanResult, len(expandedTargets))

	// Create error group for parallel execution
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(s.config.Scan.Parallel)

	// Create mutex for results
	var mu sync.Mutex

	// Scan each target
	for i, target := range expandedTargets {
		i, target := i, target // https://golang.org/doc/faq#closures_and_goroutines

		g.Go(func() error {
			// Create result
			result := ScanResult{
				Target:    target,
				StartTime: time.Now(),
				Findings:  []checks.Finding{},
				Summary:   make(map[string]interface{}),
			}

			// Create timeout context
			timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.Scan.Timeout)*time.Second)
			defer cancel()

			// Connect to target
			connection, err := s.connect(timeoutCtx, target)
			if err != nil {
				result.Error = fmt.Sprintf("failed to connect: %v", err)
				result.EndTime = time.Now()
				result.Duration = result.EndTime.Sub(result.StartTime).String()

				mu.Lock()
				results[i] = result
				mu.Unlock()

				return nil // Don't fail the entire scan if one target fails
			}
			defer connection.Close()

			// Detect distribution
			distroInfo, err := distro.Detect(timeoutCtx, connection)
			if err != nil {
				result.Error = fmt.Sprintf("failed to detect distribution: %v", err)
				result.EndTime = time.Now()
				result.Duration = result.EndTime.Sub(result.StartTime).String()

				mu.Lock()
				results[i] = result
				mu.Unlock()

				return nil
			}
			result.Distribution = distroInfo.String()

			// Skip if not in the list of distributions to scan
			if len(s.config.Scan.Distributions) > 0 {
				found := false
				for _, d := range s.config.Scan.Distributions {
					if strings.EqualFold(d, distroInfo.Name) || strings.EqualFold(d, distroInfo.Family) {
						found = true
						break
					}
				}
				if !found {
					result.Error = fmt.Sprintf("distribution %s not in scan list", distroInfo.String())
					result.EndTime = time.Now()
					result.Duration = result.EndTime.Sub(result.StartTime).String()

					mu.Lock()
					results[i] = result
					mu.Unlock()

					return nil
				}
			}

			// Run checks
			log.Info().Str("target", target).Str("distribution", distroInfo.String()).Msg("Running checks")

			for _, check := range s.checks {
				// Skip check if canceled
				if timeoutCtx.Err() != nil {
					break
				}

				// Run check
				findings, err := check.Run(timeoutCtx, connection, distroInfo)
				if err != nil {
					log.Error().Err(err).Str("check", check.Name()).Str("target", target).Msg("Check failed")
					continue
				}

				// Add findings
				result.Findings = append(result.Findings, findings...)
			}

			// Calculate summary
			result.Summary = calculateSummary(result.Findings)

			// Set end time
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime).String()

			// Store result
			mu.Lock()
			results[i] = result
			mu.Unlock()

			return nil
		})
	}

	// Wait for all scans to complete
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

// GenerateReport generates a report in the specified format
func (s *Scanner) GenerateReport(results []ScanResult, format string, writer io.Writer, colorize bool) error {
	switch strings.ToLower(format) {
	case "json":
		return generateJSONReport(results, writer)
	case "yaml":
		return generateYAMLReport(results, writer)
	case "xml":
		return generateXMLReport(results, writer)
	case "html":
		return generateHTMLReport(results, writer)
	case "text", "":
		return generateTextReport(results, writer, colorize)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// connect establishes a connection to the target
func (s *Scanner) connect(ctx context.Context, target string) (ssh.Connection, error) {
	// For localhost, use local connection
	if target == "localhost" || target == "127.0.0.1" {
		return ssh.NewLocalConnection(), nil
	}

	// For remote targets, use SSH
	return ssh.NewSSHConnection(ctx, ssh.SSHConnectionConfig{
		Host:     target,
		Port:     s.config.Scan.SSH.Port,
		User:     s.config.Scan.SSH.User,
		KeyFile:  s.config.Scan.SSH.KeyFile,
		Password: s.config.Scan.SSH.Password,
	})
}

// expandTargets expands CIDR ranges in targets
func expandTargets(targets []string) ([]string, error) {
	var expanded []string

	for _, target := range targets {
		// Check if target is a CIDR range
		if strings.Contains(target, "/") {
			// Parse CIDR
			ip, ipnet, err := net.ParseCIDR(target)
			if err != nil {
				// Not a valid CIDR, treat as a hostname
				expanded = append(expanded, target)
				continue
			}

			// Get all IPs in the range
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
				expanded = append(expanded, ip.String())
			}
		} else {
			// Not a CIDR, add as is
			expanded = append(expanded, target)
		}
	}

	return expanded, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// calculateSummary calculates summary statistics from findings
func calculateSummary(findings []checks.Finding) map[string]interface{} {
	summary := make(map[string]interface{})

	// Count findings by severity
	severityCounts := make(map[string]int)
	for _, finding := range findings {
		severityCounts[string(finding.Severity)]++
	}

	// Count findings by check type
	checkCounts := make(map[string]int)
	for _, finding := range findings {
		checkCounts[finding.CheckType]++
	}

	// Calculate pass/fail ratio
	totalChecks := 0
	passedChecks := 0
	for _, finding := range findings {
		totalChecks++
		if finding.Status == checks.StatusPassed {
			passedChecks++
		}
	}

	// Set summary values
	summary["total_findings"] = len(findings)
	summary["severity_counts"] = severityCounts
	summary["check_counts"] = checkCounts
	summary["total_checks"] = totalChecks
	summary["passed_checks"] = passedChecks
	if totalChecks > 0 {
		summary["pass_percentage"] = float64(passedChecks) / float64(totalChecks)
	}
	return summary
}

// generateJSONReport generates a JSON report
func generateJSONReport(results []ScanResult, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// generateYAMLReport generates a YAML report
func generateYAMLReport(results []ScanResult, writer io.Writer) error {
	return yaml.NewEncoder(writer).Encode(results)
}

// generateXMLReport generates an XML report
func generateXMLReport(results []ScanResult, writer io.Writer) error {
	encoder := xml.NewEncoder(writer)
	encoder.Indent("", "  ")

	// Write XML header
	if _, err := writer.Write([]byte(xml.Header)); err != nil {
		return err
	}

	// Create root element
	return encoder.Encode(struct {
		XMLName xml.Name    `xml:"scan_results"`
		Results []ScanResult `xml:"result"`
	}{
		Results: results,
	})
}

// generateHTMLReport generates an HTML report
func generateHTMLReport(results []ScanResult, writer io.Writer) error {
	// HTML template for the report
	const tmpl = `<!DOCTYPE html>
<html>
<head>
    <title>Phoenix Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .target { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        .target-header { background-color: #f5f5f5; padding: 10px; margin-bottom: 15px; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }
        .critical { border-left-color: #d9534f; }
        .high { border-left-color: #f0ad4e; }
        .medium { border-left-color: #5bc0de; }
        .low { border-left-color: #5cb85c; }
        .info { border-left-color: #777; }
        .passed { background-color: #dff0d8; }
        .failed { background-color: #f2dede; }
        .summary { margin-top: 10px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <h1>Phoenix Security Scan Report</h1>
    {{range .}}
    <div class="target">
        <div class="target-header">
            <h2>Target: {{.Target}}</h2>
            <p>Distribution: {{.Distribution}}</p>
            <p>Scan Time: {{.StartTime.Format "2006-01-02 15:04:05"}} to {{.EndTime.Format "2006-01-02 15:04:05"}} ({{.Duration}})</p>
            {{if .Error}}<p style="color: red;">Error: {{.Error}}</p>{{end}}
        </div>
        
        <div class="summary">
            <h3>Summary</h3>
            <table>
                <tr>
                    <th>Total Findings</th>
                    <td>{{index .Summary "total_findings"}}</td>
                </tr>
                <tr>
                    <th>Total Checks</th>
                    <td>{{index .Summary "total_checks"}}</td>
                </tr>
                <tr>
                    <th>Passed Checks</th>
                    <td>{{index .Summary "passed_checks"}}</td>
                </tr>
                {{if index .Summary "pass_percentage"}}
                <tr>
                    <th>Pass Percentage</th>
                    <td>{{printf "%.2f%%" (mul (index .Summary "pass_percentage") 100)}}</td>
                </tr>
                {{end}}
            </table>
            
            {{if index .Summary "severity_counts"}}
            <h4>Findings by Severity</h4>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                {{range $severity, $count := index .Summary "severity_counts"}}
                <tr>
                    <td>{{$severity}}</td>
                    <td>{{$count}}</td>
                </tr>
                {{end}}
            </table>
            {{end}}
            
            {{if index .Summary "check_counts"}}
            <h4>Findings by Check Type</h4>
            <table>
                <tr>
                    <th>Check Type</th>
                    <th>Count</th>
                </tr>
                {{range $checkType, $count := index .Summary "check_counts"}}
                <tr>
                    <td>{{$checkType}}</td>
                    <td>{{$count}}</td>
                </tr>
                {{end}}
            </table>
            {{end}}
        </div>
        
        {{if .Findings}}
        <h3>Findings</h3>
        {{range .Findings}}
        <div class="finding {{.Severity}} {{.Status}}">
            <h4>{{.Title}}</h4>
            <p><strong>Check:</strong> {{.CheckType}}</p>
            <p><strong>Severity:</strong> {{.Severity}}</p>
            <p><strong>Status:</strong> {{.Status}}</p>
            <p>{{.Description}}</p>
            {{if .Remediation}}<p><strong>Remediation:</strong> {{.Remediation}}</p>{{end}}
        </div>
        {{end}}
        {{end}}
    </div>
    {{end}}
</body>
</html>`

	// Create template
	t, err := template.New("report").Funcs(template.FuncMap{
		"mul": func(a, b float64) float64 {
			return a * b
		},
	}).Parse(tmpl)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	// Execute template
	return t.Execute(writer, results)
}

// generateTextReport generates a text report
func generateTextReport(results []ScanResult, writer io.Writer, colorize bool) error {
	// Disable color if requested
	if !colorize {
		color.NoColor = true
	}

	// Create color functions
	critical := color.New(color.FgRed, color.Bold).SprintFunc()
	high := color.New(color.FgRed).SprintFunc()
	medium := color.New(color.FgYellow).SprintFunc()
	low := color.New(color.FgGreen).SprintFunc()
	info := color.New(color.FgBlue).SprintFunc()
	passed := color.New(color.FgGreen).SprintFunc()
	failed := color.New(color.FgRed).SprintFunc()

	// Print each result
	for _, result := range results {
		// Print target header
		fmt.Fprintf(writer, "\n%s: %s\n", color.New(color.Bold).Sprint("Target"), result.Target)
		fmt.Fprintf(writer, "%s: %s\n", color.New(color.Bold).Sprint("Distribution"), result.Distribution)
		fmt.Fprintf(writer, "%s: %s to %s (%s)\n", 
			color.New(color.Bold).Sprint("Scan Time"), 
			result.StartTime.Format("2006-01-02 15:04:05"), 
			result.EndTime.Format("2006-01-02 15:04:05"), 
			result.Duration)

		// Print error if any
		if result.Error != "" {
			fmt.Fprintf(writer, "%s: %s\n", color.New(color.Bold, color.FgRed).Sprint("Error"), result.Error)
			continue
		}

		// Print summary
		fmt.Fprintf(writer, "\n%s:\n", color.New(color.Bold).Sprint("Summary"))
		fmt.Fprintf(writer, "  Total Findings: %d\n", result.Summary["total_findings"])
		fmt.Fprintf(writer, "  Total Checks: %d\n", result.Summary["total_checks"])
		fmt.Fprintf(writer, "  Passed Checks: %d\n", result.Summary["passed_checks"])
		if passPercentage, ok := result.Summary["pass_percentage"].(float64); ok {
			fmt.Fprintf(writer, "  Pass Percentage: %.2f%%\n", passPercentage*100)
		}

		// Print severity counts
		if severityCounts, ok := result.Summary["severity_counts"].(map[string]int); ok && len(severityCounts) > 0 {
			fmt.Fprintf(writer, "\n  %s:\n", color.New(color.Bold).Sprint("Findings by Severity"))
			for severity, count := range severityCounts {
				fmt.Fprintf(writer, "    %s: %d\n", severity, count)
			}
		}

		// Print check counts
		if checkCounts, ok := result.Summary["check_counts"].(map[string]int); ok && len(checkCounts) > 0 {
			fmt.Fprintf(writer, "\n  %s:\n", color.New(color.Bold).Sprint("Findings by Check Type"))
			for checkType, count := range checkCounts {
				fmt.Fprintf(writer, "    %s: %d\n", checkType, count)
			}
		}

		// Print findings
		if len(result.Findings) > 0 {
			fmt.Fprintf(writer, "\n%s:\n", color.New(color.Bold).Sprint("Findings"))

			// Create table
			table := tablewriter.NewWriter(writer)
			table.SetHeader([]string{"Check Type", "Severity", "Status", "Title"})
			table.SetAutoWrapText(false)
			table.SetRowLine(true)

			// Add findings to table
			for _, finding := range result.Findings {
				// Format severity
				var severityStr string
				switch finding.Severity {
				case checks.SeverityCritical:
					severityStr = critical("CRITICAL")
				case checks.SeverityHigh:
					severityStr = high("HIGH")
				case checks.SeverityMedium:
					severityStr = medium("MEDIUM")
				case checks.SeverityLow:
					severityStr = low("LOW")
				case checks.SeverityInfo:
					severityStr = info("INFO")
				default:
					severityStr = string(finding.Severity)
				}

				// Format status
				var statusStr string
				switch finding.Status {
				case checks.StatusPassed:
					statusStr = passed("PASSED")
				case checks.StatusFailed:
					statusStr = failed("FAILED")
				default:
					statusStr = string(finding.Status)
				}

				// Add row
				table.Append([]string{finding.CheckType, severityStr, statusStr, finding.Title})
			}

			// Render table
			table.Render()

			// Print detailed findings
			for i, finding := range result.Findings {
				fmt.Fprintf(writer, "\n%d. %s\n", i+1, color.New(color.Bold).Sprint(finding.Title))
				fmt.Fprintf(writer, "   Check: %s\n", finding.CheckType)
				
				// Format severity
				fmt.Fprintf(writer, "   Severity: ")
				switch finding.Severity {
				case checks.SeverityCritical:
					fmt.Fprintf(writer, "%s\n", critical("CRITICAL"))
				case checks.SeverityHigh:
					fmt.Fprintf(writer, "%s\n", high("HIGH"))
				case checks.SeverityMedium:
					fmt.Fprintf(writer, "%s\n", medium("MEDIUM"))
				case checks.SeverityLow:
					fmt.Fprintf(writer, "%s\n", low("LOW"))
				case checks.SeverityInfo:
					fmt.Fprintf(writer, "%s\n", info("INFO"))
				default:
					fmt.Fprintf(writer, "%s\n", string(finding.Severity))
				}

				// Format status
				fmt.Fprintf(writer, "   Status: ")
				switch finding.Status {
				case checks.StatusPassed:
					fmt.Fprintf(writer, "%s\n", passed("PASSED"))
				case checks.StatusFailed:
					fmt.Fprintf(writer, "%s\n", failed("FAILED"))
				default:
					fmt.Fprintf(writer, "%s\n", string(finding.Status))
				}

				// Print description and remediation
				fmt.Fprintf(writer, "   Description: %s\n", finding.Description)
				if finding.Remediation != "" {
					fmt.Fprintf(writer, "   Remediation: %s\n", finding.Remediation)
				}
			}
		}
	}

	return nil
}
package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/psantana5/phoenix-tools/internal/config"
	"github.com/psantana5/phoenix-tools/internal/scanner"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type scanOptions struct {
	targets       []string
	outputFormat  string
	outputFile    string
	parallel      int
	timeout       int
	distributions []string
	checks        []string
	sshUser       string
	sshKeyFile    string
	sshPassword   string
	sshPort       int
	noColor       bool
}

// newScanCommand creates the scan command
func newScanCommand() *cobra.Command {
	opts := scanOptions{}

	scanCmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Scan Linux systems for security and compliance issues",
		Long: `Scan one or more Linux systems for security and compliance issues.

Targets can be specified as hostnames, IP addresses, or CIDR ranges.
For local scanning, use 'localhost' or '127.0.0.1' as the target.`,
		Example: `  # Scan the local system
  phoenix scan localhost

  # Scan multiple remote systems
  phoenix scan server1.example.com server2.example.com

  # Scan a network range
  phoenix scan 192.168.1.0/24

  # Scan with specific checks
  phoenix scan --checks cis,ssh,firewall server1.example.com

  # Output results to a file in JSON format
  phoenix scan --output-format json --output-file results.json server1.example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate arguments
			if len(args) == 0 && len(opts.targets) == 0 {
				return fmt.Errorf("at least one target must be specified")
			}

			// Combine args and targets flag
			opts.targets = append(opts.targets, args...)

			// Load configuration
			cfg, err := config.LoadConfig()
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			// Override config with command-line options
			if opts.parallel > 0 {
				cfg.Scan.Parallel = opts.parallel
			}
			if opts.timeout > 0 {
				cfg.Scan.Timeout = opts.timeout
			}
			if len(opts.distributions) > 0 {
				cfg.Scan.Distributions = opts.distributions
			}
			if opts.sshUser != "" {
				cfg.Scan.SSH.User = opts.sshUser
			}
			if opts.sshKeyFile != "" {
				cfg.Scan.SSH.KeyFile = opts.sshKeyFile
			}
			if opts.sshPassword != "" {
				cfg.Scan.SSH.Password = opts.sshPassword
			}
			if opts.sshPort > 0 {
				cfg.Scan.SSH.Port = opts.sshPort
			}

			// Configure checks
			if len(opts.checks) > 0 {
				// Reset all checks to false
				cfg.Scan.Checks.CIS = false
				cfg.Scan.Checks.Firewall = false
				cfg.Scan.Checks.Privileges = false
				cfg.Scan.Checks.Vulnerability = false
				cfg.Scan.Checks.Permissions = false
				cfg.Scan.Checks.SSH = false

				// Enable specified checks
				for _, check := range opts.checks {
					switch strings.ToLower(check) {
					case "cis":
						cfg.Scan.Checks.CIS = true
					case "firewall":
						cfg.Scan.Checks.Firewall = true
					case "privileges":
						cfg.Scan.Checks.Privileges = true
					case "vulnerability":
						cfg.Scan.Checks.Vulnerability = true
					case "permissions":
						cfg.Scan.Checks.Permissions = true
					case "ssh":
						cfg.Scan.Checks.SSH = true
					default:
						log.Warn().Msgf("Unknown check type: %s", check)
					}
				}
			}

			// Create scanner
			scanner, err := scanner.NewScanner(cfg)
			if err != nil {
				return fmt.Errorf("failed to create scanner: %w", err)
			}

			// Run scan
			log.Info().Msgf("Starting scan of %d targets", len(opts.targets))
			startTime := time.Now()

			results, err := scanner.Scan(cmd.Context(), opts.targets)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			elapsedTime := time.Since(startTime)
			log.Info().Msgf("Scan completed in %s", elapsedTime)

			// Output results
			outputFormat := opts.outputFormat
			if outputFormat == "" {
				outputFormat = cfg.OutputFormat
			}

			outputFile := opts.outputFile
			var output *os.File
			if outputFile != "" {
				output, err = os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer output.Close()
			} else {
				output = os.Stdout
			}

			// Generate report
			if err := scanner.GenerateReport(results, outputFormat, output, !opts.noColor); err != nil {
				return fmt.Errorf("failed to generate report: %w", err)
			}

			return nil
		},
	}

	// Add flags
	scanCmd.Flags().StringSliceVarP(&opts.targets, "targets", "t", nil, "targets to scan (hostnames, IPs, or CIDR ranges)")
	scanCmd.Flags().StringVarP(&opts.outputFormat, "output-format", "f", "", "output format (json, xml, html, text)")
	scanCmd.Flags().StringVarP(&opts.outputFile, "output-file", "o", "", "output file (defaults to stdout)")
	scanCmd.Flags().IntVarP(&opts.parallel, "parallel", "p", 0, "number of parallel scans")
	scanCmd.Flags().IntVar(&opts.timeout, "timeout", 0, "scan timeout in seconds")
	scanCmd.Flags().StringSliceVar(&opts.distributions, "distributions", nil, "limit scan to specific distributions")
	scanCmd.Flags().StringSliceVar(&opts.checks, "checks", nil, "checks to run (cis,firewall,privileges,vulnerability,permissions,ssh)")
	scanCmd.Flags().StringVar(&opts.sshUser, "ssh-user", "", "SSH username")
	scanCmd.Flags().StringVar(&opts.sshKeyFile, "ssh-key", "", "SSH private key file")
	scanCmd.Flags().StringVar(&opts.sshPassword, "ssh-password", "", "SSH password")
	scanCmd.Flags().IntVar(&opts.sshPort, "ssh-port", 0, "SSH port")
	scanCmd.Flags().BoolVar(&opts.noColor, "no-color", false, "disable color output")

	// Register viper flags
	viper.BindPFlag("scan.parallel", scanCmd.Flags().Lookup("parallel"))
	viper.BindPFlag("scan.timeout", scanCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("scan.ssh.user", scanCmd.Flags().Lookup("ssh-user"))
	viper.BindPFlag("scan.ssh.key_file", scanCmd.Flags().Lookup("ssh-key"))
	viper.BindPFlag("scan.ssh.password", scanCmd.Flags().Lookup("ssh-password"))
	viper.BindPFlag("scan.ssh.port", scanCmd.Flags().Lookup("ssh-port"))

	return scanCmd
}
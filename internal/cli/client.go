package cli

import (
	"fmt"
	"time"

	"github.com/psantana5/phoenix-tools/internal/api/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// newClientCommand creates the client command
func newClientCommand() *cobra.Command {
	clientCmd := &cobra.Command{
		Use:   "client",
		Short: "Interact with a Phoenix API server",
		Long: `Interact with a Phoenix API server.

This command allows you to interact with a remote Phoenix API server
to manage scans and retrieve results.`,
	}

	// Add subcommands
	clientCmd.AddCommand(newClientHealthCommand())
	clientCmd.AddCommand(newClientScansCommand())
	clientCmd.AddCommand(newClientFindingsCommand())

	// Add global flags
	clientCmd.PersistentFlags().String("server", "http://localhost:8080", "API server URL")
	clientCmd.PersistentFlags().String("api-key", "", "API key for authentication")

	// Bind flags to viper
	viper.BindPFlag("client.server", clientCmd.PersistentFlags().Lookup("server"))
	viper.BindPFlag("client.api_key", clientCmd.PersistentFlags().Lookup("api-key"))

	return clientCmd
}

// newClientHealthCommand creates the client health command
func newClientHealthCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Check API server health",
		Long:  `Check the health status of the Phoenix API server.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get client configuration
			server := viper.GetString("client.server")
			apiKey := viper.GetString("client.api_key")

			// Create client
			c := client.NewClient(server, apiKey)

			// Get health status
			health, err := c.GetHealth()
			if err != nil {
				return fmt.Errorf("failed to get health status: %w", err)
			}

			// Print health status
			fmt.Printf("API Server Health:\n")
			fmt.Printf("  Status: %s\n", health["status"])
			fmt.Printf("  Time: %s\n", health["time"])

			return nil
		},
	}
}

// newClientScansCommand creates the client scans command
func newClientScansCommand() *cobra.Command {
	scansCmd := &cobra.Command{
		Use:   "scans",
		Short: "Manage scans",
		Long:  `Manage scans on the Phoenix API server.`,
	}

	// Add subcommands
	scansCmd.AddCommand(newClientScansListCommand())
	scansCmd.AddCommand(newClientScansCreateCommand())
	scansCmd.AddCommand(newClientScansGetCommand())
	scansCmd.AddCommand(newClientScansDeleteCommand())

	return scansCmd
}

// newClientScansListCommand creates the client scans list command
func newClientScansListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all scans",
		Long:  `List all scans on the Phoenix API server.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get client configuration
			server := viper.GetString("client.server")
			apiKey := viper.GetString("client.api_key")

			// Create client
			c := client.NewClient(server, apiKey)

			// List scans
			scans, err := c.ListScans()
			if err != nil {
				return fmt.Errorf("failed to list scans: %w", err)
			}

			// Print scans
			fmt.Printf("Scans (%d):\n", len(scans))
			for _, scan := range scans {
				fmt.Printf("  ID: %s\n", scan.ID)
				fmt.Printf("    Target: %s\n", scan.Target)
				fmt.Printf("    Status: %s\n", scan.Status)
				fmt.Printf("    Timestamp: %s\n\n", scan.Timestamp.Format(time.RFC3339))
			}

			return nil
		},
	}
}

// newClientScansCreateCommand creates the client scans create command
func newClientScansCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [target]",
		Short: "Create a new scan",
		Long:  `Create a new scan on the Phoenix API server.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get target from args
			target := args[0]

			// Get checks from flags
			checks, _ := cmd.Flags().GetStringSlice("checks")

			// Get client configuration
			server := viper.GetString("client.server")
			apiKey := viper.GetString("client.api_key")

			// Create client
			c := client.NewClient(server, apiKey)

			// Create scan request
			request := client.ScanRequest{
				Target: target,
				Checks: checks,
			}

			// Create scan
			scan, err := c.CreateScan(request)
			if err != nil {
				return fmt.Errorf("failed to create scan: %w", err)
			}

			// Print scan
			fmt.Printf("Scan created:\n")
			fmt.Printf("  ID: %s\n", scan.ID)
			fmt.Printf("  Target: %s\n", scan.Target)
			fmt.Printf("  Status: %s\n", scan.Status)
			fmt.Printf("  Timestamp: %s\n", scan.Timestamp.Format(time.RFC3339))

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringSlice("checks", []string{}, "checks to run (comma-separated)")

	return cmd
}

// newClientScansGetCommand creates the client scans get command
func newClientScansGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get [id]",
		Short: "Get a specific scan",
		Long:  `Get details for a specific scan on the Phoenix API server.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get scan ID from args
			id := args[0]

			// Get client configuration
			server := viper.GetString("client.server")
			apiKey := viper.GetString("client.api_key")

			// Create client
			c := client.NewClient(server, apiKey)

			// Get scan
			scan, err := c.GetScan(id)
			if err != nil {
				return fmt.Errorf("failed to get scan: %w", err)
			}

			// Print scan
			fmt.Printf("Scan details:\n")
			fmt.Printf("  ID: %s\n", scan.ID)
			fmt.Printf("  Target: %s\n", scan.Target)
			fmt.Printf("  Status: %s\n", scan.Status)
			fmt.Printf("  Timestamp: %s\n", scan.Timestamp.Format(time.RFC3339))

			return nil
		},
	}
}

// newClientScansDeleteCommand creates the client scans delete command
func newClientScansDeleteCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [id]",
		Short: "Delete a specific scan",
		Long:  `Delete a specific scan from the Phoenix API server.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get scan ID from args
			id := args[0]

			// Get client configuration
			server := viper.GetString("client.server")
			apiKey := viper.GetString("client.api_key")

			// Create client
			c := client.NewClient(server, apiKey)

			// Delete scan
			if err := c.DeleteScan(id); err != nil {
				return fmt.Errorf("failed to delete scan: %w", err)
			}

			fmt.Printf("Scan %s deleted successfully\n", id)
			return nil
		},
	}
}

// newClientFindingsCommand creates the client findings command
func newClientFindingsCommand() *cobra.Command {
	findingsCmd := &cobra.Command{
		Use:   "findings",
		Short: "Manage findings",
		Long:  `Manage findings on the Phoenix API server.`,
	}

	// Add subcommands
	findingsCmd.AddCommand(newClientFindingsListCommand())
	findingsCmd.AddCommand(newClientFindingsGetCommand())

	return findingsCmd
}

// newClientFindingsListCommand creates the client findings list command
func newClientFindingsListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all findings",
		Long:  `List all findings on the Phoenix API server.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get filter flags
			severity, _ := cmd.Flags().GetString("severity")
			status, _ := cmd.Flags().GetString("status")
			checkType, _ := cmd.Flags().GetString("check-type")

			// Get client configuration
			server := viper.GetString("client.server")
			apiKey := viper.GetString("client.api_key")

			// Create client
			c := client.NewClient(server, apiKey)

			// List findings
			findings, err := c.ListAllFindings(severity, status, checkType)
			if err != nil {
				return fmt.Errorf("failed to list findings: %w", err)
			}

			// Print findings
			fmt.Printf("Findings (%d):\n", len(findings))
			for _, finding := range findings {
				fmt.Printf("  ID: %s\n", finding.ID)
				fmt.Printf("    Title: %s\n", finding.Title)
				fmt.Printf("    Severity: %s\n", finding.Severity)
				fmt.Printf("    Status: %s\n", finding.Status)
				fmt.Printf("    Check Type: %s\n\n", finding.CheckType)
			}

			return nil
		},
	}

	// Add filter flags
	cmd.Flags().String("severity", "", "filter by severity (HIGH, MEDIUM, LOW)")
	cmd.Flags().String("status", "", "filter by status (PASSED, FAILED, WARNING)")
	cmd.Flags().String("check-type", "", "filter by check type (CIS, SSH, etc.)")

	return cmd
}

// newClientFindingsGetCommand creates the client findings get command
func newClientFindingsGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get [scan-id]",
		Short: "Get findings for a scan",
		Long:  `Get findings for a specific scan on the Phoenix API server.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get scan ID from args
			scanID := args[0]

			// Get client configuration
			server := viper.GetString("client.server")
			apiKey := viper.GetString("client.api_key")

			// Create client
			c := client.NewClient(server, apiKey)

			// Get findings
			findings, err := c.GetFindings(scanID)
			if err != nil {
				return fmt.Errorf("failed to get findings: %w", err)
			}

			// Print findings
			fmt.Printf("Findings for scan %s (%d):\n", scanID, len(findings))
			for _, finding := range findings {
				fmt.Printf("  ID: %s\n", finding.ID)
				fmt.Printf("    Title: %s\n", finding.Title)
				fmt.Printf("    Description: %s\n", finding.Description)
				fmt.Printf("    Severity: %s\n", finding.Severity)
				fmt.Printf("    Status: %s\n", finding.Status)
				fmt.Printf("    Resource: %s\n", finding.Resource)
				fmt.Printf("    Remediation: %s\n", finding.Remediation)
				if len(finding.References) > 0 {
					fmt.Printf("    References:\n")
					for _, ref := range finding.References {
						fmt.Printf("      - %s\n", ref)
					}
				}
				if len(finding.Details) > 0 {
					fmt.Printf("    Details: Available\n")
				}
				fmt.Println()
			}

			return nil
		},
	}
}

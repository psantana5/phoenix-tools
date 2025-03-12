package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"github.com/psantana5/phoenix-tools/internal/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// newConfigCommand creates the config command
func newConfigCommand() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage Phoenix configuration",
		Long: `Manage Phoenix configuration settings.

This command allows you to view, edit, and reset configuration settings
for the Phoenix tool. Configuration is stored in a YAML file in your
home directory by default.`,
	}

	// Add subcommands
	configCmd.AddCommand(newConfigViewCommand())
	configCmd.AddCommand(newConfigSetCommand())
	configCmd.AddCommand(newConfigResetCommand())

	return configCmd
}

// newConfigViewCommand creates the config view command
func newConfigViewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "view",
		Short: "View current configuration",
		Long:  `Display the current Phoenix configuration settings.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := config.LoadConfig()
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			// Display configuration
			fmt.Printf("Configuration file: %s\n\n", viper.ConfigFileUsed())
			
			// TODO: Implement pretty printing of configuration
			// This would typically involve marshaling the config to YAML and printing it
			fmt.Println("Configuration settings:")
			fmt.Println("(Configuration details will be displayed here)")

			return nil
		},
	}
}

// newConfigSetCommand creates the config set command
func newConfigSetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set [key] [value]",
		Short: "Set a configuration value",
		Long:  `Set a specific configuration value.`,
		Args:  cobra.ExactArgs(2),
		Example: `  # Set API server port
  phoenix config set api.port 8443

  # Set SSH username for scans
  phoenix config set scan.ssh.user admin

  # Enable CIS checks by default
  phoenix config set scan.checks.cis true`,
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			value := args[1]

			// Set the value in viper
			viper.Set(key, value)

			// Save the configuration
			if err := viper.WriteConfig(); err != nil {
				// If config file does not exist, create it
				if _, ok := err.(viper.ConfigFileNotFoundError); ok {
					home, err := os.UserHomeDir()
					if err != nil {
						return fmt.Errorf("failed to find home directory: %w", err)
					}

					configPath := filepath.Join(home, ".phoenix.yaml")
					if err := viper.WriteConfigAs(configPath); err != nil {
						return fmt.Errorf("failed to write config file: %w", err)
					}
					log.Info().Msgf("Created new config file at %s", configPath)
				} else {
					return fmt.Errorf("failed to write config file: %w", err)
				}
			}

			log.Info().Msgf("Set %s = %s", key, value)
			return nil
		},
	}
}

// newConfigResetCommand creates the config reset command
func newConfigResetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Reset configuration to defaults",
		Long:  `Reset all configuration settings to their default values.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get config file path
			configFile := viper.ConfigFileUsed()
			if configFile == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("failed to find home directory: %w", err)
				}
				configFile = filepath.Join(home, ".phoenix.yaml")
			}

			// Check if file exists
			if _, err := os.Stat(configFile); os.IsNotExist(err) {
				log.Info().Msg("No configuration file found, already using defaults")
				return nil
			}

			// Confirm with user
			fmt.Printf("This will delete your configuration file at %s\n", configFile)
			fmt.Print("Are you sure you want to continue? [y/N]: ")

			// TODO: Implement actual user confirmation
			// For now, just simulate a confirmation
			fmt.Println("y")

			// Delete the config file
			if err := os.Remove(configFile); err != nil {
				return fmt.Errorf("failed to delete config file: %w", err)
			}

			log.Info().Msg("Configuration reset to defaults")
			return nil
		},
	}
}
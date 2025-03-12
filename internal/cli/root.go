package cli

import (
	"fmt"
	"os"

	"github.com/psantana5/phoenix-tools/internal/config"
	"github.com/psantana5/phoenix-tools/internal/version"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	debug   bool
)

// NewRootCommand creates the root command for the Phoenix CLI
func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "phoenix",
		Short: "Phoenix - Enterprise Linux Auditing Tool",
		Long: `Phoenix is a comprehensive, enterprise-grade tool designed to automate 
	security and compliance auditing across multiple Linux distributions.

	It provides a robust framework for scanning systems against industry benchmarks,
	detecting vulnerabilities, and ensuring compliance with security best practices.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Initialize config
			if err := initConfig(); err != nil {
				return err
			}

			// Set log level based on flags
			config.ConfigureLogging(verbose, debug)

			return nil
		},
		Version: version.Version,
	}

	// Add persistent flags that apply to all commands
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.phoenix.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug output")

	// Add subcommands
	rootCmd.AddCommand(newScanCommand())
	rootCmd.AddCommand(newAPICommand())
	rootCmd.AddCommand(newConfigCommand())
	rootCmd.AddCommand(newReportCommand())

	return rootCmd
}

// initConfig reads in config file and ENV variables if set
func initConfig() error {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to find home directory: %w", err)
		}

		// Search config in home directory with name ".phoenix" (without extension)
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".phoenix")
	}

	// Read in environment variables that match prefix
	viper.SetEnvPrefix("PHOENIX")
	viper.AutomaticEnv()

	// If a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil {
		log.Info().Msgf("Using config file: %s", viper.ConfigFileUsed())
	}

	return nil
}
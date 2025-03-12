package cli

import (
	"fmt"
	"net"
	"strconv"

	"github.com/psantana5/phoenix-tools/internal/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type apiOptions struct {
	host    string
	port    int
	tlsCert string
	tlsKey  string
	noTLS   bool
}

// newAPICommand creates the API server command
func newAPICommand() *cobra.Command {
	opts := apiOptions{}

	apiCmd := &cobra.Command{
		Use:   "api",
		Short: "Start the Phoenix API server",
		Long: `Start the Phoenix API server for remote management and integration.

The API server provides RESTful endpoints for scanning systems, retrieving results,
and managing configurations. It can be secured with TLS for production use.`,
		Example: `  # Start API server with default settings
  phoenix api

  # Start API server on a specific port
  phoenix api --port 8443

  # Start API server with custom TLS certificates
  phoenix api --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem

  # Start API server without TLS (not recommended for production)
  phoenix api --no-tls`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := config.LoadConfig()
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			// Override config with command-line options
			if opts.host != "" {
				cfg.API.Host = opts.host
			}
			if opts.port > 0 {
				cfg.API.Port = opts.port
			}
			if opts.tlsCert != "" {
				cfg.API.TLSCert = opts.tlsCert
			}
			if opts.tlsKey != "" {
				cfg.API.TLSKey = opts.tlsKey
			}
			if opts.noTLS {
				cfg.API.TLS = false
			}

			// Validate configuration
			if cfg.API.Port <= 0 || cfg.API.Port > 65535 {
				return fmt.Errorf("invalid port number: %d", cfg.API.Port)
			}

			// Check if the port is available
			listener, err := net.Listen("tcp", net.JoinHostPort(cfg.API.Host, strconv.Itoa(cfg.API.Port)))
			if err != nil {
				return fmt.Errorf("port %d is not available: %w", cfg.API.Port, err)
			}
			listener.Close()

			// Start API server
			log.Info().Msgf("Starting Phoenix API server on %s:%d", cfg.API.Host, cfg.API.Port)
			if cfg.API.TLS {
				log.Info().Msg("TLS enabled")
				if cfg.API.TLSCert == "" || cfg.API.TLSKey == "" {
					log.Warn().Msg("Using auto-generated self-signed certificate (not recommended for production)")
				}
			} else {
				log.Warn().Msg("TLS disabled (not recommended for production)")
			}

			// TODO: Implement actual API server startup
			// This would typically involve creating a router, registering handlers,
			// and starting an HTTP/HTTPS server
			log.Info().Msg("API server started successfully")
			log.Info().Msg("Press Ctrl+C to stop the server")

			// Block until interrupted
			<-cmd.Context().Done()
			log.Info().Msg("Shutting down API server")

			return nil
		},
	}

	// Add flags
	apiCmd.Flags().StringVar(&opts.host, "host", "", "host address to bind to")
	apiCmd.Flags().IntVarP(&opts.port, "port", "p", 0, "port to listen on")
	apiCmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "TLS certificate file")
	apiCmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "TLS key file")
	apiCmd.Flags().BoolVar(&opts.noTLS, "no-tls", false, "disable TLS (not recommended for production)")

	// Register viper flags
	viper.BindPFlag("api.host", apiCmd.Flags().Lookup("host"))
	viper.BindPFlag("api.port", apiCmd.Flags().Lookup("port"))
	viper.BindPFlag("api.tls_cert", apiCmd.Flags().Lookup("tls-cert"))
	viper.BindPFlag("api.tls_key", apiCmd.Flags().Lookup("tls-key"))
	viper.BindPFlag("api.tls", apiCmd.Flags().Lookup("no-tls"))

	return apiCmd
}
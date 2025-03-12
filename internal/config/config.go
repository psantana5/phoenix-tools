package config

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Default configuration values
const (
	DefaultAPIPort = 8080
	DefaultLogLevel = "info"
	DefaultOutputFormat = "json"
)

// Config represents the application configuration
type Config struct {
	// General settings
	LogLevel     string `mapstructure:"log_level"`
	OutputFormat string `mapstructure:"output_format"`
	
	// API settings
	API APIConfig `mapstructure:"api"`
	
	// Scanning settings
	Scan ScanConfig `mapstructure:"scan"`
	
	// Notification settings
	Notifications NotificationConfig `mapstructure:"notifications"`
}

// APIConfig contains API-specific configuration
type APIConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Port    int    `mapstructure:"port"`
	Host    string `mapstructure:"host"`
	TLS     struct {
		Enabled    bool   `mapstructure:"enabled"`
		CertFile   string `mapstructure:"cert_file"`
		KeyFile    string `mapstructure:"key_file"`
	} `mapstructure:"tls"`
	Auth struct {
		Enabled bool   `mapstructure:"enabled"`
		JWTSecret string `mapstructure:"jwt_secret"`
		TokenExpiry int `mapstructure:"token_expiry"` // in minutes
	} `mapstructure:"auth"`
}

// ScanConfig contains scanning-specific configuration
type ScanConfig struct {
	Parallel      int      `mapstructure:"parallel"`
	Timeout       int      `mapstructure:"timeout"` // in seconds
	Distributions []string `mapstructure:"distributions"`
	Checks        struct {
		CIS          bool `mapstructure:"cis"`
		Firewall     bool `mapstructure:"firewall"`
		Privileges   bool `mapstructure:"privileges"`
		Vulnerability bool `mapstructure:"vulnerability"`
		Permissions  bool `mapstructure:"permissions"`
		SSH          bool `mapstructure:"ssh"`
	} `mapstructure:"checks"`
	SSH struct {
		User       string `mapstructure:"user"`
		KeyFile    string `mapstructure:"key_file"`
		Password   string `mapstructure:"password"`
		Port       int    `mapstructure:"port"`
	} `mapstructure:"ssh"`
}

// NotificationConfig contains notification-specific configuration
type NotificationConfig struct {
	Email struct {
		Enabled  bool   `mapstructure:"enabled"`
		SMTP     string `mapstructure:"smtp"`
		Port     int    `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		From     string `mapstructure:"from"`
		To       string `mapstructure:"to"`
	} `mapstructure:"email"`
	Slack struct {
		Enabled   bool   `mapstructure:"enabled"`
		WebhookURL string `mapstructure:"webhook_url"`
		Channel   string `mapstructure:"channel"`
	} `mapstructure:"slack"`
	Webhook struct {
		Enabled bool   `mapstructure:"enabled"`
		URL     string `mapstructure:"url"`
		Method  string `mapstructure:"method"`
	} `mapstructure:"webhook"`
}

// LoadConfig loads the configuration from viper
func LoadConfig() (*Config, error) {
	var config Config

	// Set defaults
	viper.SetDefault("log_level", DefaultLogLevel)
	viper.SetDefault("output_format", DefaultOutputFormat)
	viper.SetDefault("api.port", DefaultAPIPort)
	viper.SetDefault("api.enabled", true)
	viper.SetDefault("api.host", "127.0.0.1")
	viper.SetDefault("scan.parallel", 10)
	viper.SetDefault("scan.timeout", 300)
	viper.SetDefault("scan.checks.cis", true)
	viper.SetDefault("scan.checks.firewall", true)
	viper.SetDefault("scan.checks.privileges", true)
	viper.SetDefault("scan.checks.vulnerability", true)
	viper.SetDefault("scan.checks.permissions", true)
	viper.SetDefault("scan.checks.ssh", true)
	viper.SetDefault("scan.ssh.port", 22)

	// Unmarshal config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// ConfigureLogging sets up the logging based on the provided flags
func ConfigureLogging(verbose, debug bool) {
	// Set log level based on flags
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug logging enabled")
	} else if verbose {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		log.Info().Msg("Verbose logging enabled")
	} else {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}
}
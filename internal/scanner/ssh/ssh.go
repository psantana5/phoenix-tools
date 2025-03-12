package ssh

import (
	"context"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Connection represents a connection to a target system
type Connection interface {
	RunCommand(ctx context.Context, command string) (string, error)
	Close() error
}

// SSHConnectionConfig represents the configuration for an SSH connection
type SSHConnectionConfig struct {
	Host     string
	Port     int
	User     string
	KeyFile  string
	Password string
}

// SSHConnection represents an SSH connection to a target system
type SSHConnection struct {
	client *ssh.Client
	config SSHConnectionConfig
}

// LocalConnection represents a connection to the local system
type LocalConnection struct{}

// NewSSHConnection creates a new SSH connection
func NewSSHConnection(ctx context.Context, config SSHConnectionConfig) (Connection, error) {
	// Set default port if not specified
	if config.Port == 0 {
		config.Port = 22
	}

	// Create SSH client config
	clientConfig := &ssh.ClientConfig{
		User:            config.User,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Add authentication methods
	if config.Password != "" {
		clientConfig.Auth = append(clientConfig.Auth, ssh.Password(config.Password))
	}

	if config.KeyFile != "" {
		key, err := ioutil.ReadFile(config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read private key: %w", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %w", err)
		}

		clientConfig.Auth = append(clientConfig.Auth, ssh.PublicKeys(signer))
	}

	// Connect to the SSH server
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	return &SSHConnection{
		client: client,
		config: config,
	}, nil
}

// RunCommand runs a command on the target system
func (c *SSHConnection) RunCommand(ctx context.Context, command string) (string, error) {
	// Create a session
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Run the command
	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}

// Close closes the SSH connection
func (c *SSHConnection) Close() error {
	return c.client.Close()
}

// NewLocalConnection creates a new local connection
func NewLocalConnection() Connection {
	return &LocalConnection{}
}

// RunCommand runs a command on the local system
func (c *LocalConnection) RunCommand(ctx context.Context, command string) (string, error) {
	// Split the command into parts
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty command")
	}

	// Create the command
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)

	// Run the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}

// Close is a no-op for local connections
func (c *LocalConnection) Close() error {
	return nil
}

package distro

import (
	"context"
	"fmt"
	"strings"

	"github.com/psantana5/phoenix-tools/internal/scanner/ssh"
)

// Info represents information about a Linux distribution
// This renames DistroInfo to Info to match what's expected in checks.go
type Info struct {
	Name    string
	Version string
	Family  string
}

// String returns a string representation of the distribution
func (d Info) String() string {
	return fmt.Sprintf("%s %s (%s)", d.Name, d.Version, d.Family)
}

// Detect attempts to detect the Linux distribution on the target system
func Detect(ctx context.Context, conn ssh.Connection) (Info, error) {
	// Try to read /etc/os-release first
	output, err := conn.RunCommand(ctx, "cat /etc/os-release")
	if err == nil {
		return parseOSRelease(output), nil
	}

	// Fall back to other methods
	output, err = conn.RunCommand(ctx, "lsb_release -a")
	if err == nil {
		return parseLSBRelease(output), nil
	}

	// Try to read /etc/issue
	output, err = conn.RunCommand(ctx, "cat /etc/issue")
	if err == nil {
		return parseIssue(output), nil
	}

	// If all else fails, return a generic Linux distribution
	return Info{
		Name:    "Unknown",
		Version: "Unknown",
		Family:  "Linux",
	}, nil
}

// parseOSRelease parses the output of /etc/os-release
func parseOSRelease(output string) Info {
	var name, version, id string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(line[5:], "\"")
		} else if strings.HasPrefix(line, "VERSION=") {
			version = strings.Trim(line[8:], "\"")
		} else if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(line[3:], "\"")
		}
	}

	family := determineFamily(id)

	return Info{
		Name:    name,
		Version: version,
		Family:  family,
	}
}

// parseLSBRelease parses the output of lsb_release -a
func parseLSBRelease(output string) Info {
	var name, version string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "Distributor ID:") {
			name = strings.TrimSpace(line[15:])
		} else if strings.HasPrefix(line, "Release:") {
			version = strings.TrimSpace(line[8:])
		}
	}

	family := determineFamily(strings.ToLower(name))

	return Info{
		Name:    name,
		Version: version,
		Family:  family,
	}
}

// parseIssue parses the output of /etc/issue
func parseIssue(output string) Info {
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return Info{
			Name:    "Unknown",
			Version: "Unknown",
			Family:  "Linux",
		}
	}

	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return Info{
			Name:    parts[0],
			Version: "Unknown",
			Family:  determineFamily(strings.ToLower(parts[0])),
		}
	}

	return Info{
		Name:    parts[0],
		Version: parts[1],
		Family:  determineFamily(strings.ToLower(parts[0])),
	}
}

// determineFamily determines the Linux family based on the distribution ID
func determineFamily(id string) string {
	id = strings.ToLower(id)

	// Debian-based
	if id == "debian" || id == "ubuntu" || id == "mint" || id == "kali" {
		return "Debian"
	}

	// Red Hat-based
	if id == "rhel" || id == "centos" || id == "fedora" || id == "rocky" || id == "alma" {
		return "RedHat"
	}

	// SUSE-based
	if id == "suse" || id == "opensuse" || id == "sles" {
		return "SUSE"
	}

	// Arch-based
	if id == "arch" || id == "manjaro" {
		return "Arch"
	}

	return "Unknown"
}

package checks

import (
	"context"
	"time"

	"github.com/psantana5/phoenix-tools/internal/scanner/distro"
	"github.com/psantana5/phoenix-tools/internal/scanner/ssh"
)

// Severity represents the severity level of a finding
type Severity string

// Status represents the status of a check
type Status string

// Severity levels
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Status values
const (
	StatusPassed  Status = "passed"
	StatusFailed  Status = "failed"
	StatusWarning Status = "warning"
	StatusInfo    Status = "info"
)

// Finding represents a security finding
type Finding struct {
	ID          string                 `json:"id" yaml:"id" xml:"id"`
	Title       string                 `json:"title" yaml:"title" xml:"title"`
	Description string                 `json:"description" yaml:"description" xml:"description"`
	Severity    Severity               `json:"severity" yaml:"severity" xml:"severity"`
	Status      Status                 `json:"status" yaml:"status" xml:"status"`
	CheckType   string                 `json:"check_type" yaml:"check_type" xml:"check_type"`
	Timestamp   time.Time              `json:"timestamp" yaml:"timestamp" xml:"timestamp"`
	Resource    string                 `json:"resource" yaml:"resource" xml:"resource"`
	Remediation string                 `json:"remediation" yaml:"remediation" xml:"remediation"`
	Details     map[string]interface{} `json:"details,omitempty" yaml:"details,omitempty" xml:"details,omitempty"`
	References  []string               `json:"references,omitempty" yaml:"references,omitempty" xml:"references>reference,omitempty"`
}

// Check represents a security check
type Check interface {
	// Name returns the name of the check
	Name() string

	// Description returns the description of the check
	Description() string

	// Run executes the check against the target
	Run(ctx context.Context, connection ssh.Connection, distroInfo distro.Info) ([]Finding, error)
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
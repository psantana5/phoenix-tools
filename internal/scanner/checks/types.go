package checks

import "time"

// Severity represents the severity of a finding
type Severity string

const (
	// SeverityCritical represents a critical severity
	SeverityCritical Severity = "CRITICAL"
	// SeverityHigh represents a high severity
	SeverityHigh Severity = "HIGH"
	// SeverityMedium represents a medium severity
	SeverityMedium Severity = "MEDIUM"
	// SeverityLow represents a low severity
	SeverityLow Severity = "LOW"
	// SeverityInfo represents an informational severity
	SeverityInfo Severity = "INFO"
)

// Status represents the status of a finding
type Status string

const (
	// StatusPassed represents a passed check
	StatusPassed Status = "PASSED"
	// StatusFailed represents a failed check
	StatusFailed Status = "FAILED"
	// StatusWarning represents a warning
	StatusWarning Status = "WARNING"
	// StatusInfo represents an informational finding
	StatusInfo Status = "INFO"
)

// Finding represents a security finding
type Finding struct {
	ID          string                 `json:"id"`
	CheckType   string                 `json:"check_type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    Severity               `json:"severity"`
	Status      Status                 `json:"status"`
	Timestamp   time.Time              `json:"timestamp"`
	Resource    string                 `json:"resource"`
	Remediation string                 `json:"remediation,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	References  []string               `json:"references,omitempty"`
}

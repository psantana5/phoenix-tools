package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/psantana5/phoenix-tools/internal/config"
	"github.com/psantana5/phoenix-tools/internal/scanner/checks"
	"github.com/rs/zerolog/log"
)

// Server represents the API server
// Update the Server struct to include auth config
type Server struct {
	router *mux.Router
	server *http.Server
	config config.APIConfig
}

// Make sure the config.APIConfig struct includes Auth settings
// This should be in your config package
// type APIConfig struct {
//     Host string
//     Port int
//     TLS struct {
//         Enabled  bool
//         CertFile string
//         KeyFile  string
//     }
//     Auth struct {
//         Enabled bool
//         APIKeys []string
//     }
// }

// NewServer creates a new API server
func NewServer(cfg config.APIConfig) *Server {
	router := mux.NewRouter()

	server := &Server{
		router: router,
		config: cfg,
	}

	// Register routes
	server.registerRoutes()

	return server
}

// registerRoutes registers all API routes
// Update the registerRoutes method to use middlewares
func (s *Server) registerRoutes() {
	// Apply global middlewares
	s.router.Use(loggingMiddleware)
	s.router.Use(corsMiddleware)

	// API version prefix
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Apply authentication middleware to API routes
	api.Use(s.authMiddleware)

	// Health check endpoint
	api.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Scan endpoints
	scans := api.PathPrefix("/scans").Subrouter()
	scans.HandleFunc("", s.handleListScans).Methods("GET")
	scans.HandleFunc("", s.handleCreateScan).Methods("POST")
	scans.HandleFunc("/{id}", s.handleGetScan).Methods("GET")
	scans.HandleFunc("/{id}", s.handleDeleteScan).Methods("DELETE")

	// Findings endpoints
	api.HandleFunc("/scans/{id}/findings", s.handleGetFindings).Methods("GET")
	api.HandleFunc("/findings", s.handleListAllFindings).Methods("GET")
}

// Start starts the API server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Info().Msgf("API server listening on %s", addr)

	var err error
	if s.config.TLS.Enabled {
		err = s.server.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	} else {
		err = s.server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

// Shutdown gracefully shuts down the API server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// handleHealth handles the health check endpoint
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleListScans handles listing all scans
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement listing scans from database
	scans := []map[string]interface{}{
		{
			"id":        "scan-123",
			"target":    "192.168.1.100",
			"status":    "completed",
			"timestamp": time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
		},
		{
			"id":        "scan-456",
			"target":    "192.168.1.101",
			"status":    "in_progress",
			"timestamp": time.Now().Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

// handleCreateScan handles creating a new scan
func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var scanRequest struct {
		Target string   `json:"target"`
		Checks []string `json:"checks,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&scanRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// TODO: Implement actual scan creation
	response := map[string]interface{}{
		"id":        "scan-789",
		"target":    scanRequest.Target,
		"status":    "pending",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// handleGetScan handles getting a specific scan
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// TODO: Implement fetching scan from database
	scan := map[string]interface{}{
		"id":        id,
		"target":    "192.168.1.100",
		"status":    "completed",
		"timestamp": time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

// handleDeleteScan handles deleting a specific scan
func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// TODO: Implement deleting scan from database
	log.Info().Msgf("Deleted scan %s", id)

	w.WriteHeader(http.StatusNoContent)
}

// handleGetFindings handles getting findings for a specific scan
func (s *Server) handleGetFindings(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// TODO: Implement fetching findings from database
	findings := getMockFindings(id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(findings)
}

// handleListAllFindings handles listing all findings
func (s *Server) handleListAllFindings(w http.ResponseWriter, r *http.Request) {
	// Get query parameters for filtering
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	checkType := r.URL.Query().Get("check_type")

	// Get mock findings
	findings := getMockFindings("all")

	// Filter findings based on query parameters
	var filteredFindings []checks.Finding
	for _, finding := range findings {
		if (severity == "" || string(finding.Severity) == severity) &&
			(status == "" || string(finding.Status) == status) &&
			(checkType == "" || finding.CheckType == checkType) {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filteredFindings)
}

// getMockFindings returns mock findings for testing
func getMockFindings(scanID string) []checks.Finding {
	return []checks.Finding{
		{
			ID:          "finding-1",
			CheckType:   "CIS",
			Title:       "CIS 1.1.1 - Ensure mounting of cramfs filesystems is disabled",
			Description: "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems.",
			Severity:    checks.SeverityMedium,
			Status:      checks.StatusPassed,
			Timestamp:   time.Now(),
			Resource:    "Filesystem",
			Remediation: "Edit /etc/modprobe.d/CIS.conf and add 'install cramfs /bin/true'",
		},
		{
			ID:          "finding-2",
			CheckType:   "Firewall",
			Title:       "Firewall - Ensure firewall is enabled",
			Description: "A firewall is a set of rules that blocks or allows network traffic based on security criteria.",
			Severity:    checks.SeverityHigh,
			Status:      checks.StatusFailed,
			Timestamp:   time.Now(),
			Resource:    "Firewall",
			Remediation: "Enable the firewall service: 'systemctl enable firewalld && systemctl start firewalld'",
		},
		{
			ID:          "finding-3",
			CheckType:   "SSH",
			Title:       "SSH Password Authentication Enabled",
			Description: "SSH server is configured to allow password authentication, which is less secure than key-based authentication.",
			Severity:    checks.SeverityMedium,
			Status:      checks.StatusWarning,
			Timestamp:   time.Now(),
			Resource:    "SSH Configuration",
			Remediation: "Disable password authentication by setting 'PasswordAuthentication no' in /etc/ssh/sshd_config",
			References:  []string{"https://www.ssh.com/academy/ssh/sshd_config"},
		},
	}
}

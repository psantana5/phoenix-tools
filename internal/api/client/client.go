package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/psantana5/phoenix-tools/internal/scanner/checks"
)

// Client represents an API client for the Phoenix API
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
}

// NewClient creates a new API client
func NewClient(baseURL string, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiKey: apiKey,
	}
}

// ScanRequest represents a request to create a new scan
type ScanRequest struct {
	Target string   `json:"target"`
	Checks []string `json:"checks,omitempty"`
}

// ScanResponse represents a response from the scan API
type ScanResponse struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth gets the health status of the API
func (c *Client) GetHealth() (map[string]string, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/api/v1/health", c.baseURL))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// ListScans lists all scans
func (c *Client) ListScans() ([]ScanResponse, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/scans", c.baseURL), nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result []ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateScan creates a new scan
func (c *Client) CreateScan(request ScanRequest) (*ScanResponse, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/scans", c.baseURL), bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetScan gets a specific scan
func (c *Client) GetScan(id string) (*ScanResponse, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/scans/%s", c.baseURL, id), nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteScan deletes a specific scan
func (c *Client) DeleteScan(id string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/scans/%s", c.baseURL, id), nil)
	if err != nil {
		return err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// GetFindings gets findings for a specific scan
func (c *Client) GetFindings(scanID string) ([]checks.Finding, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/scans/%s/findings", c.baseURL, scanID), nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result []checks.Finding
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// ListAllFindings lists all findings with optional filtering
func (c *Client) ListAllFindings(severity, status, checkType string) ([]checks.Finding, error) {
	url := fmt.Sprintf("%s/api/v1/findings", c.baseURL)

	// Add query parameters for filtering
	first := true
	if severity != "" {
		url += "?severity=" + severity
		first = false
	}
	if status != "" {
		if first {
			url += "?"
			first = false
		} else {
			url += "&"
		}
		url += "status=" + status
	}
	if checkType != "" {
		if first {
			url += "?"
		} else {
			url += "&"
		}
		url += "check_type=" + checkType
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result []checks.Finding
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

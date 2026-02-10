package tenantclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	tenantauth "github.com/fantasticauth/tenant-sdk-go/vaultauth"
)

// Client is the HTTP client for the Fantasticauth tenant API.
type Client struct {
	HTTPClient *http.Client
	Config     *Config
	TenantSDK  *tenantauth.Client
}

// NewClient creates a new Fantasticauth tenant API client.
func NewClient(config *Config) (*Client, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}
	if config.BaseURL == "" {
		return nil, fmt.Errorf("base_url is required")
	}
	if config.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	sdkClient, err := tenantauth.New(tenantauth.Config{
		APIKey:  config.APIKey,
		BaseURL: config.BaseURL,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tenant SDK client: %w", err)
	}

	return &Client{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		Config:    config,
		TenantSDK: sdkClient,
	}, nil
}

// doRequest makes an HTTP request to the Fantasticauth API.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	url := fmt.Sprintf("%s/api/v1%s", c.Config.BaseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.Config.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", c.Config.TenantID)

	return c.HTTPClient.Do(req)
}

// Get makes a GET request
func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.doRequest(ctx, http.MethodGet, path, nil)
}

// Post makes a POST request
func (c *Client) Post(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return c.doRequest(ctx, http.MethodPost, path, body)
}

// Put makes a PUT request
func (c *Client) Put(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return c.doRequest(ctx, http.MethodPut, path, body)
}

// Patch makes a PATCH request
func (c *Client) Patch(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return c.doRequest(ctx, http.MethodPatch, path, body)
}

// Delete makes a DELETE request
func (c *Client) Delete(ctx context.Context, path string) (*http.Response, error) {
	return c.doRequest(ctx, http.MethodDelete, path, nil)
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *APIError       `json:"error,omitempty"`
}

// APIError represents an API error
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// UnmarshalResponse unmarshals an API response
func UnmarshalResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		var apiResp APIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		if apiResp.Error != nil {
			return apiResp.Error
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return err
	}

	if !apiResp.Success {
		if apiResp.Error != nil {
			return apiResp.Error
		}
		return fmt.Errorf("API request failed")
	}

	if target != nil && apiResp.Data != nil {
		return json.Unmarshal(apiResp.Data, target)
	}

	return nil
}

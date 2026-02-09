package vaultauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config holds the client configuration
type Config struct {
	APIKey       string
	BaseURL      string
	Timeout      time.Duration
	MaxRetries   int
	RetryDelay   time.Duration
	RequestID    string
	JWKSCacheTTL time.Duration
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		BaseURL:      "https://api.vault.dev",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryDelay:   time.Second,
		JWKSCacheTTL: time.Hour,
	}
}

// Client is the main Vault Auth client
type Client struct {
	config       Config
	httpClient   *http.Client
	jwks         *JWKS
	jwksFetchedAt time.Time
	
	// API sub-clients
	Users         *UsersAPI
	Organizations *OrganizationsAPI
	Sessions      *SessionsAPI
}

// New creates a new Vault Auth client
func New(config Config) (*Client, error) {
	if config.APIKey == "" {
		return nil, NewConfigurationError("API key is required")
	}
	if !strings.HasPrefix(config.APIKey, "vault_m2m_") {
		return nil, NewConfigurationError("API key must start with 'vault_m2m_'")
	}
	
	// Set defaults
	if config.BaseURL == "" {
		config.BaseURL = DefaultConfig().BaseURL
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultConfig().Timeout
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = DefaultConfig().MaxRetries
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = DefaultConfig().RetryDelay
	}
	if config.JWKSCacheTTL == 0 {
		config.JWKSCacheTTL = DefaultConfig().JWKSCacheTTL
	}
	
	client := &Client{
		config:     config,
		httpClient: &http.Client{Timeout: config.Timeout},
	}
	
	// Initialize sub-clients
	client.Users = &UsersAPI{client: client}
	client.Organizations = &OrganizationsAPI{client: client}
	client.Sessions = &SessionsAPI{client: client}
	
	return client, nil
}

// makeRequest performs an HTTP request with retry logic
func (c *Client) makeRequest(method, path string, body interface{}, queryParams map[string]string) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}
	
	url := c.config.BaseURL + path
	if len(queryParams) > 0 {
		q := make(url.Values)
		for key, value := range queryParams {
			q.Set(key, value)
		}
		url = url + "?" + q.Encode()
	}
	
	var lastErr error
	for attempt := 0; attempt < c.config.MaxRetries; attempt++ {
		req, err := http.NewRequest(method, url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "vault-auth-go/1.0.0")
		if c.config.RequestID != "" {
			req.Header.Set("X-Request-ID", c.config.RequestID)
		}
		
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < c.config.MaxRetries-1 {
				time.Sleep(c.config.RetryDelay * time.Duration(1<<attempt))
				continue
			}
			return nil, lastErr
		}
		defer resp.Body.Close()
		
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		
		// Handle response
		requestID := resp.Header.Get("X-Request-ID")
		result, err := c.handleResponse(resp.StatusCode, respBody, &requestID)
		if err != nil {
			// Check if we should retry
			if _, ok := err.(*ServerError); ok && attempt < c.config.MaxRetries-1 {
				lastErr = err
				time.Sleep(c.config.RetryDelay * time.Duration(1<<attempt))
				continue
			}
			return nil, err
		}
		
		return result, nil
	}
	
	return nil, lastErr
}

// handleResponse processes the HTTP response and returns appropriate errors
func (c *Client) handleResponse(statusCode int, body []byte, requestID *string) ([]byte, error) {
	if statusCode == http.StatusOK || statusCode == http.StatusCreated {
		return body, nil
	}
	if statusCode == http.StatusNoContent {
		return []byte{}, nil
	}
	
	var errorResp struct {
		Message string                 `json:"message"`
		Code    *string                `json:"code,omitempty"`
		Details map[string]interface{} `json:"details,omitempty"`
	}
	if err := json.Unmarshal(body, &errorResp); err != nil {
		errorResp.Message = string(body)
	}
	
	switch statusCode {
	case http.StatusBadRequest:
		fieldErrors := make(map[string]string)
		if errorResp.Details != nil {
			if fields, ok := errorResp.Details["fields"].(map[string]interface{}); ok {
				for k, v := range fields {
					if s, ok := v.(string); ok {
						fieldErrors[k] = s
					}
				}
			}
		}
		return nil, NewValidationError(errorResp.Message, fieldErrors, errorResp.Code, errorResp.Details, requestID)
	case http.StatusUnauthorized:
		return nil, NewAuthenticationError(errorResp.Message, errorResp.Code, errorResp.Details, requestID)
	case http.StatusForbidden:
		return nil, NewAuthorizationError(errorResp.Message, errorResp.Code, errorResp.Details, requestID)
	case http.StatusNotFound:
		return nil, NewNotFoundError(errorResp.Message, nil, nil, errorResp.Code, errorResp.Details, requestID)
	case http.StatusTooManyRequests:
		var retryAfter *int
		return nil, NewRateLimitError(errorResp.Message, retryAfter, errorResp.Code, errorResp.Details, requestID)
	default:
		if statusCode >= 500 {
			return nil, NewServerError(errorResp.Message, statusCode, errorResp.Code, errorResp.Details, requestID)
		}
		return nil, &VaultAuthError{
			Message:    errorResp.Message,
			StatusCode: statusCode,
			ErrorCode:  errorResp.Code,
			Details:    errorResp.Details,
			RequestID:  requestID,
		}
	}
}

// getJWKS fetches and caches the JWKS
func (c *Client) getJWKS() (*JWKS, error) {
	now := time.Now()
	if c.jwks != nil && now.Sub(c.jwksFetchedAt) < c.config.JWKSCacheTTL {
		return c.jwks, nil
	}
	
	body, err := c.makeRequest("GET", "/.well-known/jwks.json", nil, nil)
	if err != nil {
		return nil, err
	}
	
	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}
	
	c.jwks = &jwks
	c.jwksFetchedAt = now
	return &jwks, nil
}

// VerifyToken verifies a JWT token and returns the associated user
func (c *Client) VerifyToken(token string) (*User, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, NewInvalidTokenError("Invalid token format", nil, nil, nil)
	}
	
	// Decode header to get key ID
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, NewInvalidTokenError(fmt.Sprintf("Failed to decode header: %v", err), nil, nil, nil)
	}
	
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, NewInvalidTokenError(fmt.Sprintf("Failed to unmarshal header: %v", err), nil, nil, nil)
	}
	
	if header.Kid == "" {
		return nil, NewInvalidTokenError("Token missing key ID", nil, nil, nil)
	}
	
	// Get JWKS
	_, err = c.getJWKS()
	if err != nil {
		return nil, err
	}
	
	// Decode payload to check expiration
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, NewInvalidTokenError(fmt.Sprintf("Failed to decode payload: %v", err), nil, nil, nil)
	}
	
	var payload struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, NewInvalidTokenError(fmt.Sprintf("Failed to unmarshal payload: %v", err), nil, nil, nil)
	}
	
	if payload.Exp > 0 && payload.Exp < time.Now().Unix() {
		return nil, NewTokenExpiredError("", nil, nil, nil)
	}
	
	// Verify token via API
	reqBody := VerifyTokenRequest{Token: token}
	respBody, err := c.makeRequest("POST", "/api/v1/auth/verify", reqBody, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[User]
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// DecodeToken decodes a JWT token without verification
func (c *Client) DecodeToken(token string) (*TokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, NewInvalidTokenError("Invalid token format", nil, nil, nil)
	}
	
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, NewInvalidTokenError(fmt.Sprintf("Failed to decode payload: %v", err), nil, nil, nil)
	}
	
	var payload TokenPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, NewInvalidTokenError(fmt.Sprintf("Failed to unmarshal payload: %v", err), nil, nil, nil)
	}
	
	return &payload, nil
}

// GetJWKS returns the JWKS
func (c *Client) GetJWKS() (*JWKS, error) {
	return c.getJWKS()
}

// HealthCheck checks the Vault API health status
func (c *Client) HealthCheck() (map[string]interface{}, error) {
	body, err := c.makeRequest("GET", "/health", nil, nil)
	if err != nil {
		return nil, err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return result, nil
}

// UsersAPI handles user-related operations
type UsersAPI struct {
	client *Client
}

// Get retrieves a user by ID
func (u *UsersAPI) Get(userID string) (*User, error) {
	body, err := u.client.makeRequest("GET", fmt.Sprintf("/api/v1/users/%s", userID), nil, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[User]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// GetByEmail retrieves a user by email address
func (u *UsersAPI) GetByEmail(email string) (*User, error) {
	body, err := u.client.makeRequest("GET", fmt.Sprintf("/api/v1/users/email/%s", email), nil, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[User]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// List retrieves a list of users
func (u *UsersAPI) List(page, perPage int, status, organizationID *string) (*PaginatedResponse[User], error) {
	params := map[string]string{
		"page":     strconv.Itoa(page),
		"per_page": strconv.Itoa(perPage),
	}
	if status != nil {
		params["status"] = *status
	}
	if organizationID != nil {
		params["organization_id"] = *organizationID
	}
	
	body, err := u.client.makeRequest("GET", "/api/v1/users", nil, params)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[UserListResponse]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &PaginatedResponse[User]{
		Data:    resp.Data.Users,
		Total:   resp.Data.Total,
		Page:    resp.Data.Page,
		PerPage: resp.Data.PerPage,
		HasMore: resp.Data.HasMore,
	}, nil
}

// Create creates a new user
func (u *UsersAPI) Create(req CreateUserRequest) (*User, error) {
	body, err := u.client.makeRequest("POST", "/api/v1/users", req, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[User]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// Update updates a user
func (u *UsersAPI) Update(userID string, req UpdateUserRequest) (*User, error) {
	body, err := u.client.makeRequest("PATCH", fmt.Sprintf("/api/v1/users/%s", userID), req, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[User]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// Delete deletes a user
func (u *UsersAPI) Delete(userID string) error {
	_, err := u.client.makeRequest("DELETE", fmt.Sprintf("/api/v1/users/%s", userID), nil, nil)
	return err
}

// UpdatePassword updates a user's password
func (u *UsersAPI) UpdatePassword(userID string, password string) error {
	req := map[string]string{"password": password}
	_, err := u.client.makeRequest("PATCH", fmt.Sprintf("/api/v1/users/%s/password", userID), req, nil)
	return err
}

// GetOrganizations retrieves a user's organizations
func (u *UsersAPI) GetOrganizations(userID string) ([]OrganizationMembership, error) {
	body, err := u.client.makeRequest("GET", fmt.Sprintf("/api/v1/users/%s/organizations", userID), nil, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[struct {
		Memberships []OrganizationMembership `json:"memberships"`
	}]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return resp.Data.Memberships, nil
}

// GetSessions retrieves a user's sessions
func (u *UsersAPI) GetSessions(userID string) ([]Session, error) {
	body, err := u.client.makeRequest("GET", fmt.Sprintf("/api/v1/users/%s/sessions", userID), nil, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[SessionListResponse]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return resp.Data.Sessions, nil
}

// OrganizationsAPI handles organization-related operations
type OrganizationsAPI struct {
	client *Client
}

// Get retrieves an organization by ID
func (o *OrganizationsAPI) Get(orgID string) (*Organization, error) {
	body, err := o.client.makeRequest("GET", fmt.Sprintf("/api/v1/organizations/%s", orgID), nil, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[Organization]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// GetBySlug retrieves an organization by slug
func (o *OrganizationsAPI) GetBySlug(slug string) (*Organization, error) {
	body, err := o.client.makeRequest("GET", fmt.Sprintf("/api/v1/organizations/slug/%s", slug), nil, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[Organization]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// List retrieves a list of organizations
func (o *OrganizationsAPI) List(page, perPage int) (*PaginatedResponse[Organization], error) {
	params := map[string]string{
		"page":     strconv.Itoa(page),
		"per_page": strconv.Itoa(perPage),
	}
	
	body, err := o.client.makeRequest("GET", "/api/v1/organizations", nil, params)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[OrganizationListResponse]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &PaginatedResponse[Organization]{
		Data:    resp.Data.Organizations,
		Total:   resp.Data.Total,
		Page:    resp.Data.Page,
		PerPage: resp.Data.PerPage,
		HasMore: resp.Data.HasMore,
	}, nil
}

// Create creates a new organization
func (o *OrganizationsAPI) Create(req CreateOrganizationRequest) (*Organization, error) {
	body, err := o.client.makeRequest("POST", "/api/v1/organizations", req, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[Organization]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// Update updates an organization
func (o *OrganizationsAPI) Update(orgID string, req UpdateOrganizationRequest) (*Organization, error) {
	body, err := o.client.makeRequest("PATCH", fmt.Sprintf("/api/v1/organizations/%s", orgID), req, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[Organization]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// Delete deletes an organization
func (o *OrganizationsAPI) Delete(orgID string) error {
	_, err := o.client.makeRequest("DELETE", fmt.Sprintf("/api/v1/organizations/%s", orgID), nil, nil)
	return err
}

// GetMembers retrieves organization members
func (o *OrganizationsAPI) GetMembers(orgID string) ([]OrganizationMembership, error) {
	body, err := o.client.makeRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/members", orgID), nil, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[MembershipListResponse]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return resp.Data.Members, nil
}

// AddMember adds a member to an organization
func (o *OrganizationsAPI) AddMember(orgID string, req AddMemberRequest) (*OrganizationMembership, error) {
	body, err := o.client.makeRequest("POST", fmt.Sprintf("/api/v1/organizations/%s/members", orgID), req, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[OrganizationMembership]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// RemoveMember removes a member from an organization
func (o *OrganizationsAPI) RemoveMember(orgID, userID string) error {
	_, err := o.client.makeRequest("DELETE", fmt.Sprintf("/api/v1/organizations/%s/members/%s", orgID, userID), nil, nil)
	return err
}

// UpdateMemberRole updates a member's role
func (o *OrganizationsAPI) UpdateMemberRole(orgID, userID string, req UpdateMemberRoleRequest) (*OrganizationMembership, error) {
	body, err := o.client.makeRequest("PATCH", fmt.Sprintf("/api/v1/organizations/%s/members/%s", orgID, userID), req, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[OrganizationMembership]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// SessionsAPI handles session-related operations
type SessionsAPI struct {
	client *Client
}

// Get retrieves a session by ID
func (s *SessionsAPI) Get(sessionID string) (*Session, error) {
	body, err := s.client.makeRequest("GET", fmt.Sprintf("/api/v1/sessions/%s", sessionID), nil, nil)
	if err != nil {
		return nil, err
	}
	
	var resp APIResponse[Session]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp.Data, nil
}

// Revoke revokes a session
func (s *SessionsAPI) Revoke(sessionID string) error {
	_, err := s.client.makeRequest("POST", fmt.Sprintf("/api/v1/sessions/%s/revoke", sessionID), nil, nil)
	return err
}

// RevokeAllUserSessions revokes all sessions for a user
func (s *SessionsAPI) RevokeAllUserSessions(userID string) error {
	_, err := s.client.makeRequest("POST", fmt.Sprintf("/api/v1/users/%s/sessions/revoke-all", userID), nil, nil)
	return err
}

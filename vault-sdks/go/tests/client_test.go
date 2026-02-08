package vaultauth_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vault-dev/vaultauth"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name      string
		config    vaultauth.Config
		wantError bool
		errType   string
	}{
		{
			name: "valid config",
			config: vaultauth.Config{
				APIKey: "vault_m2m_test_key",
			},
			wantError: false,
		},
		{
			name: "missing API key",
			config: vaultauth.Config{
				APIKey: "",
			},
			wantError: true,
			errType:   "ConfigurationError",
		},
		{
			name: "invalid API key format",
			config: vaultauth.Config{
				APIKey: "invalid_key",
			},
			wantError: true,
			errType:   "ConfigurationError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vaultauth.New(tt.config)
			if tt.wantError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyToken(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []map[string]interface{}{
					{"kty": "RSA", "kid": "key1", "alg": "RS256"},
				},
			})
		case "/api/v1/auth/verify":
			var req struct {
				Token string `json:"token"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":             "user_123",
					"email":          "test@example.com",
					"email_verified": true,
					"status":         "active",
					"first_name":     "Test",
					"last_name":      "User",
				},
			})
		}
	}))
	defer server.Close()

	client, _ := vaultauth.New(vaultauth.Config{
		APIKey:     "vault_m2m_test_key",
		BaseURL:    server.URL,
		MaxRetries: 1,
	})

	// Create a dummy JWT with future expiration
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"key1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user_123","exp":9999999999}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	token := header + "." + payload + "." + signature

	user, err := client.VerifyToken(token)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if user.ID != "user_123" {
		t.Errorf("Expected user ID 'user_123', got '%s'", user.ID)
	}
	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}
	if user.FullName() != "Test User" {
		t.Errorf("Expected full name 'Test User', got '%s'", user.FullName())
	}
}

func TestUsersGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users/user_123" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":     "user_123",
					"email":  "test@example.com",
					"status": "active",
				},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "User not found",
				"code":    "not_found",
			})
		}
	}))
	defer server.Close()

	client, _ := vaultauth.New(vaultauth.Config{
		APIKey:  "vault_m2m_test_key",
		BaseURL: server.URL,
	})

	// Test successful get
	user, err := client.Users.Get("user_123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if user.ID != "user_123" {
		t.Errorf("Expected user ID 'user_123', got '%s'", user.ID)
	}

	// Test not found
	_, err = client.Users.Get("notfound")
	if err == nil {
		t.Error("Expected error for not found user")
	}
	if _, ok := err.(*vaultauth.NotFoundError); !ok {
		t.Errorf("Expected NotFoundError, got %T", err)
	}
}

func TestUsersCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/api/v1/users" {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":     "user_new",
					"email":  "new@example.com",
					"status": "pending_verification",
				},
			})
		}
	}))
	defer server.Close()

	client, _ := vaultauth.New(vaultauth.Config{
		APIKey:  "vault_m2m_test_key",
		BaseURL: server.URL,
	})

	user, err := client.Users.Create(vaultauth.CreateUserRequest{
		Email:    "new@example.com",
		Password: "secure_password",
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if user.ID != "user_new" {
		t.Errorf("Expected user ID 'user_new', got '%s'", user.ID)
	}
}

func TestUsersList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"users": []map[string]interface{}{
						{"id": "user_1", "email": "user1@example.com"},
						{"id": "user_2", "email": "user2@example.com"},
					},
					"total":    2,
					"page":     1,
					"per_page": 20,
					"has_more": false,
				},
			})
		}
	}))
	defer server.Close()

	client, _ := vaultauth.New(vaultauth.Config{
		APIKey:  "vault_m2m_test_key",
		BaseURL: server.URL,
	})

	result, err := client.Users.List(1, 20, nil, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(result.Data) != 2 {
		t.Errorf("Expected 2 users, got %d", len(result.Data))
	}
	if result.Total != 2 {
		t.Errorf("Expected total 2, got %d", result.Total)
	}
}

func TestRetryLogic(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Internal server error",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":    "user_123",
				"email": "test@example.com",
			},
		})
	}))
	defer server.Close()

	client, _ := vaultauth.New(vaultauth.Config{
		APIKey:     "vault_m2m_test_key",
		BaseURL:    server.URL,
		MaxRetries: 3,
		RetryDelay: 10 * time.Millisecond,
	})

	user, err := client.Users.Get("user_123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if user.ID != "user_123" {
		t.Errorf("Expected user ID 'user_123', got '%s'", user.ID)
	}
	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", attempts)
	}
}

func TestOrganizationsGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/organizations/org_123" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":     "org_123",
					"name":   "Test Org",
					"slug":   "test-org",
					"status": "active",
				},
			})
		}
	}))
	defer server.Close()

	client, _ := vaultauth.New(vaultauth.Config{
		APIKey:  "vault_m2m_test_key",
		BaseURL: server.URL,
	})

	org, err := client.Organizations.Get("org_123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if org.ID != "org_123" {
		t.Errorf("Expected org ID 'org_123', got '%s'", org.ID)
	}
	if org.Name != "Test Org" {
		t.Errorf("Expected name 'Test Org', got '%s'", org.Name)
	}
}

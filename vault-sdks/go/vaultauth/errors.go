package vaultauth

import (
	"fmt"
)

// VaultAuthError is the base error for Vault Auth SDK
type VaultAuthError struct {
	Message    string
	StatusCode int
	ErrorCode  *string
	Details    map[string]interface{}
	RequestID  *string
}

func (e *VaultAuthError) Error() string {
	parts := []string{e.Message}
	if e.ErrorCode != nil {
		parts = append(parts, fmt.Sprintf("(code: %s)", *e.ErrorCode))
	}
	if e.RequestID != nil {
		parts = append(parts, fmt.Sprintf("[request_id: %s]", *e.RequestID))
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += " " + p
	}
	return result
}

// AuthenticationError is raised when authentication fails (401)
type AuthenticationError struct {
	VaultAuthError
}

// NewAuthenticationError creates a new AuthenticationError
func NewAuthenticationError(message string, code *string, details map[string]interface{}, requestID *string) *AuthenticationError {
	if message == "" {
		message = "Authentication failed"
	}
	return &AuthenticationError{
		VaultAuthError: VaultAuthError{
			Message:    message,
			StatusCode: 401,
			ErrorCode:  code,
			Details:    details,
			RequestID:  requestID,
		},
	}
}

// AuthorizationError is raised when user lacks permission (403)
type AuthorizationError struct {
	VaultAuthError
}

// NewAuthorizationError creates a new AuthorizationError
func NewAuthorizationError(message string, code *string, details map[string]interface{}, requestID *string) *AuthorizationError {
	if message == "" {
		message = "Not authorized"
	}
	return &AuthorizationError{
		VaultAuthError: VaultAuthError{
			Message:    message,
			StatusCode: 403,
			ErrorCode:  code,
			Details:    details,
			RequestID:  requestID,
		},
	}
}

// NotFoundError is raised when resource is not found (404)
type NotFoundError struct {
	VaultAuthError
	ResourceType *string
	ResourceID   *string
}

// NewNotFoundError creates a new NotFoundError
func NewNotFoundError(message string, resourceType, resourceID *string, code *string, details map[string]interface{}, requestID *string) *NotFoundError {
	if message == "" {
		if resourceType != nil && resourceID != nil {
			message = fmt.Sprintf("%s '%s' not found", *resourceType, *resourceID)
		} else {
			message = "Resource not found"
		}
	}
	return &NotFoundError{
		VaultAuthError: VaultAuthError{
			Message:    message,
			StatusCode: 404,
			ErrorCode:  code,
			Details:    details,
			RequestID:  requestID,
		},
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
}

// RateLimitError is raised when rate limit is exceeded (429)
type RateLimitError struct {
	VaultAuthError
	RetryAfter *int
}

// NewRateLimitError creates a new RateLimitError
func NewRateLimitError(message string, retryAfter *int, code *string, details map[string]interface{}, requestID *string) *RateLimitError {
	if message == "" {
		message = "Rate limit exceeded"
	}
	return &RateLimitError{
		VaultAuthError: VaultAuthError{
			Message:    message,
			StatusCode: 429,
			ErrorCode:  code,
			Details:    details,
			RequestID:  requestID,
		},
		RetryAfter: retryAfter,
	}
}

// ServerError is raised when server returns 5xx error
type ServerError struct {
	VaultAuthError
}

// NewServerError creates a new ServerError
func NewServerError(message string, statusCode int, code *string, details map[string]interface{}, requestID *string) *ServerError {
	if message == "" {
		message = "Internal server error"
	}
	if statusCode == 0 {
		statusCode = 500
	}
	return &ServerError{
		VaultAuthError: VaultAuthError{
			Message:    message,
			StatusCode: statusCode,
			ErrorCode:  code,
			Details:    details,
			RequestID:  requestID,
		},
	}
}

// ValidationError is raised when request validation fails (400)
type ValidationError struct {
	VaultAuthError
	FieldErrors map[string]string
}

// NewValidationError creates a new ValidationError
func NewValidationError(message string, fieldErrors map[string]string, code *string, details map[string]interface{}, requestID *string) *ValidationError {
	if message == "" {
		message = "Validation failed"
	}
	return &ValidationError{
		VaultAuthError: VaultAuthError{
			Message:    message,
			StatusCode: 400,
			ErrorCode:  code,
			Details:    details,
			RequestID:  requestID,
		},
		FieldErrors: fieldErrors,
	}
}

// TokenExpiredError is raised when JWT token is expired
type TokenExpiredError struct {
	AuthenticationError
}

// NewTokenExpiredError creates a new TokenExpiredError
func NewTokenExpiredError(message string, code *string, details map[string]interface{}, requestID *string) *TokenExpiredError {
	if message == "" {
		message = "Token has expired"
	}
	return &TokenExpiredError{
		AuthenticationError: *NewAuthenticationError(message, code, details, requestID),
	}
}

// InvalidTokenError is raised when JWT token is invalid
type InvalidTokenError struct {
	AuthenticationError
}

// NewInvalidTokenError creates a new InvalidTokenError
func NewInvalidTokenError(message string, code *string, details map[string]interface{}, requestID *string) *InvalidTokenError {
	if message == "" {
		message = "Invalid token"
	}
	return &InvalidTokenError{
		AuthenticationError: *NewAuthenticationError(message, code, details, requestID),
	}
}

// ConfigurationError is raised when SDK is misconfigured
type ConfigurationError struct {
	VaultAuthError
}

// NewConfigurationError creates a new ConfigurationError
func NewConfigurationError(message string) *ConfigurationError {
	if message == "" {
		message = "Configuration error"
	}
	return &ConfigurationError{
		VaultAuthError: VaultAuthError{
			Message: message,
		},
	}
}

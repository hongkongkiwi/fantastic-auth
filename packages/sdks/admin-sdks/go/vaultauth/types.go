package vaultauth

import (
	"time"
)

// UserStatus represents the status of a user
type UserStatus string

const (
	UserStatusActive              UserStatus = "active"
	UserStatusInactive            UserStatus = "inactive"
	UserStatusSuspended           UserStatus = "suspended"
	UserStatusPendingVerification UserStatus = "pending_verification"
)

// OrganizationRole represents the role in an organization
type OrganizationRole string

const (
	OrganizationRoleOwner  OrganizationRole = "owner"
	OrganizationRoleAdmin  OrganizationRole = "admin"
	OrganizationRoleMember OrganizationRole = "member"
)

// User represents a Vault user
type User struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Status        UserStatus             `json:"status"`
	FirstName     *string                `json:"first_name,omitempty"`
	LastName      *string                `json:"last_name,omitempty"`
	AvatarURL     *string                `json:"avatar_url,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt     *time.Time             `json:"created_at,omitempty"`
	UpdatedAt     *time.Time             `json:"updated_at,omitempty"`
	LastLoginAt   *time.Time             `json:"last_login_at,omitempty"`
}

// FullName returns the user's full name
func (u *User) FullName() string {
	if u.FirstName != nil && u.LastName != nil {
		return *u.FirstName + " " + *u.LastName
	}
	if u.FirstName != nil {
		return *u.FirstName
	}
	if u.LastName != nil {
		return *u.LastName
	}
	return u.Email
}

// Organization represents a Vault organization
type Organization struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Slug      string                 `json:"slug"`
	Status    string                 `json:"status"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt *time.Time             `json:"created_at,omitempty"`
	UpdatedAt *time.Time             `json:"updated_at,omitempty"`
}

// OrganizationMembership represents a user's membership in an organization
type OrganizationMembership struct {
	ID             string            `json:"id"`
	UserID         string            `json:"user_id"`
	OrganizationID string            `json:"organization_id"`
	Role           OrganizationRole  `json:"role"`
	JoinedAt       *time.Time        `json:"joined_at,omitempty"`
	Organization   *Organization     `json:"organization,omitempty"`
}

// Session represents a user session
type Session struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	IPAddress  *string    `json:"ip_address,omitempty"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// IsActive checks if the session is active
func (s *Session) IsActive() bool {
	if s.RevokedAt != nil {
		return false
	}
	if s.ExpiresAt != nil && s.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}

// JWKSKey represents a JSON Web Key
type JWKSKey struct {
	Kty string  `json:"kty"`
	Kid string  `json:"kid"`
	Use *string `json:"use,omitempty"`
	Alg *string `json:"alg,omitempty"`
	N   *string `json:"n,omitempty"`  // RSA modulus
	E   *string `json:"e,omitempty"`  // RSA exponent
	X   *string `json:"x,omitempty"`  // EC x coordinate
	Y   *string `json:"y,omitempty"`  // EC y coordinate
	Crv *string `json:"crv,omitempty"` // EC curve
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWKSKey `json:"keys"`
}

// TokenPayload represents a decoded JWT token payload
type TokenPayload struct {
	Sub           string  `json:"sub"` // User ID
	Exp           int64   `json:"exp"` // Expiration timestamp
	Iat           int64   `json:"iat"` // Issued at timestamp
	Iss           string  `json:"iss"` // Issuer
	Aud           string  `json:"aud"` // Audience
	Jti           string  `json:"jti"` // JWT ID
	Email         *string `json:"email,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`
	OrgID         *string `json:"org_id,omitempty"`
	OrgRole       *string `json:"org_role,omitempty"`
}

// UserID returns the user ID from the subject claim
func (t *TokenPayload) UserID() string {
	return t.Sub
}

// PaginatedResponse is a generic paginated response wrapper
type PaginatedResponse[T any] struct {
	Data     []T  `json:"data"`
	Total    int  `json:"total"`
	Page     int  `json:"page"`
	PerPage  int  `json:"per_page"`
	HasMore  bool `json:"has_more"`
}

// UserListResponse represents a list of users response
type UserListResponse struct {
	Users    []User `json:"users"`
	Total    int    `json:"total"`
	Page     int    `json:"page"`
	PerPage  int    `json:"per_page"`
	HasMore  bool   `json:"has_more"`
}

// OrganizationListResponse represents a list of organizations response
type OrganizationListResponse struct {
	Organizations []Organization `json:"organizations"`
	Total         int            `json:"total"`
	Page          int            `json:"page"`
	PerPage       int            `json:"per_page"`
	HasMore       bool           `json:"has_more"`
}

// MembershipListResponse represents organization members response
type MembershipListResponse struct {
	Members []OrganizationMembership `json:"members"`
}

// SessionListResponse represents user sessions response
type SessionListResponse struct {
	Sessions []Session `json:"sessions"`
}

// APIResponse is a generic API response wrapper
type APIResponse[T any] struct {
	Data    T                 `json:"data"`
	Message *string           `json:"message,omitempty"`
	Code    *string           `json:"code,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	Email          string                 `json:"email"`
	Password       string                 `json:"password"`
	FirstName      *string                `json:"first_name,omitempty"`
	LastName       *string                `json:"last_name,omitempty"`
	EmailVerified  bool                   `json:"email_verified,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	FirstName *string                `json:"first_name,omitempty"`
	LastName  *string                `json:"last_name,omitempty"`
	Email     *string                `json:"email,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// CreateOrganizationRequest represents a request to create an organization
type CreateOrganizationRequest struct {
	Name     string                 `json:"name"`
	Slug     *string                `json:"slug,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateOrganizationRequest represents a request to update an organization
type UpdateOrganizationRequest struct {
	Name     *string                `json:"name,omitempty"`
	Slug     *string                `json:"slug,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// AddMemberRequest represents a request to add a member to an organization
type AddMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role,omitempty"`
}

// UpdateMemberRoleRequest represents a request to update a member's role
type UpdateMemberRoleRequest struct {
	Role string `json:"role"`
}

// VerifyTokenRequest represents a token verification request
type VerifyTokenRequest struct {
	Token string `json:"token"`
}

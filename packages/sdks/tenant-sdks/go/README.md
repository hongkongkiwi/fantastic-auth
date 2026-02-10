# Fantasticauth Tenant Go SDK

Official Go SDK for Fantasticauth tenant authentication and management.

## Installation

```bash
go get github.com/fantasticauth/tenant-sdk-go
```

## Quick Start

```go
package main

import (
    "log"
    "github.com/fantasticauth/tenant-sdk-go/vaultauth"
)

func main() {
    // Create client
    config := vaultauth.Config{
        APIKey:  "vault_m2m_your_key_here",
        BaseURL: "https://api.fantasticauth.com",
    }
    
    client, err := vaultauth.New(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Verify a JWT token
    user, err := client.VerifyToken("eyJhbGciOiJSUzI1NiIs...")
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("User: %s (%s)", user.FullName(), user.Email)
    
    // Get user by ID
    user, err = client.Users.Get("user_123")
    if err != nil {
        log.Fatal(err)
    }
}
```

## Configuration

```go
config := vaultauth.Config{
    APIKey:       "vault_m2m_...",           // Required
    BaseURL:      "https://api.fantasticauth.com",   // Default
    Timeout:      30 * time.Second,          // Default
    MaxRetries:   3,                         // Default
    RetryDelay:   time.Second,               // Default
    RequestID:    "trace-123",               // Optional
    JWKSCacheTTL: time.Hour,                 // Default
}
```

## User Management

```go
// Get user by ID
user, err := client.Users.Get("user_123")

// Get user by email
user, err := client.Users.GetByEmail("user@example.com")

// Create user
firstName := "John"
lastName := "Doe"
newUser, err := client.Users.Create(vaultauth.CreateUserRequest{
    Email:     "new@example.com",
    Password:  "secure_password",
    FirstName: &firstName,
    LastName:  &lastName,
})

// List users
usersPage, err := client.Users.List(1, 20, nil, nil)
if err != nil {
    log.Fatal(err)
}
for _, user := range usersPage.Data {
    log.Println(user.Email)
}

// Update user
newFirstName := "Jane"
updatedUser, err := client.Users.Update("user_123", vaultauth.UpdateUserRequest{
    FirstName: &newFirstName,
})

// Delete user
err = client.Users.Delete("user_123")

// Get user's organizations
memberships, err := client.Users.GetOrganizations("user_123")
for _, m := range memberships {
    log.Printf("%s - %s", m.Organization.Name, m.Role)
}

// Get user's sessions
sessions, err := client.Users.GetSessions("user_123")
```

## Organization Management

```go
// Create organization
slug := "acme-corp"
org, err := client.Organizations.Create(vaultauth.CreateOrganizationRequest{
    Name: "Acme Corp",
    Slug: &slug,
})

// Get organization
org, err := client.Organizations.Get("org_123")

// Update organization
newName := "Acme Corporation"
org, err = client.Organizations.Update("org_123", vaultauth.UpdateOrganizationRequest{
    Name: &newName,
})

// Delete organization
err = client.Organizations.Delete("org_123")

// Manage members
member, err := client.Organizations.AddMember("org_123", vaultauth.AddMemberRequest{
    UserID: "user_123",
    Role:   "admin",
})
err = client.Organizations.UpdateMemberRole("org_123", "user_123", vaultauth.UpdateMemberRoleRequest{
    Role: "owner",
})
err = client.Organizations.RemoveMember("org_123", "user_123")

// Get members
members, err := client.Organizations.GetMembers("org_123")
```

## Session Management

```go
// Get session
session, err := client.Sessions.Get("session_123")

// Revoke session
err = client.Sessions.Revoke("session_123")

// Revoke all user sessions
err = client.Sessions.RevokeAllUserSessions("user_123")
```

## Gin Integration

```go
package main

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/fantasticauth/tenant-sdk-go/vaultauth"
    "github.com/fantasticauth/tenant-sdk-go/vaultauth/middleware"
)

func main() {
    config := vaultauth.Config{
        APIKey:  "vault_m2m_...",
        BaseURL: "https://api.fantasticauth.com",
    }
    client, _ := vaultauth.New(config)
    
    r := gin.Default()
    
    // Apply middleware
    r.Use(middleware.MiddlewareGin(client, "/health", "/public"))
    
    // Protected route
    r.GET("/protected", func(c *gin.Context) {
        user, exists := middleware.GetCurrentUser(c)
        if !exists {
            c.JSON(401, gin.H{"error": "Not authenticated"})
            return
        }
        c.JSON(200, gin.H{"email": user.Email})
    })
    
    // Route with auth requirement
    r.GET("/admin", middleware.RequireAuth([]string{"admin", "owner"}, false), func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Admin area"})
    })
    
    r.Run()
}
```

## Echo Integration

```go
package main

import (
    "net/http"
    "github.com/labstack/echo/v4"
    "github.com/fantasticauth/tenant-sdk-go/vaultauth"
    "github.com/fantasticauth/tenant-sdk-go/vaultauth/middleware"
)

func main() {
    config := vaultauth.Config{
        APIKey:  "vault_m2m_...",
        BaseURL: "https://api.fantasticauth.com",
    }
    client, _ := vaultauth.New(config)
    
    e := echo.New()
    
    // Apply middleware
    e.Use(middleware.MiddlewareEcho(client, "/health"))
    
    // Protected route
    e.GET("/protected", func(c echo.Context) error {
        user, exists := middleware.GetCurrentUserEcho(c)
        if !exists {
            return c.JSON(401, map[string]string{"error": "Not authenticated"})
        }
        return c.JSON(200, map[string]string{"email": user.Email})
    })
    
    // Route with auth requirement
    e.GET("/admin", func(c echo.Context) error {
        return c.JSON(200, map[string]string{"message": "Admin area"})
    }, middleware.RequireAuthEcho([]string{"admin"}, false))
    
    e.Start(":8080")
}
```

## Standard Library Integration

```go
package main

import (
    "fmt"
    "net/http"
    "github.com/fantasticauth/tenant-sdk-go/vaultauth"
    "github.com/fantasticauth/tenant-sdk-go/vaultauth/middleware"
)

func main() {
    config := vaultauth.Config{
        APIKey:  "vault_m2m_...",
        BaseURL: "https://api.fantasticauth.com",
    }
    client, _ := vaultauth.New(config)
    
    // Create mux
    mux := http.NewServeMux()
    
    // Public route
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK"))
    })
    
    // Protected route
    protected := middleware.MiddlewareStdlib(client, "/health")(http.HandlerFunc(
        func(w http.ResponseWriter, r *http.Request) {
            user, exists := middleware.GetCurrentUserStdlib(r.Context())
            if !exists {
                http.Error(w, "Not authenticated", 401)
                return
            }
            fmt.Fprintf(w, "Hello %s", user.Email)
        },
    ))
    mux.Handle("/protected", protected)
    
    http.ListenAndServe(":8080", mux)
}
```

## Error Handling

```go
user, err := client.Users.Get("user_123")
if err != nil {
    switch e := err.(type) {
    case *vaultauth.NotFoundError:
        log.Printf("User not found: %s", e.ResourceID)
    case *vaultauth.AuthenticationError:
        log.Printf("Authentication failed: %s", e.Message)
    case *vaultauth.RateLimitError:
        log.Printf("Rate limited, retry after: %d seconds", *e.RetryAfter)
    case *vaultauth.ValidationError:
        log.Printf("Validation failed: %v", e.FieldErrors)
    default:
        log.Printf("Error: %v", err)
    }
}
```

## Token Verification

```go
// Verify token and get user
user, err := client.VerifyToken("eyJhbGc...")

// Decode token without verification
payload, err := client.DecodeToken("eyJhbGc...")
log.Printf("User ID: %s", payload.UserID())
log.Printf("Org ID: %s", *payload.OrgID)
log.Printf("Org Role: %s", *payload.OrgRole)

// Get JWKS for manual verification
jwks, err := client.GetJWKS()
for _, key := range jwks.Keys {
    log.Printf("Key ID: %s, Algorithm: %s", key.Kid, *key.Alg)
}
```

## License

MIT License - see LICENSE file for details.

package vaultauth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// ContextKeyUser is the key for storing user in gin context
	ContextKeyUser = "vault_user"
	// ContextKeyToken is the key for storing token in gin context
	ContextKeyToken = "vault_token"
	// ContextKeyTokenPayload is the key for storing token payload in gin context
	ContextKeyTokenPayload = "vault_token_payload"
)

// MiddlewareGin creates a Gin middleware for Vault authentication
func MiddlewareGin(client *Client, excludedPaths ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip excluded paths
		for _, path := range excludedPaths {
			if strings.HasPrefix(c.Request.URL.Path, path) {
				c.Next()
				return
			}
		}
		
		// Extract token
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.Next()
			return
		}
		
		token := authHeader[7:]
		
		// Verify token
		user, err := client.VerifyToken(token)
		if err != nil {
			c.Next()
			return
		}
		
		payload, _ := client.DecodeToken(token)
		
		// Store in context
		c.Set(ContextKeyUser, user)
		c.Set(ContextKeyToken, token)
		c.Set(ContextKeyTokenPayload, payload)
		
		c.Next()
	}
}

// RequireAuth creates a Gin middleware that requires authentication
func RequireAuth(roles []string, requireOrg bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(ContextKeyUser)
		if !exists || user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}
		
		if requireOrg {
			payloadInterface, exists := c.Get(ContextKeyTokenPayload)
			if !exists {
				c.JSON(http.StatusForbidden, gin.H{"error": "Organization membership required"})
				c.Abort()
				return
			}
			
			payload, ok := payloadInterface.(*TokenPayload)
			if !ok || payload.OrgID == nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Organization membership required"})
				c.Abort()
				return
			}
			
			if len(roles) > 0 {
				hasRole := false
				for _, role := range roles {
					if payload.OrgRole != nil && *payload.OrgRole == role {
						hasRole = true
						break
					}
				}
				if !hasRole {
					c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
					c.Abort()
					return
				}
			}
		}
		
		c.Next()
	}
}

// RequireOrgMember creates a Gin middleware that requires organization membership
func RequireOrgMember(orgIDParam string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(ContextKeyUser)
		if !exists || user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}
		
		orgID := c.Param(orgIDParam)
		payloadInterface, exists := c.Get(ContextKeyTokenPayload)
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of this organization"})
			c.Abort()
			return
		}
		
		payload, ok := payloadInterface.(*TokenPayload)
		if !ok || payload.OrgID == nil || *payload.OrgID != orgID {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of this organization"})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// GetCurrentUser retrieves the current user from the Gin context
func GetCurrentUser(c *gin.Context) (*User, bool) {
	user, exists := c.Get(ContextKeyUser)
	if !exists || user == nil {
		return nil, false
	}
	return user.(*User), true
}

// GetCurrentTokenPayload retrieves the current token payload from the Gin context
func GetCurrentTokenPayload(c *gin.Context) (*TokenPayload, bool) {
	payload, exists := c.Get(ContextKeyTokenPayload)
	if !exists || payload == nil {
		return nil, false
	}
	return payload.(*TokenPayload), true
}

// HandleError handles VaultAuthError and returns appropriate JSON response
func HandleError(c *gin.Context, err error) {
	if vaultErr, ok := err.(interface{ Error() string }); ok {
		var statusCode int
		switch err.(type) {
		case *AuthenticationError, *TokenExpiredError, *InvalidTokenError:
			statusCode = http.StatusUnauthorized
		case *AuthorizationError:
			statusCode = http.StatusForbidden
		case *NotFoundError:
			statusCode = http.StatusNotFound
		case *RateLimitError:
			statusCode = http.StatusTooManyRequests
		case *ValidationError:
			statusCode = http.StatusBadRequest
		case *ServerError:
			statusCode = http.StatusInternalServerError
		default:
			statusCode = http.StatusInternalServerError
		}
		
		c.JSON(statusCode, gin.H{"error": vaultErr.Error()})
		c.Abort()
		return
	}
	
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	c.Abort()
}

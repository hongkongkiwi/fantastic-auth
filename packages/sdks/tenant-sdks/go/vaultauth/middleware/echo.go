package middleware

import (
	"net/http"
	"strings"

	"github.com/fantasticauth/tenant-sdk-go/vaultauth"
	"github.com/labstack/echo/v4"
)

const (
	// EchoContextKeyUser is the key for storing user in echo context
	EchoContextKeyUser = "fantasticauth_user"
	// EchoContextKeyToken is the key for storing token in echo context
	EchoContextKeyToken = "fantasticauth_token"
	// EchoContextKeyTokenPayload is the key for storing token payload in echo context
	EchoContextKeyTokenPayload = "fantasticauth_token_payload"
)

// MiddlewareEcho creates an Echo middleware for Vault authentication
func MiddlewareEcho(client *vaultauth.Client, excludedPaths ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip excluded paths
			for _, path := range excludedPaths {
				if strings.HasPrefix(c.Request().URL.Path, path) {
					return next(c)
				}
			}

			// Extract token
			authHeader := c.Request().Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				return next(c)
			}

			token := authHeader[7:]

			// Verify token
			user, err := client.VerifyToken(token)
			if err != nil {
				return next(c)
			}

			payload, _ := client.DecodeToken(token)

			// Store in context
			c.Set(EchoContextKeyUser, user)
			c.Set(EchoContextKeyToken, token)
			c.Set(EchoContextKeyTokenPayload, payload)

			return next(c)
		}
	}
}

// RequireAuthEcho creates an Echo middleware that requires authentication
func RequireAuthEcho(roles []string, requireOrg bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get(EchoContextKeyUser)
			if user == nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
			}

			if requireOrg {
				payloadInterface := c.Get(EchoContextKeyTokenPayload)
				if payloadInterface == nil {
					return c.JSON(http.StatusForbidden, map[string]string{"error": "Organization membership required"})
				}

				payload, ok := payloadInterface.(*vaultauth.TokenPayload)
				if !ok || payload.OrgID == nil {
					return c.JSON(http.StatusForbidden, map[string]string{"error": "Organization membership required"})
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
						return c.JSON(http.StatusForbidden, map[string]string{"error": "Insufficient permissions"})
					}
				}
			}

			return next(c)
		}
	}
}

// RequireOrgMemberEcho creates an Echo middleware that requires organization membership
func RequireOrgMemberEcho(orgIDParam string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get(EchoContextKeyUser)
			if user == nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
			}

			orgID := c.Param(orgIDParam)
			payloadInterface := c.Get(EchoContextKeyTokenPayload)
			if payloadInterface == nil {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "Not a member of this organization"})
			}

			payload, ok := payloadInterface.(*vaultauth.TokenPayload)
			if !ok || payload.OrgID == nil || *payload.OrgID != orgID {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "Not a member of this organization"})
			}

			return next(c)
		}
	}
}

// GetCurrentUserEcho retrieves the current user from the Echo context
func GetCurrentUserEcho(c echo.Context) (*vaultauth.User, bool) {
	user := c.Get(EchoContextKeyUser)
	if user == nil {
		return nil, false
	}
	return user.(*vaultauth.User), true
}

// GetCurrentTokenPayloadEcho retrieves the current token payload from the Echo context
func GetCurrentTokenPayloadEcho(c echo.Context) (*vaultauth.TokenPayload, bool) {
	payload := c.Get(EchoContextKeyTokenPayload)
	if payload == nil {
		return nil, false
	}
	return payload.(*vaultauth.TokenPayload), true
}

// HandleErrorEcho handles VaultAuthError and returns appropriate JSON response
func HandleErrorEcho(c echo.Context, err error) error {
	if vaultErr, ok := err.(interface{ Error() string }); ok {
		var statusCode int
		switch err.(type) {
		case *vaultauth.AuthenticationError, *vaultauth.TokenExpiredError, *vaultauth.InvalidTokenError:
			statusCode = http.StatusUnauthorized
		case *vaultauth.AuthorizationError:
			statusCode = http.StatusForbidden
		case *vaultauth.NotFoundError:
			statusCode = http.StatusNotFound
		case *vaultauth.RateLimitError:
			statusCode = http.StatusTooManyRequests
		case *vaultauth.ValidationError:
			statusCode = http.StatusBadRequest
		case *vaultauth.ServerError:
			statusCode = http.StatusInternalServerError
		default:
			statusCode = http.StatusInternalServerError
		}

		return c.JSON(statusCode, map[string]string{"error": vaultErr.Error()})
	}

	return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

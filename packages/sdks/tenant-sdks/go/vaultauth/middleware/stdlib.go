package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/fantasticauth/tenant-sdk-go/vaultauth"
)

// Context keys for standard library context
type contextKey string

const (
	// StdlibContextKeyUser is the key for storing user in context
	StdlibContextKeyUser contextKey = "fantasticauth_user"
	// StdlibContextKeyToken is the key for storing token in context
	StdlibContextKeyToken contextKey = "fantasticauth_token"
	// StdlibContextKeyTokenPayload is the key for storing token payload in context
	StdlibContextKeyTokenPayload contextKey = "fantasticauth_token_payload"
)

// MiddlewareStdlib creates a standard library middleware for Vault authentication
func MiddlewareStdlib(client *vaultauth.Client, excludedPaths ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip excluded paths
			for _, path := range excludedPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Extract token
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				next.ServeHTTP(w, r)
				return
			}

			token := authHeader[7:]

			// Verify token
			user, err := client.VerifyToken(token)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			payload, _ := client.DecodeToken(token)

			// Store in context
			ctx := r.Context()
			ctx = context.WithValue(ctx, StdlibContextKeyUser, user)
			ctx = context.WithValue(ctx, StdlibContextKeyToken, token)
			ctx = context.WithValue(ctx, StdlibContextKeyTokenPayload, payload)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuthStdlib creates a standard library middleware that requires authentication
func RequireAuthStdlib(roles []string, requireOrg bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := r.Context().Value(StdlibContextKeyUser)
			if user == nil {
				http.Error(w, `{"error": "Authentication required"}`, http.StatusUnauthorized)
				return
			}

			if requireOrg {
				payloadInterface := r.Context().Value(StdlibContextKeyTokenPayload)
				if payloadInterface == nil {
					http.Error(w, `{"error": "Organization membership required"}`, http.StatusForbidden)
					return
				}

				payload, ok := payloadInterface.(*vaultauth.TokenPayload)
				if !ok || payload.OrgID == nil {
					http.Error(w, `{"error": "Organization membership required"}`, http.StatusForbidden)
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
						http.Error(w, `{"error": "Insufficient permissions"}`, http.StatusForbidden)
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetCurrentUserStdlib retrieves the current user from the context
func GetCurrentUserStdlib(ctx context.Context) (*vaultauth.User, bool) {
	user := ctx.Value(StdlibContextKeyUser)
	if user == nil {
		return nil, false
	}
	return user.(*vaultauth.User), true
}

// GetCurrentTokenPayloadStdlib retrieves the current token payload from the context
func GetCurrentTokenPayloadStdlib(ctx context.Context) (*vaultauth.TokenPayload, bool) {
	payload := ctx.Value(StdlibContextKeyTokenPayload)
	if payload == nil {
		return nil, false
	}
	return payload.(*vaultauth.TokenPayload), true
}

// WriteErrorStdlib writes an error response in JSON format
func WriteErrorStdlib(w http.ResponseWriter, err error) {
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write([]byte(`{"error": "` + err.Error() + `"}`))
}

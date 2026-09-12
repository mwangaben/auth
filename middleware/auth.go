package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mwangaben/auth/passport"
)

type contextKey string

const (
	UserContextKey  contextKey = "user"
	TokenContextKey contextKey = "token"
)

// AuthMiddleware creates authentication middleware
func AuthMiddleware(p *passport.Passport) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Extract token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]

			// Validate token
			claims, err := p.ValidateToken(r.Context(), tokenString)
			if err != nil {
				http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Get user from claims
			user, err := p.GetUserByID(r.Context(), claims.UserID)
			if err != nil {
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			// Add user and token to context
			ctx := context.WithValue(r.Context(), UserContextKey, user)
			ctx = context.WithValue(ctx, TokenContextKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserFromContext retrieves user from context
func GetUserFromContext(ctx context.Context) interface{} {
	return ctx.Value(UserContextKey)
}

// GetTokenFromContext retrieves token claims from context
func GetTokenFromContext(ctx context.Context) *jwt.Claims {
	if claims, ok := ctx.Value(TokenContextKey).(*jwt.Claims); ok {
		return claims
	}
	return nil
}

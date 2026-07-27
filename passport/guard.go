package passport

import (
	"context"
	"errors"
	"strings"

	_ "github.com/mwangaben/auth/jwt"
	"github.com/mwangaben/auth/models"
)

// Guard handles authentication
type Guard struct {
	passport *Passport
}

// NewGuard creates a new Guard instance
func NewGuard(passport *Passport) *Guard {
	return &Guard{passport: passport}
}

// Check checks if a user is authenticated
func (g *Guard) Check(ctx context.Context) bool {
	user := g.User(ctx)
	return user != nil
}

// Guest checks if a user is not authenticated
func (g *Guard) Guest(ctx context.Context) bool {
	return !g.Check(ctx)
}

// User returns the authenticated user
func (g *Guard) User(ctx context.Context) interface{} {
	if user, ok := ctx.Value("user").(interface{}); ok {
		return user
	}
	return nil
}

// ID returns the authenticated user ID
func (g *Guard) ID(ctx context.Context) string {
	if user := g.User(ctx); user != nil {
		return g.passport.userProvider.GetUserID(user)
	}
	return ""
}

// Validate validates a token and returns the user
func (g *Guard) Validate(ctx context.Context, tokenString string) (interface{}, error) {
	// Remove Bearer prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	// Validate token
	claims, err := g.passport.jwtManager.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Check if token exists in database
	var token models.Token
	if err := g.passport.db.Where("access_token = ? AND revoked = ?", tokenString, false).First(&token).Error; err != nil {
		return nil, errors.New("token not found or revoked")
	}

	// Check if token has expired
	if token.IsExpired() {
		return nil, errors.New("token has expired")
	}

	// Get user
	user, err := g.passport.userProvider.FindByID(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

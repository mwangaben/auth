package passport

import (
	"context"
	"errors"
	"strings"

	"github.com/mwangaben/auth/jwt"
)

// Guard handles authentication helpers around Passport.
type Guard struct {
	passport *Passport
}

// NewGuard creates a new Guard.
func NewGuard(passport *Passport) *Guard {
	return &Guard{passport: passport}
}

// Check reports whether the context contains an authenticated user.
func (g *Guard) Check(ctx context.Context) bool {
	return g.User(ctx) != nil
}

// Guest is the inverse of Check.
func (g *Guard) Guest(ctx context.Context) bool {
	return !g.Check(ctx)
}

// User returns the authenticated user from the context, if any.
func (g *Guard) User(ctx context.Context) interface{} {
	if user, ok := ctx.Value("user").(interface{}); ok {
		return user
	}
	return nil
}

// ID returns the authenticated user's ID, or "" if unauthenticated.
func (g *Guard) ID(ctx context.Context) string {
	if user := g.User(ctx); user != nil {
		return g.passport.userProvider.GetUserID(user)
	}
	return ""
}

// Validate validates a token string and returns the associated user.
func (g *Guard) Validate(ctx context.Context, tokenString string) (interface{}, error) {
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	claims, err := g.passport.jwtManager.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	tok, err := g.passport.repo.GetTokenByAccessToken(ctx, tokenString)
	if err != nil {
		return nil, errors.New("token not found or revoked")
	}
	if tok.IsExpired() {
		return nil, errors.New("token has expired")
	}

	_ = claims // retained for future use (e.g., scope checks)

	return g.passport.userProvider.FindByID(ctx, claims.UserID)
}

var _ = jwt.Claims{} // keep the jwt import; remove if unused

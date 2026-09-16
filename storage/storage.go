// storage/storage.go
package storage

import (
	"context"
	"time"
)

// User represents a user in the system (provider-agnostic).
type User struct {
	ID        string
	Email     string
	Password  string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Client represents an OAuth client.
type Client struct {
	ID                   string
	Name                 string
	Secret               string
	RedirectURI          string
	PersonalAccessClient bool
	PasswordClient       bool
	Revoked              bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Token represents an OAuth token pair.
//
// Access and refresh tokens have separate lifetimes:
//
//   - AccessExpiresAt:  short (minutes to hours) — the token that accompanies
//     each request. Renewed via the refresh token.
//   - RefreshExpiresAt: long (days to weeks) — the token used to obtain a new
//     access token. Rotates on each refresh.
//
// A token pair is "fully expired" only when BOTH lifetimes have passed;
// until then the row remains for audit/cleanup purposes.
type Token struct {
	ID           string
	UserID       string
	ClientID     string
	Name         string
	Scopes       string
	Revoked      bool
	AccessToken  string
	RefreshToken string

	// AccessExpiresAt is when the access token becomes invalid.
	// Typically short: minutes to hours.
	AccessExpiresAt time.Time

	// RefreshExpiresAt is when the refresh token becomes invalid.
	// Typically long: days to weeks.
	//
	// For personal access tokens (which have no refresh), this is set to
	// the same value as AccessExpiresAt.
	RefreshExpiresAt time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsAccessTokenExpired reports whether the access token's lifetime has elapsed.
func (t *Token) IsAccessTokenExpired() bool {
	return t.AccessExpiresAt.Before(time.Now())
}

// IsRefreshTokenExpired reports whether the refresh token's lifetime has elapsed.
func (t *Token) IsRefreshTokenExpired() bool {
	return t.RefreshExpiresAt.Before(time.Now())
}

// IsAccessTokenValid reports whether the access token may be used right now:
// it is not revoked and has not expired.
func (t *Token) IsAccessTokenValid() bool {
	return !t.Revoked && !t.IsAccessTokenExpired()
}

// IsRefreshTokenValid reports whether the refresh token may be used right now:
// it is not revoked and has not expired.
func (t *Token) IsRefreshTokenValid() bool {
	return !t.Revoked && !t.IsRefreshTokenExpired()
}

// PersonalAccessToken represents a long-lived token without a refresh pair.
type PersonalAccessToken struct {
	ID        string
	TokenID   string
	UserID    string
	Name      string
	Revoked   bool
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Repository is the storage abstraction both GORM and Ent implement.
type Repository interface {
	// ─── Client operations ─────────────────────────────────────────────
	CreateClient(ctx context.Context, client *Client) error
	GetClient(ctx context.Context, id string) (*Client, error)
	RevokeClient(ctx context.Context, id string) error

	// ─── Token operations ──────────────────────────────────────────────
	CreateToken(ctx context.Context, token *Token) error
	GetTokenByAccessToken(ctx context.Context, accessToken string) (*Token, error)
	GetTokenByRefreshToken(ctx context.Context, refreshToken string) (*Token, error)
	RevokeToken(ctx context.Context, id string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	UpdateToken(ctx context.Context, token *Token) error
	ListUserTokens(ctx context.Context, userID string) ([]*Token, error)

	// DeleteExpiredTokens removes rows whose refresh window has passed.
	// Pass the current time (or a cutoff): only rows strictly older than
	// `before` on BOTH access and refresh expiry are deleted.
	DeleteExpiredTokens(ctx context.Context, before time.Time) (int, error)

	// ─── Personal Access Token operations ──────────────────────────────
	CreatePersonalAccessToken(ctx context.Context, pat *PersonalAccessToken) error

	// ─── Migration & introspection ─────────────────────────────────────
	AutoMigrate(ctx context.Context) error
	Name() string
}

// RepositoryFactory is a function that creates a Repository from an opaque
// database handle.
type RepositoryFactory func(db interface{}) (Repository, error)

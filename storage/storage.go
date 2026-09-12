// storage/storage.go
package storage

import (
	"context"
	"time"
)

// User represents a user in the system (provider-agnostic)
type User struct {
	ID        string
	Email     string
	Password  string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Client represents an OAuth client
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

// Token represents an OAuth token
type Token struct {
	ID           string
	UserID       string
	ClientID     string
	Name         string
	Scopes       string
	Revoked      bool
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// PersonalAccessToken represents a PAT
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
	// Client operations
	CreateClient(ctx context.Context, client *Client) error
	GetClient(ctx context.Context, id string) (*Client, error)
	RevokeClient(ctx context.Context, id string) error

	// Token operations
	CreateToken(ctx context.Context, token *Token) error
	GetTokenByAccessToken(ctx context.Context, accessToken string) (*Token, error)
	GetTokenByRefreshToken(ctx context.Context, refreshToken string) (*Token, error)
	RevokeToken(ctx context.Context, id string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	UpdateToken(ctx context.Context, token *Token) error

	// Personal Access Token operations
	CreatePersonalAccessToken(ctx context.Context, pat *PersonalAccessToken) error

	// Migration
	AutoMigrate(ctx context.Context) error

	// Backend name for debugging
	Name() string
	ListUserTokens(ctx context.Context, userID string) ([]*Token, error)
}

// RepositoryFactory is a function that creates a Repository from an opaque DB handle.
type RepositoryFactory func(db interface{}) (Repository, error)

// storage/storage.go (continued)
func (t *Token) IsExpired() bool {
	return t.ExpiresAt.Before(time.Now())
}

func (t *Token) IsValid() bool {
	return !t.Revoked && !t.IsExpired()
}

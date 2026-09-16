// models/token.go
package models

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// OAuthToken is the GORM model for the oauth_access_tokens table.
//
// Access and refresh tokens have independent expiry columns so the access
// token can be short-lived while the refresh token remains valid for days
// or weeks.
type OAuthToken struct {
	ID           string `gorm:"primaryKey;type:varchar(100)" json:"id"`
	UserID       string `gorm:"type:varchar(255);index" json:"user_id"`
	ClientID     string `gorm:"type:varchar(100);index" json:"client_id"`
	Name         string `gorm:"type:varchar(255)" json:"name"`
	Scopes       string `gorm:"type:text" json:"scopes"`
	Revoked      bool   `gorm:"default:false" json:"revoked"`
	AccessToken  string `gorm:"type:text" json:"-"`
	RefreshToken string `gorm:"type:text" json:"-"`

	// Two separate expiry columns. See models.OAuthToken docs.
	AccessExpiresAt  time.Time `gorm:"index" json:"access_expires_at"`
	RefreshExpiresAt time.Time `gorm:"index" json:"refresh_expires_at"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name.
func (OAuthToken) TableName() string {
	return "oauth_access_tokens"
}

// IsAccessTokenExpired reports whether the access token's lifetime has elapsed.
func (t *OAuthToken) IsAccessTokenExpired() bool {
	return t.AccessExpiresAt.Before(time.Now())
}

// IsRefreshTokenExpired reports whether the refresh token's lifetime has elapsed.
func (t *OAuthToken) IsRefreshTokenExpired() bool {
	return t.RefreshExpiresAt.Before(time.Now())
}

// IsAccessTokenValid reports whether the access token may be used.
func (t *OAuthToken) IsAccessTokenValid() bool {
	return !t.Revoked && !t.IsAccessTokenExpired() && t.DeletedAt.Time.IsZero()
}

// IsRefreshTokenValid reports whether the refresh token may be used.
func (t *OAuthToken) IsRefreshTokenValid() bool {
	return !t.Revoked && !t.IsRefreshTokenExpired() && t.DeletedAt.Time.IsZero()
}

// GetScopes returns the scopes as a slice.
func (t *OAuthToken) GetScopes() []string {
	if t.Scopes == "" {
		return []string{}
	}
	return strings.Split(t.Scopes, ",")
}

// SetScopes sets the scopes from a slice.
func (t *OAuthToken) SetScopes(scopes []string) {
	t.Scopes = strings.Join(scopes, ",")
}

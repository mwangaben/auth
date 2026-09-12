package models

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// Token represents an OAuth token
type OAuthToken struct {
	ID           string         `gorm:"primaryKey;type:varchar(100)" json:"id"`
	UserID       string         `gorm:"type:varchar(255);index" json:"user_id"`
	ClientID     string         `gorm:"type:varchar(100);index" json:"client_id"`
	Name         string         `gorm:"type:varchar(255)" json:"name"`
	Scopes       string         `gorm:"type:text" json:"scopes"`
	Revoked      bool           `gorm:"default:false" json:"revoked"`
	AccessToken  string         `gorm:"type:text" json:"-"`
	RefreshToken string         `gorm:"type:text" json:"-"`
	ExpiresAt    time.Time      `json:"expires_at"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name
func (OAuthToken) TableName() string {
	return "oauth_access_tokens"
}

// IsValid checks if the token is valid
func (t *OAuthToken) IsValid() bool {
	return !t.Revoked && t.ExpiresAt.After(time.Now()) && t.DeletedAt.Time.IsZero()
}

// IsExpired checks if the token has expired
func (t *OAuthToken) IsExpired() bool {
	return t.ExpiresAt.Before(time.Now())
}

// GetScopes returns the scopes as a slice
func (t *OAuthToken) GetScopes() []string {
	if t.Scopes == "" {
		return []string{}
	}
	// Scopes are stored as comma-separated values
	return strings.Split(t.Scopes, ",")
}

// SetScopes sets the scopes from a slice
func (t *OAuthToken) SetScopes(scopes []string) {
	t.Scopes = strings.Join(scopes, ",")
}

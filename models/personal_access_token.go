package models

import (
	"time"

	"gorm.io/gorm"
)

// PersonalAccessToken represents a personal access token
type OAuthPersonalAccessToken struct {
	ID        string         `gorm:"primaryKey;type:varchar(100)" json:"id"`
	TokenID   string         `gorm:"type:varchar(100);index" json:"token_id"`
	UserID    string         `gorm:"type:varchar(255);index" json:"user_id"`
	Name      string         `gorm:"type:varchar(255);not null" json:"name"`
	Revoked   bool           `gorm:"default:false" json:"revoked"`
	ExpiresAt time.Time      `json:"expires_at"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name
func (OAuthPersonalAccessToken) TableName() string {
	return "oauth_personal_access_tokens"
}

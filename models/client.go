package models

import (
	"time"

	"gorm.io/gorm"
)

// Client represents an OAuth client
type OAuthClient struct {
	ID                   string         `gorm:"primaryKey;type:varchar(100)" json:"id"`
	Name                 string         `gorm:"type:varchar(255);not null" json:"name"`
	Secret               string         `gorm:"type:varchar(255);not null" json:"-"`
	RedirectURI          string         `gorm:"type:varchar(255)" json:"redirect_uri"`
	PersonalAccessClient bool           `gorm:"default:false" json:"personal_access_client"`
	PasswordClient       bool           `gorm:"default:false" json:"password_client"`
	Revoked              bool           `gorm:"default:false" json:"revoked"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	DeletedAt            gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name
func (OAuthClient) TableName() string {
	return "oauth_clients"
}

// IsValid checks if the client is valid
func (c *OAuthClient) IsValid() bool {
	return !c.Revoked && c.DeletedAt.Time.IsZero()
}

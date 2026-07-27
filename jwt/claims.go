package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents JWT claims with custom fields
type Claims struct {
	jwt.RegisteredClaims
	UserID   string                 `json:"user_id"`
	ClientID string                 `json:"client_id,omitempty"`
	Scopes   []string               `json:"scopes,omitempty"`
	Meta     map[string]interface{} `json:"meta,omitempty"`
}

// NewClaims creates a new Claims instance
func NewClaims(userID, clientID string, scopes []string) *Claims {
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID: uuid.New().String(), // Add unique ID
		},
		UserID:   userID,
		ClientID: clientID,
		Scopes:   scopes,
		Meta:     make(map[string]interface{}),
	}
}

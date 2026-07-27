package passport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/mwangaben/auth/models"
	"golang.org/x/crypto/bcrypt"
)

// CreateClient creates a new OAuth client
func (p *Passport) CreateClient(ctx context.Context, name, redirectURI string, personalAccess, password bool) (*models.Client, string, error) {
	clientID := uuid.New().String()
	clientSecret, err := generateClientSecret()
	if err != nil {
		return nil, "", err
	}

	// Hash the client secret
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}

	client := &models.Client{
		ID:                   clientID,
		Name:                 name,
		Secret:               string(hashedSecret),
		RedirectURI:          redirectURI,
		PersonalAccessClient: personalAccess,
		PasswordClient:       password,
		Revoked:              false,
	}

	if err := p.db.Create(client).Error; err != nil {
		return nil, "", fmt.Errorf("failed to create client: %w", err)
	}

	return client, clientSecret, nil
}

// GetClient retrieves a client by ID
func (p *Passport) GetClient(ctx context.Context, clientID string) (*models.Client, error) {
	var client models.Client
	if err := p.db.Where("id = ? AND revoked = ?", clientID, false).First(&client).Error; err != nil {
		return nil, errors.New("client not found")
	}
	return &client, nil
}

// VerifyClientSecret verifies a client secret
func (p *Passport) VerifyClientSecret(client *models.Client, secret string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(secret))
	return err == nil
}

// RevokeClient revokes a client
func (p *Passport) RevokeClient(ctx context.Context, clientID string) error {
	return p.db.Model(&models.Client{}).Where("id = ?", clientID).Update("revoked", true).Error
}

// generateClientSecret generates a random client secret
func generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

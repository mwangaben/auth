package passport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/mwangaben/auth/storage"
	"golang.org/x/crypto/bcrypt"
)

// CreateClient creates a new OAuth client and returns it along with the
// plain-text secret (which is only available at creation time).
func (p *Passport) CreateClient(
	ctx context.Context,
	name, redirectURI string,
	personalAccess, password bool,
) (*storage.Client, string, error) {
	clientID := uuid.New().String()

	clientSecret, err := generateClientSecret()
	if err != nil {
		return nil, "", err
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}

	client := &storage.Client{
		ID:                   clientID,
		Name:                 name,
		Secret:               string(hashedSecret),
		RedirectURI:          redirectURI,
		PersonalAccessClient: personalAccess,
		PasswordClient:       password,
		Revoked:              false,
	}

	if err := p.repo.CreateClient(ctx, client); err != nil {
		return nil, "", fmt.Errorf("failed to create client: %w", err)
	}

	return client, clientSecret, nil
}

// GetClient retrieves a non-revoked client by ID.
func (p *Passport) GetClient(ctx context.Context, clientID string) (*storage.Client, error) {
	return p.repo.GetClient(ctx, clientID)
}

// VerifyClientSecret verifies a client secret against its bcrypt hash.
func (p *Passport) VerifyClientSecret(client *storage.Client, secret string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(secret))
	return err == nil
}

// RevokeClient revokes a client by ID.
func (p *Passport) RevokeClient(ctx context.Context, clientID string) error {
	return p.repo.RevokeClient(ctx, clientID)
}

func generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

var _ = errors.New // keep errors import if unused elsewhere

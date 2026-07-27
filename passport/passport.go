package passport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/mwangaben/auth/jwt"
	"github.com/mwangaben/auth/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Passport is the main authentication manager
type Passport struct {
	db            *gorm.DB
	jwtManager    *jwt.Manager
	userProvider  UserProvider
	tokenExpiry   time.Duration
	refreshExpiry time.Duration
}

// Config holds passport configuration
type Config struct {
	PrivateKey    []byte
	PublicKey     []byte
	TokenExpiry   time.Duration
	RefreshExpiry time.Duration
	Issuer        string
	Audience      string
}

// TokenResponse represents a token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// NewPassport creates a new Passport instance
func NewPassport(db *gorm.DB, config *Config, userProvider UserProvider) (*Passport, error) {
	if db == nil {
		return nil, errors.New("database connection is required")
	}
	if userProvider == nil {
		return nil, errors.New("user provider is required")
	}

	if config == nil {
		config = &Config{}
	}

	if config.TokenExpiry == 0 {
		config.TokenExpiry = time.Hour * 24 // 24 hours
	}
	if config.RefreshExpiry == 0 {
		config.RefreshExpiry = time.Hour * 24 * 7 // 7 days
	}

	// Auto migrate models
	if err := db.AutoMigrate(&models.Client{}, &models.Token{}, &models.PersonalAccessToken{}); err != nil {
		return nil, fmt.Errorf("failed to migrate models: %w", err)
	}

	// Create JWT manager
	jwtConfig := &jwt.Config{
		PrivateKey:  config.PrivateKey,
		PublicKey:   config.PublicKey,
		Issuer:      config.Issuer,
		Audience:    config.Audience,
		TokenExpiry: config.TokenExpiry,
	}
	jwtManager, err := jwt.NewManager(jwtConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT manager: %w", err)
	}

	return &Passport{
		db:            db,
		jwtManager:    jwtManager,
		userProvider:  userProvider,
		tokenExpiry:   config.TokenExpiry,
		refreshExpiry: config.RefreshExpiry,
	}, nil
}

// GetDB returns the database connection
func (p *Passport) GetDB() *gorm.DB {
	return p.db
}

// GetJWTManager returns the JWT manager
func (p *Passport) GetJWTManager() *jwt.Manager {
	return p.jwtManager
}

// GetPublicKey returns the public key in PEM format
func (p *Passport) GetPublicKey() []byte {
	return p.jwtManager.GetPublicKeyPEM()
}

// IssueToken issues a new token for a user
func (p *Passport) IssueToken(ctx context.Context, userID, clientID string, scopes []string) (*TokenResponse, error) {
	// Generate access token
	claims := jwt.NewClaims(userID, clientID, scopes)
	accessToken, err := p.jwtManager.GenerateToken(claims, p.tokenExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := p.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store token in database
	tokenID := uuid.New().String()
	token := &models.Token{
		ID:           tokenID,
		UserID:       userID,
		ClientID:     clientID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(p.tokenExpiry),
		Revoked:      false,
	}
	token.SetScopes(scopes)

	if err := p.db.Create(token).Error; err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.tokenExpiry.Seconds()),
	}, nil
}

// IssuePersonalAccessToken issues a personal access token
func (p *Passport) IssuePersonalAccessToken(ctx context.Context, userID, name string, scopes []string, expiresAt *time.Time) (*TokenResponse, error) {
	// Generate access token
	claims := jwt.NewClaims(userID, "", scopes)
	accessToken, err := p.jwtManager.GenerateToken(claims, p.tokenExpiry)
	if err != nil {
		return nil, err
	}

	// Store as personal access token
	tokenID := uuid.New().String()
	pat := &models.PersonalAccessToken{
		ID:        uuid.New().String(),
		TokenID:   tokenID,
		UserID:    userID,
		Name:      name,
		Revoked:   false,
		ExpiresAt: time.Now().Add(p.tokenExpiry),
	}
	if expiresAt != nil {
		pat.ExpiresAt = *expiresAt
	}

	if err := p.db.Create(pat).Error; err != nil {
		return nil, err
	}

	// Create the actual token
	token := &models.Token{
		ID:           tokenID,
		UserID:       userID,
		ClientID:     "",
		AccessToken:  accessToken,
		RefreshToken: "",
		ExpiresAt:    pat.ExpiresAt,
		Revoked:      false,
	}
	token.SetScopes(scopes)

	if err := p.db.Create(token).Error; err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(pat.ExpiresAt).Seconds()),
	}, nil
}

// ValidateToken validates a token and returns the claims
// ValidateToken validates a token and returns the claims
func (p *Passport) ValidateToken(tokenString string) (*jwt.Claims, error) {
	// First validate JWT
	claims, err := p.jwtManager.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Check if token exists in database and is not revoked
	var token models.Token
	if err := p.db.Where("access_token = ? AND revoked = ?", tokenString, false).First(&token).Error; err != nil {
		return nil, errors.New("token not found or revoked")
	}

	// Check if token has expired
	if token.IsExpired() {
		return nil, errors.New("token has expired")
	}

	return claims, nil
}

// RefreshToken refreshes an expired access token
func (p *Passport) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	// Find token by refresh token
	var token models.Token
	if err := p.db.Where("refresh_token = ? AND revoked = ?", refreshToken, false).First(&token).Error; err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if refresh token has expired
	if token.IsExpired() {
		return nil, errors.New("refresh token has expired")
	}

	// Get the current user ID
	userID := token.UserID
	clientID := token.ClientID
	scopes := token.GetScopes()

	// Revoke old token
	token.Revoked = true
	if err := p.db.Save(&token).Error; err != nil {
		return nil, err
	}

	// Generate new access token with new claims
	claims := jwt.NewClaims(userID, clientID, scopes)
	accessToken, err := p.jwtManager.GenerateToken(claims, p.tokenExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate new refresh token
	newRefreshToken, err := p.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store new token in database
	tokenID := uuid.New().String()
	newToken := &models.Token{
		ID:           tokenID,
		UserID:       userID,
		ClientID:     clientID,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(p.tokenExpiry),
		Revoked:      false,
	}
	newToken.SetScopes(scopes)

	if err := p.db.Create(newToken).Error; err != nil {
		return nil, fmt.Errorf("failed to store new token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.tokenExpiry.Seconds()),
	}, nil
}

// RevokeToken revokes a token
func (p *Passport) RevokeToken(ctx context.Context, tokenString string) error {
	var token models.Token
	if err := p.db.Where("access_token = ?", tokenString).First(&token).Error; err != nil {
		return errors.New("token not found")
	}

	token.Revoked = true
	return p.db.Save(&token).Error
}

// RevokeAllTokens revokes all tokens for a user
func (p *Passport) RevokeAllTokens(ctx context.Context, userID string) error {
	return p.db.Model(&models.Token{}).Where("user_id = ? AND revoked = ?", userID, false).Update("revoked", true).Error
}

// generateRefreshToken generates a random refresh token
func (p *Passport) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// HashPassword hashes a password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

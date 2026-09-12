package passport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/mwangaben/auth/jwt"
	"github.com/mwangaben/auth/storage"
	"github.com/mwangaben/auth/storage/entstore"
	"github.com/mwangaben/auth/storage/gormstore"
	"golang.org/x/crypto/bcrypt"
)

// Passport is the main authentication manager.
//
// It is storage-agnostic: the underlying persistence layer is chosen at
// construction time based on the type of `db` passed to NewPassport, or
// overridden explicitly via Config.StorageDriver.
type Passport struct {
	repo          storage.Repository
	jwtManager    *jwt.Manager
	userProvider  UserProvider
	tokenExpiry   time.Duration
	refreshExpiry time.Duration
}

// Config holds passport configuration.
type Config struct {
	PrivateKey  []byte
	PublicKey   []byte
	TokenExpiry time.Duration
	Issuer      string
	Audience    string

	// RefreshExpiry is how long a refresh token is valid for.
	RefreshExpiry time.Duration

	// StorageDriver forces a specific backend: "gorm" or "ent".
	// If empty, the driver is auto-detected from the db handle.
	StorageDriver string
}

// TokenResponse represents a token response returned to clients.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// NewPassport creates a new Passport instance.
//
// `db` may be:
//   - *gorm.DB                       (GORM backend)
//   - *ent.Client                    (Ent backend, from storage/entstore/ent)
//   - any value exposing DB() *gorm.DB       (GORM wrapper)
//   - any value exposing Client() *ent.Client (Ent wrapper)
//
// The backend is auto-detected unless Config.StorageDriver is set.
func NewPassport(db interface{}, config *Config, userProvider UserProvider) (*Passport, error) {
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
		config.TokenExpiry = 24 * time.Hour
	}
	if config.RefreshExpiry == 0 {
		config.RefreshExpiry = 7 * 24 * time.Hour
	}

	repo, err := buildRepository(db, config.StorageDriver)
	if err != nil {
		return nil, fmt.Errorf("failed to build storage: %w", err)
	}

	if err := repo.AutoMigrate(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to migrate models: %w", err)
	}

	jwtManager, err := jwt.NewManager(&jwt.Config{
		PrivateKey:  config.PrivateKey,
		PublicKey:   config.PublicKey,
		Issuer:      config.Issuer,
		Audience:    config.Audience,
		TokenExpiry: config.TokenExpiry,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT manager: %w", err)
	}

	return &Passport{
		repo:          repo,
		jwtManager:    jwtManager,
		userProvider:  userProvider,
		tokenExpiry:   config.TokenExpiry,
		refreshExpiry: config.RefreshExpiry,
	}, nil
}

// buildRepository resolves the storage backend.
func buildRepository(db interface{}, forceDriver string) (storage.Repository, error) {
	driver := forceDriver
	if driver == "" {
		var err error
		driver, err = storage.DetectDriver(db)
		if err != nil {
			return nil, err
		}
	}

	switch driver {
	case storage.DriverGorm:
		return gormstore.New(db)
	case storage.DriverEnt:
		return entstore.New(db)
	default:
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}
}

// GetRepository returns the underlying storage repository.
// Useful for advanced use cases and tests.
func (p *Passport) GetRepository() storage.Repository {
	return p.repo
}

// GetJWTManager returns the JWT manager.
func (p *Passport) GetJWTManager() *jwt.Manager {
	return p.jwtManager
}

// GetPublicKey returns the RSA public key in PEM format.
func (p *Passport) GetPublicKey() []byte {
	return p.jwtManager.GetPublicKeyPEM()
}

// generateRefreshToken generates a cryptographically random refresh token.
func (p *Passport) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// VerifyPassword verifies a password against a bcrypt hash.
func VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// GetUserID extracts the user ID from an opaque user value using the
// configured UserProvider. Returns "" if the value is not a recognized user.
func (p *Passport) GetUserID(user interface{}) string {
	if user == nil {
		return ""
	}
	return p.userProvider.GetUserID(user)
}

package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

// Manager handles JWT operations

type Manager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
}

// Config holds JWT configuration
type Config struct {
	PrivateKey  []byte
	PublicKey   []byte
	Issuer      string
	Audience    string
	TokenExpiry time.Duration
}

// NewManager creates a new JWT manager
func NewManager(config *Config) (*Manager, error) {
	m := &Manager{
		issuer:   config.Issuer,
		audience: config.Audience,
	}

	if config.PrivateKey != nil && config.PublicKey != nil {
		privateKey, err := parsePrivateKey(config.PrivateKey)
		if err != nil {
			return nil, err
		}
		publicKey, err := parsePublicKey(config.PublicKey)
		if err != nil {
			return nil, err
		}
		m.privateKey = privateKey
		m.publicKey = publicKey
	} else {
		// Generate new key pair
		privateKey, publicKey, err := generateKeyPair()
		if err != nil {
			return nil, err
		}
		m.privateKey = privateKey
		m.publicKey = publicKey
	}

	return m, nil
}

// GenerateToken generates a new JWT token
func (m *Manager) GenerateToken(claims *Claims, expiry time.Duration) (string, error) {
	if expiry == 0 {
		expiry = time.Hour * 24 // Default 24 hours
	}

	now := time.Now()

	// Add a unique JWT ID to ensure tokens are different
	if claims.ID == "" {
		claims.ID = uuid.New().String()
	}

	claims.RegisteredClaims = jwt.RegisteredClaims{
		ID:        claims.ID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    m.issuer,
		Audience:  jwt.ClaimStrings{m.audience},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(m.privateKey)
}

// ValidateToken validates and parses a JWT token
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// parsePrivateKey parses an RSA private key from PEM
func parsePrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is not RSA private key")
		}
		return privateKey, nil
	}
	return privateKey, nil
}

// parsePublicKey parses an RSA public key from PEM
func parsePublicKey(keyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not RSA public key")
	}
	return rsaPublicKey, nil
}

// generateKeyPair generates a new RSA key pair
func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// GetPublicKeyPEM returns the public key in PEM format
func (m *Manager) GetPublicKeyPEM() []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(m.publicKey)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
}

// GetPrivateKeyPEM returns the private key in PEM format
func (m *Manager) GetPrivateKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(m.privateKey),
	})
}

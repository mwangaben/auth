// passport/token.go
package passport

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/mwangaben/auth/jwt"
	"github.com/mwangaben/auth/storage"
)

// IssueToken issues a new access token + refresh token pair.
//
// The access token expires after p.tokenExpiry (short — minutes to hours).
// The refresh token expires after p.refreshExpiry (long — days to weeks).
func (p *Passport) IssueToken(ctx context.Context, userID, clientID string, scopes []string) (*TokenResponse, error) {
	claims := jwt.NewClaims(userID, clientID, scopes)
	accessToken, err := p.jwtManager.GenerateToken(claims, p.tokenExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := p.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	now := time.Now()
	tok := &storage.Token{
		ID:           uuid.New().String(),
		UserID:       userID,
		ClientID:     clientID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Scopes:       joinScopes(scopes),

		AccessExpiresAt:  now.Add(p.tokenExpiry),
		RefreshExpiresAt: now.Add(p.refreshExpiry),

		Revoked: false,
	}
	if err := p.repo.CreateToken(ctx, tok); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.tokenExpiry.Seconds()),
	}, nil
}

// IssuePersonalAccessToken issues a personal access token for a user.
//
// Personal access tokens have no refresh companion. Both expiry columns are
// set to the same value so the token behaves like a normal (non-refreshable)
// bearer token.
func (p *Passport) IssuePersonalAccessToken(
	ctx context.Context,
	userID, name string,
	scopes []string,
	expiresAt *time.Time,
) (*TokenResponse, error) {
	claims := jwt.NewClaims(userID, "", scopes)
	accessToken, err := p.jwtManager.GenerateToken(claims, p.tokenExpiry)
	if err != nil {
		return nil, err
	}

	expiry := time.Now().Add(p.tokenExpiry)
	if expiresAt != nil {
		expiry = *expiresAt
	}

	tokenID := uuid.New().String()
	pat := &storage.PersonalAccessToken{
		ID:        uuid.New().String(),
		TokenID:   tokenID,
		UserID:    userID,
		Name:      name,
		Revoked:   false,
		ExpiresAt: expiry,
	}
	if err := p.repo.CreatePersonalAccessToken(ctx, pat); err != nil {
		return nil, err
	}

	tok := &storage.Token{
		ID:           tokenID,
		UserID:       userID,
		ClientID:     "",
		AccessToken:  accessToken,
		RefreshToken: "",
		Scopes:       joinScopes(scopes),

		// PATs have no refresh companion: both expiries use the same value
		// so IsAccessTokenExpired and IsRefreshTokenExpired agree.
		AccessExpiresAt:  expiry,
		RefreshExpiresAt: expiry,

		Revoked: false,
	}
	if err := p.repo.CreateToken(ctx, tok); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(expiry).Seconds()),
	}, nil
}

// ValidateToken validates an access token against both the JWT signature and
// the database record.
//
// Only the access token's lifetime is checked. If it has expired, the caller
// should use the refresh token (via RefreshToken) to obtain a fresh access
// token.
func (p *Passport) ValidateToken(ctx context.Context, tokenString string) (*jwt.Claims, error) {
	claims, err := p.jwtManager.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	tok, err := p.repo.GetTokenByAccessToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	if tok.IsAccessTokenExpired() {
		return nil, errors.New("access token has expired")
	}
	return claims, nil
}

// RefreshToken rotates a refresh token, returning a new access + refresh pair.
//
// The old token pair is revoked and a new pair is issued. Both expiries are
// reset on the new pair.
func (p *Passport) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	tok, err := p.repo.GetTokenByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Only the refresh token's lifetime is consulted here. The access token
	// is already expired — that's why the caller is refreshing.
	if tok.IsRefreshTokenExpired() {
		return nil, errors.New("refresh token has expired")
	}

	if err := p.repo.RevokeToken(ctx, tok.ID); err != nil {
		return nil, err
	}

	claims := jwt.NewClaims(tok.UserID, tok.ClientID, splitScopes(tok.Scopes))
	newAccess, err := p.jwtManager.GenerateToken(claims, p.tokenExpiry)
	if err != nil {
		return nil, err
	}
	newRefresh, err := p.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	newTok := &storage.Token{
		ID:           uuid.New().String(),
		UserID:       tok.UserID,
		ClientID:     tok.ClientID,
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
		Scopes:       tok.Scopes,

		AccessExpiresAt:  now.Add(p.tokenExpiry),
		RefreshExpiresAt: now.Add(p.refreshExpiry),

		Revoked: false,
	}
	if err := p.repo.CreateToken(ctx, newTok); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.tokenExpiry.Seconds()),
	}, nil
}

// RevokeToken revokes a single access token.
func (p *Passport) RevokeToken(ctx context.Context, tokenString string) error {
	tok, err := p.repo.GetTokenByAccessToken(ctx, tokenString)
	if err != nil {
		return errors.New("token not found")
	}
	return p.repo.RevokeToken(ctx, tok.ID)
}

// RevokeAllTokens revokes every active token for a user.
func (p *Passport) RevokeAllTokens(ctx context.Context, userID string) error {
	return p.repo.RevokeAllUserTokens(ctx, userID)
}

// CleanupExpiredTokens deletes tokens whose refresh window has closed. Safe
// to call from a background goroutine or scheduled job; it does not interfere
// with in-flight requests.
func (p *Passport) CleanupExpiredTokens(ctx context.Context) (int, error) {
	return p.repo.DeleteExpiredTokens(ctx, time.Now())
}

func joinScopes(s []string) string {
	if len(s) == 0 {
		return ""
	}
	out := s[0]
	for _, v := range s[1:] {
		out += "," + v
	}
	return out
}

func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

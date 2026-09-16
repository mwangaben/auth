// storage/gormstore/repository.go
package gormstore

import (
	"context"
	"errors"
	"github.com/mwangaben/auth/models"
	"github.com/mwangaben/auth/storage"
	"gorm.io/gorm"
	"strings"
	"time"
)

// GormModels — keep the existing models but move them here or keep in models/
// Reuse existing models from github.com/mwangaben/auth/models

type Repository struct {
	db *gorm.DB
}

func New(db interface{}) (storage.Repository, error) {
	gdb, ok := db.(*gorm.DB)
	if !ok {
		return nil, errors.New("gormstore store: expected *gormstore.DB")
	}
	return &Repository{db: gdb}, nil
}

func (r *Repository) Name() string { return "gormstore" }

func (r *Repository) AutoMigrate(ctx context.Context) error {
	return r.db.WithContext(ctx).AutoMigrate(
		&models.OAuthClient{},
		&models.OAuthToken{},
		&models.OAuthPersonalAccessToken{},
	)
}

func (r *Repository) CreateClient(ctx context.Context, c *storage.Client) error {
	m := toGormClient(c)
	return r.db.WithContext(ctx).Create(m).Error
}

func (r *Repository) GetClient(ctx context.Context, id string) (*storage.Client, error) {
	var m models.OAuthClient
	if err := r.db.WithContext(ctx).
		Where("id = ? AND revoked = ?", id, false).
		First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("client not found")
		}
		return nil, err
	}
	return fromGormClient(&m), nil
}

func (r *Repository) RevokeClient(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).
		Model(&models.OAuthClient{}).
		Where("id = ?", id).
		Update("revoked", true).Error
}

func (r *Repository) CreateToken(ctx context.Context, t *storage.Token) error {
	return r.db.WithContext(ctx).Create(toGormToken(t)).Error
}

func (r *Repository) GetTokenByAccessToken(ctx context.Context, at string) (*storage.Token, error) {
	var m models.OAuthToken
	if err := r.db.WithContext(ctx).
		Where("access_token = ? AND revoked = ?", at, false).
		First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("token not found or revoked")
		}
		return nil, err
	}
	return fromGormToken(&m), nil
}

func (r *Repository) GetTokenByRefreshToken(ctx context.Context, rt string) (*storage.Token, error) {
	var m models.OAuthToken
	if err := r.db.WithContext(ctx).
		Where("refresh_token = ? AND revoked = ?", rt, false).
		First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid refresh token")
		}
		return nil, err
	}
	return fromGormToken(&m), nil
}

func (r *Repository) RevokeToken(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).
		Model(&models.OAuthToken{}).
		Where("id = ?", id).
		Update("revoked", true).Error
}

func (r *Repository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).
		Model(&models.OAuthToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true).Error
}

func (r *Repository) UpdateToken(ctx context.Context, t *storage.Token) error {
	return r.db.WithContext(ctx).Save(toGormToken(t)).Error
}

func (r *Repository) CreatePersonalAccessToken(ctx context.Context, pat *storage.PersonalAccessToken) error {
	return r.db.WithContext(ctx).Create(toGormPAT(pat)).Error
}

func (r *Repository) DeleteExpiredTokens(ctx context.Context, before time.Time) (int, error) {
	result := r.db.WithContext(ctx).
		Unscoped().
		Where("access_expires_at < ? AND refresh_expires_at < ?", before, before).
		Delete(&models.OAuthToken{})
	if result.Error != nil {
		return 0, result.Error
	}
	return int(result.RowsAffected), nil
}

// ---- Mappers ----

func toGormClient(c *storage.Client) *models.OAuthClient {
	return &models.OAuthClient{
		ID: c.ID, Name: c.Name, Secret: c.Secret,
		RedirectURI:          c.RedirectURI,
		PersonalAccessClient: c.PersonalAccessClient,
		PasswordClient:       c.PasswordClient,
		Revoked:              c.Revoked,
	}
}

func fromGormClient(m *models.OAuthClient) *storage.Client {
	return &storage.Client{
		ID: m.ID, Name: m.Name, Secret: m.Secret,
		RedirectURI:          m.RedirectURI,
		PersonalAccessClient: m.PersonalAccessClient,
		PasswordClient:       m.PasswordClient,
		Revoked:              m.Revoked,
		CreatedAt:            m.CreatedAt,
		UpdatedAt:            m.UpdatedAt,
	}
}

func toGormToken(t *storage.Token) *models.OAuthToken {
	return &models.OAuthToken{
		ID:           t.ID,
		UserID:       t.UserID,
		ClientID:     t.ClientID,
		Name:         t.Name,
		Scopes:       t.Scopes,
		Revoked:      t.Revoked,
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		// NEW
		AccessExpiresAt:  t.AccessExpiresAt,
		RefreshExpiresAt: t.RefreshExpiresAt,
	}
}

func fromGormToken(m *models.OAuthToken) *storage.Token {
	return &storage.Token{
		ID:           m.ID,
		UserID:       m.UserID,
		ClientID:     m.ClientID,
		Name:         m.Name,
		Scopes:       m.Scopes,
		Revoked:      m.Revoked,
		AccessToken:  m.AccessToken,
		RefreshToken: m.RefreshToken,
		// NEW
		AccessExpiresAt:  m.AccessExpiresAt,
		RefreshExpiresAt: m.RefreshExpiresAt,
		CreatedAt:        m.CreatedAt,
		UpdatedAt:        m.UpdatedAt,
	}
}

func toGormPAT(p *storage.PersonalAccessToken) *models.OAuthPersonalAccessToken {
	return &models.OAuthPersonalAccessToken{
		ID: p.ID, TokenID: p.TokenID, UserID: p.UserID,
		Name: p.Name, Revoked: p.Revoked, ExpiresAt: p.ExpiresAt,
	}
}

// Scopes helper (kept here or in storage)
func JoinScopes(s []string) string { return strings.Join(s, ",") }
func SplitScopes(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}
func (r *Repository) ListUserTokens(ctx context.Context, userID string) ([]*storage.Token, error) {
	var rows []models.OAuthToken
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND revoked = ?", userID, false).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]*storage.Token, 0, len(rows))
	for i := range rows {
		out = append(out, fromGormToken(&rows[i]))
	}
	return out, nil
}

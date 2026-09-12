package entstore

import (
	"context"
	"errors"

	"github.com/mwangaben/auth/storage"
	"github.com/mwangaben/auth/storage/entstore/ent"
	"github.com/mwangaben/auth/storage/entstore/ent/oauthclient"
	_ "github.com/mwangaben/auth/storage/entstore/ent/oauthpersonalaccesstoken"
	"github.com/mwangaben/auth/storage/entstore/ent/oauthtoken"
)

// Repository is the Ent-backed implementation of storage.Repository.
type Repository struct {
	client *ent.Client
}

// New builds a Repository from an *ent.Client, or from any value that
// exposes one via a Client() *ent.Client method.
func New(db interface{}) (storage.Repository, error) {
	switch v := db.(type) {
	case *ent.Client:
		return &Repository{client: v}, nil
	case interface{ Client() *ent.Client }:
		return &Repository{client: v.Client()}, nil
	default:
		return nil, errors.New("entstore: expected *ent.Client or a value exposing Client() *ent.Client")
	}
}

func (r *Repository) Name() string { return storage.DriverEnt }

func (r *Repository) AutoMigrate(ctx context.Context) error {
	return r.client.Schema.Create(ctx)
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

func (r *Repository) CreateClient(ctx context.Context, c *storage.Client) error {
	_, err := r.client.OAuthClient.Create().
		SetID(c.ID).
		SetName(c.Name).
		SetSecret(c.Secret).
		SetRedirectURI(c.RedirectURI).
		SetPersonalAccessClient(c.PersonalAccessClient).
		SetPasswordClient(c.PasswordClient).
		SetRevoked(c.Revoked).
		Save(ctx)
	return err
}

func (r *Repository) GetClient(ctx context.Context, id string) (*storage.Client, error) {
	m, err := r.client.OAuthClient.Query().
		Where(oauthclient.ID(id), oauthclient.Revoked(false)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("client not found")
		}
		return nil, err
	}
	return fromEntClient(m), nil
}

func (r *Repository) RevokeClient(ctx context.Context, id string) error {
	return r.client.OAuthClient.UpdateOneID(id).SetRevoked(true).Exec(ctx)
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

func (r *Repository) CreateToken(ctx context.Context, t *storage.Token) error {
	b := r.client.OAuthToken.Create().
		SetID(t.ID).
		SetUserID(t.UserID).
		SetRevoked(t.Revoked).
		SetAccessToken(t.AccessToken).
		SetRefreshToken(t.RefreshToken).
		SetExpiresAt(t.ExpiresAt)

	if t.ClientID != "" {
		b = b.SetClientID(t.ClientID)
	}
	if t.Name != "" {
		b = b.SetName(t.Name)
	}
	if t.Scopes != "" {
		b = b.SetScopes(t.Scopes)
	}

	_, err := b.Save(ctx)
	return err
}

func (r *Repository) GetTokenByAccessToken(ctx context.Context, at string) (*storage.Token, error) {
	m, err := r.client.OAuthToken.Query().
		Where(oauthtoken.AccessToken(at), oauthtoken.Revoked(false)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("token not found or revoked")
		}
		return nil, err
	}
	return fromEntToken(m), nil
}

func (r *Repository) GetTokenByRefreshToken(ctx context.Context, rt string) (*storage.Token, error) {
	m, err := r.client.OAuthToken.Query().
		Where(oauthtoken.RefreshToken(rt), oauthtoken.Revoked(false)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("invalid refresh token")
		}
		return nil, err
	}
	return fromEntToken(m), nil
}

func (r *Repository) RevokeToken(ctx context.Context, id string) error {
	return r.client.OAuthToken.UpdateOneID(id).SetRevoked(true).Exec(ctx)
}

func (r *Repository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	_, err := r.client.OAuthToken.Update().
		Where(oauthtoken.UserID(userID), oauthtoken.Revoked(false)).
		SetRevoked(true).
		Save(ctx)
	return err
}

func (r *Repository) UpdateToken(ctx context.Context, t *storage.Token) error {
	return r.client.OAuthToken.UpdateOneID(t.ID).
		SetRevoked(t.Revoked).
		SetExpiresAt(t.ExpiresAt).
		SetAccessToken(t.AccessToken).
		SetRefreshToken(t.RefreshToken).
		Exec(ctx)
}

// ---------------------------------------------------------------------------
// Personal Access Tokens
// ---------------------------------------------------------------------------

func (r *Repository) CreatePersonalAccessToken(ctx context.Context, p *storage.PersonalAccessToken) error {
	_, err := r.client.OAuthPersonalAccessToken.Create().
		SetID(p.ID).
		SetTokenID(p.TokenID).
		SetUserID(p.UserID).
		SetName(p.Name).
		SetRevoked(p.Revoked).
		SetExpiresAt(p.ExpiresAt).
		Save(ctx)
	return err
}

// ---------------------------------------------------------------------------
// Mappers
// ---------------------------------------------------------------------------

func fromEntClient(m *ent.OAuthClient) *storage.Client {
	return &storage.Client{
		ID:                   m.ID,
		Name:                 m.Name,
		Secret:               m.Secret,
		RedirectURI:          m.RedirectURI,
		PersonalAccessClient: m.PersonalAccessClient,
		PasswordClient:       m.PasswordClient,
		Revoked:              m.Revoked,
		CreatedAt:            m.CreatedAt,
		UpdatedAt:            m.UpdatedAt,
	}
}

func fromEntToken(m *ent.OAuthToken) *storage.Token {
	return &storage.Token{
		ID:           m.ID,
		UserID:       m.UserID,
		ClientID:     m.ClientID,
		Name:         m.Name,
		Scopes:       m.Scopes,
		Revoked:      m.Revoked,
		AccessToken:  m.AccessToken,
		RefreshToken: m.RefreshToken,
		ExpiresAt:    m.ExpiresAt,
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}
}

func (r *Repository) ListUserTokens(ctx context.Context, userID string) ([]*storage.Token, error) {
	rows, err := r.client.OAuthToken.Query().
		Where(oauthtoken.UserID(userID), oauthtoken.Revoked(false)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*storage.Token, 0, len(rows))
	for _, row := range rows {
		out = append(out, fromEntToken(row))
	}
	return out, nil
}

// compile-time assertion that Repository satisfies the storage interface
var _ storage.Repository = (*Repository)(nil)

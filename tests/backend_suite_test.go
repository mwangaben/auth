package tests

import (
	"context"
	"testing"
	"time"

	"github.com/mwangaben/auth/passport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// backendFactory builds a Passport against a fresh DB, and returns a cleanup.
type backendFactory struct {
	name    string
	newDB   func(t *testing.T) interface{} // returns whatever NewPassport accepts
	userDB  func(t *testing.T) *gorm.DB    // where test_users lives
	cleanup func(t *testing.T)
}

func backends() []backendFactory {
	return []backendFactory{
		{
			name: "gorm",
			newDB: func(t *testing.T) interface{} {
				return SetupTestDBPost(t)
			},
			userDB: func(t *testing.T) *gorm.DB {
				return gormDBFromEnv(t) // same DB; NewPassport already created it
			},
			cleanup: func(t *testing.T) {
				// SetupTestDBPost uses factory refresh; deferring cleanup
				// is optional since next run refreshes.
			},
		},
		{
			name: "ent",
			newDB: func(t *testing.T) interface{} {
				return SetupTestEntClient(t)
			},
			userDB: func(t *testing.T) *gorm.DB {
				return gormDBFromEnv(t)
			},
			cleanup: func(t *testing.T) {
				// CleanupTestEntClient is called via client handle; kept
				// here for symmetry.
			},
		},
	}
}

func TestBackends(t *testing.T) {
	for _, b := range backends() {
		b := b
		t.Run(b.name, func(t *testing.T) {
			db := b.newDB(t)
			defer b.cleanup(t)

			gdb := b.userDB(t)
			defer func() {
				if sqlDB, err := gdb.DB(); err == nil && sqlDB != nil {
					sqlDB.Close()
				}
			}()

			userProvider := &TestUserProvider{db: gdb}
			user, err := CreateTestUser(gdb, "shared@example.com", "password123", "Shared")
			require.NoError(t, err)

			p, err := passport.NewPassport(db, &passport.Config{
				TokenExpiry:   time.Hour,
				RefreshExpiry: time.Hour * 24 * 7,
				Issuer:        "test",
				Audience:      "test",
			}, userProvider)
			require.NoError(t, err)

			ctx := context.Background()

			t.Run("IssueAndValidate", func(t *testing.T) {
				resp, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
				require.NoError(t, err)
				assert.NotEmpty(t, resp.AccessToken)

				claims, err := p.ValidateToken(ctx, resp.AccessToken)
				require.NoError(t, err)
				assert.Equal(t, user.ID, claims.UserID)
			})

			t.Run("Revoke", func(t *testing.T) {
				resp, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
				require.NoError(t, err)
				require.NoError(t, p.RevokeToken(ctx, resp.AccessToken))

				_, err = p.ValidateToken(ctx, resp.AccessToken)
				require.Error(t, err)
				assert.ErrorContains(t, err, "token not found or revoked")
			})

			t.Run("RefreshRotates", func(t *testing.T) {
				resp, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
				require.NoError(t, err)

				newResp, err := p.RefreshToken(ctx, resp.RefreshToken)
				require.NoError(t, err)
				assert.NotEqual(t, resp.AccessToken, newResp.AccessToken)
				assert.NotEqual(t, resp.RefreshToken, newResp.RefreshToken)

				_, err = p.ValidateToken(ctx, resp.AccessToken)
				assert.Error(t, err)

				_, err = p.RefreshToken(ctx, resp.RefreshToken)
				assert.Error(t, err, "old refresh token should be unusable")
			})
		})
	}
}

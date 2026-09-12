package tests

import (
	"context"
	"testing"
	"time"

	"github.com/mwangaben/auth/passport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntPassport(t *testing.T) {
	client := SetupTestEntClient(t)
	defer CleanupTestEntClient(t, client)

	// Reuse the GORM-backed TestUserProvider for user lookups; it queries
	// the same Postgres DB where test_users lives.
	gdb := gormDBFromEnv(t)
	defer func() {
		sqlDB, _ := gdb.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	userProvider := &TestUserProvider{db: gdb}

	user, err := CreateTestUser(gdb, "ent@example.com", "password123", "Ent User")
	require.NoError(t, err)

	p, err := passport.NewPassport(client, &passport.Config{
		TokenExpiry:   time.Hour,
		RefreshExpiry: time.Hour * 24 * 7,
		Issuer:        "test",
		Audience:      "test",
		StorageDriver: "ent", // explicit; also tests the override path
	}, userProvider)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("IssueToken", func(t *testing.T) {
		resp, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read", "write"})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Greater(t, resp.ExpiresIn, int64(0))
	})

	t.Run("ValidateToken", func(t *testing.T) {
		resp, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
		require.NoError(t, err)

		claims, err := p.ValidateToken(ctx, resp.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, user.ID, claims.UserID)
		assert.Equal(t, "test-client", claims.ClientID)
		assert.ElementsMatch(t, []string{"read"}, claims.Scopes)
	})

	t.Run("RefreshToken", func(t *testing.T) {
		resp, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
		require.NoError(t, err)

		newResp, err := p.RefreshToken(ctx, resp.RefreshToken)
		require.NoError(t, err)

		assert.NotEqual(t, resp.AccessToken, newResp.AccessToken)
		assert.NotEqual(t, resp.RefreshToken, newResp.RefreshToken)

		// Old access token must now fail
		_, err = p.ValidateToken(ctx, resp.AccessToken)
		assert.Error(t, err)

		// New access token must succeed
		claims, err := p.ValidateToken(ctx, newResp.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, user.ID, claims.UserID)

		// Old refresh token must now fail (rotation)
		_, err = p.RefreshToken(ctx, resp.RefreshToken)
		assert.Error(t, err)
	})

	t.Run("RevokeToken", func(t *testing.T) {
		resp, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
		require.NoError(t, err)

		require.NoError(t, p.RevokeToken(ctx, resp.AccessToken))

		_, err = p.ValidateToken(ctx, resp.AccessToken)
		require.Error(t, err)
		assert.ErrorContains(t, err, "token not found or revoked")
	})

	t.Run("PersonalAccessToken", func(t *testing.T) {
		resp, err := p.IssuePersonalAccessToken(ctx, user.ID, "ent-pat", []string{"read", "write"}, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)

		claims, err := p.ValidateToken(ctx, resp.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, user.ID, claims.UserID)
	})

	t.Run("RevokeAllTokens", func(t *testing.T) {
		// Fresh batch
		for i := 0; i < 3; i++ {
			_, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
			require.NoError(t, err)
		}

		require.NoError(t, p.RevokeAllTokens(ctx, user.ID))

		active, err := p.GetRepository().ListUserTokens(ctx, user.ID)
		require.NoError(t, err)
		assert.Empty(t, active, "all tokens should be revoked")
	})
}

func TestEntClientManagement(t *testing.T) {
	client := SetupTestEntClient(t)
	defer CleanupTestEntClient(t, client)

	gdb := gormDBFromEnv(t)
	defer func() {
		sqlDB, _ := gdb.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()
	userProvider := &TestUserProvider{db: gdb}

	p, err := passport.NewPassport(client, &passport.Config{
		TokenExpiry:   time.Hour,
		RefreshExpiry: time.Hour * 24 * 7,
		Issuer:        "test",
		Audience:      "test",
		StorageDriver: "ent",
	}, userProvider)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("CreateClient", func(t *testing.T) {
		c, secret, err := p.CreateClient(ctx, "Ent Client", "http://localhost:8080/cb", false, false)
		require.NoError(t, err)
		assert.NotEmpty(t, c.ID)
		assert.NotEmpty(t, secret)
		assert.Equal(t, "Ent Client", c.Name)
	})

	t.Run("GetClient", func(t *testing.T) {
		created, _, err := p.CreateClient(ctx, "Get Me", "http://localhost:8080/cb", false, false)
		require.NoError(t, err)

		found, err := p.GetClient(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, found.ID)
		assert.Equal(t, "Get Me", found.Name)
	})

	t.Run("RevokeClient", func(t *testing.T) {
		created, _, err := p.CreateClient(ctx, "Revoke Me", "http://localhost:8080/cb", false, false)
		require.NoError(t, err)

		require.NoError(t, p.RevokeClient(ctx, created.ID))

		_, err = p.GetClient(ctx, created.ID)
		require.Error(t, err)
		assert.ErrorContains(t, err, "client not found")
	})
}

package tests

import (
	"context"
	"testing"
	"time"

	"github.com/mwangaben/auth/models"
	"github.com/mwangaben/auth/passport"
)

func TestPassport(t *testing.T) {
	db := SetupTestDB(t)
	defer CleanupTestDB(db)

	userProvider := &TestUserProvider{db: db}

	// Create test user
	user, err := CreateTestUser(db, "test@example.com", "password123", "Test User")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create passport
	p, err := passport.NewPassport(db, &passport.Config{
		TokenExpiry:   time.Hour,
		RefreshExpiry: time.Hour * 24 * 7,
		Issuer:        "test",
		Audience:      "test",
	}, userProvider)
	if err != nil {
		t.Fatalf("Failed to create passport: %v", err)
	}

	ctx := context.Background()

	// Test IssueToken
	t.Run("IssueToken", func(t *testing.T) {
		tokenResponse, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read", "write"})
		if err != nil {
			t.Fatalf("Failed to issue token: %v", err)
		}

		if tokenResponse.AccessToken == "" {
			t.Error("Access token is empty")
		}
		if tokenResponse.RefreshToken == "" {
			t.Error("Refresh token is empty")
		}
		if tokenResponse.TokenType != "Bearer" {
			t.Errorf("Expected token type 'Bearer', got '%s'", tokenResponse.TokenType)
		}
		if tokenResponse.ExpiresIn <= 0 {
			t.Errorf("Expected expires_in > 0, got %d", tokenResponse.ExpiresIn)
		}
	})

	// Test ValidateToken
	t.Run("ValidateToken", func(t *testing.T) {
		// Issue a token first
		tokenResponse, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
		if err != nil {
			t.Fatalf("Failed to issue token: %v", err)
		}

		// Validate the token
		claims, err := p.ValidateToken(tokenResponse.AccessToken)
		if err != nil {
			t.Fatalf("Failed to validate token: %v", err)
		}

		if claims.UserID != user.ID {
			t.Errorf("Expected user ID %s, got %s", user.ID, claims.UserID)
		}
	})

	// Test RefreshToken - FIXED: Use correct assertions
	t.Run("RefreshToken", func(t *testing.T) {
		// Issue a token first
		tokenResponse, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
		if err != nil {
			t.Fatalf("Failed to issue token: %v", err)
		}

		// Refresh the token
		newTokenResponse, err := p.RefreshToken(ctx, tokenResponse.RefreshToken)
		if err != nil {
			t.Fatalf("Failed to refresh token: %v", err)
		}

		// The access token should be different (it's a new token)
		if newTokenResponse.AccessToken == tokenResponse.AccessToken {
			t.Error("Access token should be different after refresh")
		}

		// The refresh token should also be different
		if newTokenResponse.RefreshToken == tokenResponse.RefreshToken {
			t.Error("Refresh token should be different after refresh")
		}

		// Validate the new token
		claims, err := p.ValidateToken(newTokenResponse.AccessToken)
		if err != nil {
			t.Errorf("New token should be valid: %v", err)
		}
		if claims.UserID != user.ID {
			t.Errorf("Expected user ID %s, got %s", user.ID, claims.UserID)
		}

		// The old token should be revoked
		_, err = p.ValidateToken(tokenResponse.AccessToken)
		if err == nil {
			t.Error("Old token should be revoked")
		}
	})

	// Test RevokeToken - FIXED: The assertion is correct now
	t.Run("RevokeToken", func(t *testing.T) {
		// Issue a token first
		tokenResponse, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
		if err != nil {
			t.Fatalf("Failed to issue token: %v", err)
		}

		// Revoke the token
		err = p.RevokeToken(ctx, tokenResponse.AccessToken)
		if err != nil {
			t.Fatalf("Failed to revoke token: %v", err)
		}

		// Try to validate the revoked token - should fail
		_, err = p.ValidateToken(tokenResponse.AccessToken)
		if err == nil {
			t.Error("Expected error when validating revoked token")
		}

		// Check that the token is marked as revoked in the database
		var token models.Token
		result := p.GetDB().Where("access_token = ?", tokenResponse.AccessToken).First(&token)
		if result.Error != nil {
			t.Fatalf("Failed to find token in database: %v", result.Error)
		}
		if !token.Revoked {
			t.Error("Token should be marked as revoked in database")
		}
	})

	// Test Personal Access Token
	t.Run("PersonalAccessToken", func(t *testing.T) {
		tokenResponse, err := p.IssuePersonalAccessToken(ctx, user.ID, "test-pat", []string{"read", "write"}, nil)
		if err != nil {
			t.Fatalf("Failed to issue personal access token: %v", err)
		}

		if tokenResponse.AccessToken == "" {
			t.Error("Access token is empty")
		}
		if tokenResponse.TokenType != "Bearer" {
			t.Errorf("Expected token type 'Bearer', got '%s'", tokenResponse.TokenType)
		}
	})

	// Test RevokeAllTokens
	t.Run("RevokeAllTokens", func(t *testing.T) {
		// Issue multiple tokens
		for i := 0; i < 3; i++ {
			_, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
			if err != nil {
				t.Fatalf("Failed to issue token: %v", err)
			}
		}

		// Revoke all tokens
		err := p.RevokeAllTokens(ctx, user.ID)
		if err != nil {
			t.Fatalf("Failed to revoke all tokens: %v", err)
		}

		// Check that all tokens are revoked
		var tokens []models.Token
		p.GetDB().Where("user_id = ? AND revoked = ?", user.ID, false).Find(&tokens)
		if len(tokens) > 0 {
			t.Errorf("Expected 0 active tokens, got %d", len(tokens))
		}
	})
}

func TestClientManagement(t *testing.T) {
	db := SetupTestDB(t)
	defer CleanupTestDB(db)

	userProvider := &TestUserProvider{db: db}

	p, err := passport.NewPassport(db, &passport.Config{
		TokenExpiry:   time.Hour,
		RefreshExpiry: time.Hour * 24 * 7,
		Issuer:        "test",
		Audience:      "test",
	}, userProvider)
	if err != nil {
		t.Fatalf("Failed to create passport: %v", err)
	}

	ctx := context.Background()

	t.Run("CreateClient", func(t *testing.T) {
		client, secret, err := p.CreateClient(ctx, "Test Client", "http://localhost:8080/callback", false, false)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		if client.ID == "" {
			t.Error("Client ID is empty")
		}
		if secret == "" {
			t.Error("Client secret is empty")
		}
		if client.Name != "Test Client" {
			t.Errorf("Expected name 'Test Client', got '%s'", client.Name)
		}
	})

	t.Run("GetClient", func(t *testing.T) {
		client, _, err := p.CreateClient(ctx, "Get Test", "http://localhost:8080/callback", false, false)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		found, err := p.GetClient(ctx, client.ID)
		if err != nil {
			t.Fatalf("Failed to get client: %v", err)
		}
		if found.ID != client.ID {
			t.Errorf("Expected client ID %s, got %s", client.ID, found.ID)
		}
	})

	t.Run("RevokeClient", func(t *testing.T) {
		client, _, err := p.CreateClient(ctx, "Revoke Test", "http://localhost:8080/callback", false, false)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		err = p.RevokeClient(ctx, client.ID)
		if err != nil {
			t.Fatalf("Failed to revoke client: %v", err)
		}

		_, err = p.GetClient(ctx, client.ID)
		if err == nil {
			t.Error("Expected error when getting revoked client")
		}
	})
}

// Debug test to see what's happening with revocation
func TestDebugRevocation(t *testing.T) {
	db := SetupTestDB(t)
	defer CleanupTestDB(db)

	userProvider := &TestUserProvider{db: db}

	// Create test user
	user, err := CreateTestUser(db, "debug@example.com", "password123", "Debug User")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create passport
	p, err := passport.NewPassport(db, &passport.Config{
		TokenExpiry:   time.Hour,
		RefreshExpiry: time.Hour * 24 * 7,
		Issuer:        "test",
		Audience:      "test",
	}, userProvider)
	if err != nil {
		t.Fatalf("Failed to create passport: %v", err)
	}

	ctx := context.Background()

	// Issue token
	tokenResponse, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
	if err != nil {
		t.Fatalf("Failed to issue token: %v", err)
	}

	t.Logf("Access Token: %s", tokenResponse.AccessToken[:20]+"...")
	t.Logf("Refresh Token: %s", tokenResponse.RefreshToken[:20]+"...")

	// Validate token before revocation
	claims, err := p.ValidateToken(tokenResponse.AccessToken)
	if err != nil {
		t.Fatalf("Token should be valid before revocation: %v", err)
	}
	t.Logf("User ID from claims: %s", claims.UserID)

	// Revoke the token
	err = p.RevokeToken(ctx, tokenResponse.AccessToken)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}
	t.Log("Token revoked successfully")

	// Check in database
	var token models.Token
	db.Where("access_token = ?", tokenResponse.AccessToken).First(&token)
	t.Logf("Token in DB: Revoked=%v, ExpiresAt=%v", token.Revoked, token.ExpiresAt)

	// Try to validate after revocation
	_, err = p.ValidateToken(tokenResponse.AccessToken)
	if err != nil {
		t.Logf("Validation after revocation failed as expected: %v", err)
	} else {
		t.Error("Token should be invalid after revocation")
	}
}

func TestDebugRefreshToken(t *testing.T) {
	db := SetupTestDB(t)
	defer CleanupTestDB(db)

	userProvider := &TestUserProvider{db: db}

	// Create test user
	user, err := CreateTestUser(db, "debug2@example.com", "password123", "Debug User 2")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create passport
	p, err := passport.NewPassport(db, &passport.Config{
		TokenExpiry:   time.Hour,
		RefreshExpiry: time.Hour * 24 * 7,
		Issuer:        "test",
		Audience:      "test",
	}, userProvider)
	if err != nil {
		t.Fatalf("Failed to create passport: %v", err)
	}

	ctx := context.Background()

	// Issue token
	tokenResponse, err := p.IssueToken(ctx, user.ID, "test-client", []string{"read"})
	if err != nil {
		t.Fatalf("Failed to issue token: %v", err)
	}

	t.Logf("Original Access Token: %s", tokenResponse.AccessToken[:20]+"...")
	t.Logf("Original Refresh Token: %s", tokenResponse.RefreshToken[:20]+"...")

	// Refresh the token
	newTokenResponse, err := p.RefreshToken(ctx, tokenResponse.RefreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	t.Logf("New Access Token: %s", newTokenResponse.AccessToken[:20]+"...")
	t.Logf("New Refresh Token: %s", newTokenResponse.RefreshToken[:20]+"...")

	// Check if they are different
	if newTokenResponse.AccessToken == tokenResponse.AccessToken {
		t.Error("Access token should be different after refresh")
	} else {
		t.Log("✅ Access token is different (good!)")
	}

	if newTokenResponse.RefreshToken == tokenResponse.RefreshToken {
		t.Error("Refresh token should be different after refresh")
	} else {
		t.Log("✅ Refresh token is different (good!)")
	}
}

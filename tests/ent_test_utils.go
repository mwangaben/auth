package tests

import (
	"context"
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx" driver
	_ "github.com/lib/pq"              // registers "postgres" driver
	"github.com/mwangaben/auth/models"
	"github.com/mwangaben/auth/storage/entstore/ent"
	"github.com/mwangaben/factory/factory"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"testing"
)

// SetupTestEntClient:
//  1. Connects GORM (same DB) and uses factory to DROP ALL TABLES.
//  2. Re-migrates GORM models so the shared test_users table exists.
//  3. Opens an Ent client on the same DB and calls Schema.Create.
//
// This mirrors the GORM flow: drop everything → re-create → clean slate.
func SetupTestEntClient(t *testing.T) *ent.Client {
	t.Helper()

	//dbPassword := getEnv("DB_PASSWORD", "")
	//dbSSLMode := getEnv("DB_SSLMODE", "disable")

	// ── 1. GORM connection on the same DB, refresh (drop all + migrate) ───
	gdb := gormDBFromEnv(t)
	defer func() {
		if sqlDB, err := gdb.DB(); err == nil && sqlDB != nil {
			sqlDB.Close()
		}
	}()

	if err := factory.NewDatabaseHelper(gdb).RefreshDatabase(
		&TestUser{},
		&models.OAuthClient{},
		&models.OAuthToken{},
		&models.OAuthPersonalAccessToken{},
	); err != nil {
		t.Fatalf("failed refreshing database: %v", err)
	}

	// The factory just migrated the GORM schema. Now DROP the OAuth tables
	// so Ent can create them with its own column layout. We keep test_users
	// because Ent doesn't manage it.
	if err := gdb.Exec(`DROP TABLE IF EXISTS oauth_access_tokens CASCADE`).Error; err != nil {
		t.Fatalf("drop oauth_access_tokens: %v", err)
	}
	if err := gdb.Exec(`DROP TABLE IF EXISTS oauth_clients CASCADE`).Error; err != nil {
		t.Fatalf("drop oauth_clients: %v", err)
	}
	if err := gdb.Exec(`DROP TABLE IF EXISTS oauth_personal_access_tokens CASCADE`).Error; err != nil {
		t.Fatalf("drop oauth_personal_access_tokens: %v", err)
	}

	// ── 2. Ent client on the same DB ──────────────────────────────────────
	dsn := postgresDSN()
	drv, err := entsql.Open(dialect.Postgres, dsn)
	if err != nil {
		t.Fatalf("failed opening ent driver: %v", err)
	}

	client := ent.NewClient(ent.Driver(drv))

	// Ent creates oauth_clients, oauth_access_tokens, oauth_personal_access_tokens
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatalf("failed creating ent schema: %v", err)
	}

	return client
}

func CleanupTestEntClient(t *testing.T, client *ent.Client) {
	t.Helper()
	if client == nil {
		return
	}
	_ = client.Close()
}

// postgresDSN builds a Postgres DSN from the environment, matching the
// defaults used by SetupTestDBPost.
func postgresDSN() string {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "benedictmwanga")
	pass := getEnv("DB_PASSWORD", "")
	name := getEnv("DB_NAME", "auth_test")
	ssl := getEnv("DB_SSLMODE", "disable")

	if pass != "" {
		return fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			host, port, user, pass, name, ssl,
		)
	}
	return fmt.Sprintf(
		"host=%s port=%s user=%s dbname=%s sslmode=%s",
		host, port, user, name, ssl,
	)
}

// SetupTestEntClient opens an Ent client against the same Postgres test DB
// used by SetupTestDBPost, drops existing tables, and re-creates the schema.

func dropEntTables(t *testing.T, client *ent.Client) {
	t.Helper()
	ctx := context.Background()
	// Order matters if FKs exist; here there are none, but keep it defensive.
	if _, err := client.OAuthToken.Delete().Exec(ctx); err != nil && !ent.IsNotFound(err) {
		// ignore: table may not exist yet
	}
	if _, err := client.OAuthPersonalAccessToken.Delete().Exec(ctx); err != nil && !ent.IsNotFound(err) {
		// ignore
	}
	if _, err := client.OAuthClient.Delete().Exec(ctx); err != nil && !ent.IsNotFound(err) {
		// ignore
	}
}

func gormDBFromEnv(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s dbname=%s sslmode=%s",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "benedictmwanga"),
		getEnv("DB_NAME", "auth_test"),
		getEnv("DB_SSLMODE", "disable"),
	)
	if pw := getEnv("DB_PASSWORD", ""); pw != "" {
		dsn = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			getEnv("DB_HOST", "localhost"),
			getEnv("DB_PORT", "5432"),
			getEnv("DB_USER", "benedictmwanga"),
			pw,
			getEnv("DB_NAME", "auth_test"),
			getEnv("DB_SSLMODE", "disable"),
		)
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed opening gorm db: %v", err)
	}
	return db
}

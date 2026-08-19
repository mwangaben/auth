package tests

import (
	"context"
	"fmt"
	"github.com/mwangaben/factory/factory"
	"gorm.io/driver/postgres"
	"gorm.io/gorm/logger"
	"os"
	"testing"
	"time"

	"github.com/mwangaben/auth/models"
	"github.com/mwangaben/auth/passport"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// TestUser is a test user model
type TestUser struct {
	ID        string `gorm:"primaryKey;type:varchar(255)"`
	Email     string `gorm:"uniqueIndex;type:varchar(255)"`
	Password  string `gorm:"type:varchar(255)"`
	Name      string `gorm:"type:varchar(255)"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TestUserProvider implements passport.UserProvider
type TestUserProvider struct {
	db *gorm.DB
}

func (p *TestUserProvider) FindByCredentials(ctx context.Context, email, password string) (interface{}, error) {
	var user TestUser
	if err := p.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	if !passport.VerifyPassword(user.Password, password) {
		return nil, nil
	}
	return &user, nil
}

func (p *TestUserProvider) FindByID(ctx context.Context, id string) (interface{}, error) {
	var user TestUser
	if err := p.db.Where("id = ?", id).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *TestUserProvider) FindByEmail(ctx context.Context, email string) (interface{}, error) {
	var user TestUser
	if err := p.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *TestUserProvider) GetUserID(user interface{}) string {
	if u, ok := user.(*TestUser); ok {
		return u.ID
	}
	return ""
}

// getEnv gets environment variable or returns default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// SetupTestDB sets up a test database using MariaDB
func SetupTestDB(t *testing.T) *gorm.DB {
	// Get database configuration from environment with defaults
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "3306")
	dbUser := getEnv("DB_USER", "root")
	dbPassword := getEnv("DB_PASSWORD", "root")
	dbName := getEnv("DB_NAME", "auth_test")

	// Build DSN for MariaDB
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbUser,
		dbPassword,
		dbHost,
		dbPort,
		dbName,
	)

	// Connect to database
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto migrate models
	if err := db.AutoMigrate(&TestUser{}, &models.Client{}, &models.Token{}, &models.PersonalAccessToken{}); err != nil {
		t.Fatalf("Failed to migrate: %v", err)
	}

	// Clean up existing data
	db.Exec("SET FOREIGN_KEY_CHECKS = 0")
	db.Exec("TRUNCATE TABLE oauth_access_tokens")
	db.Exec("TRUNCATE TABLE oauth_clients")
	db.Exec("TRUNCATE TABLE oauth_personal_access_tokens")
	db.Exec("TRUNCATE TABLE test_users")
	db.Exec("SET FOREIGN_KEY_CHECKS = 1")

	return db
}

// CreateTestUser creates a test user
func CreateTestUser(db *gorm.DB, email, password, name string) (*TestUser, error) {
	hashedPassword, err := passport.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &TestUser{
		ID:       "test-user-1",
		Email:    email,
		Password: hashedPassword,
		Name:     name,
	}

	if err := db.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

// CleanupTestDB cleans up the test database
func CleanupTestDB(db *gorm.DB) {
	if db != nil {
		db.Exec("SET FOREIGN_KEY_CHECKS = 0")
		db.Exec("TRUNCATE TABLE oauth_access_tokens")
		db.Exec("TRUNCATE TABLE oauth_clients")
		db.Exec("TRUNCATE TABLE oauth_personal_access_tokens")
		db.Exec("TRUNCATE TABLE test_users")
		db.Exec("SET FOREIGN_KEY_CHECKS = 1")

		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}
}

// SetupTestDBPost sets up a test database using PostgreSQL and factory helper
func SetupTestDBPost(t *testing.T) *gorm.DB {
	// Get database configuration from environment with PostgreSQL defaults
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "benedictmwanga")
	dbPassword := getEnv("DB_PASSWORD", "")
	dbName := getEnv("DB_NAME", "auth_test")
	dbSSLMode := getEnv("DB_SSLMODE", "disable")

	// Build DSN for PostgreSQL
	var dsn string
	if dbPassword != "" {
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			dbHost, dbPort, dbUser, dbPassword, dbName, dbSSLMode)
	} else {
		dsn = fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=%s",
			dbHost, dbPort, dbUser, dbName, dbSSLMode)
	}

	// Connect to database
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Use factory helper to refresh database
	// This will drop all tables and recreate them with proper PostgreSQL syntax
	err = factory.NewDatabaseHelper(db).RefreshDatabase(
		&TestUser{},
		&models.Client{},
		&models.Token{},
		&models.PersonalAccessToken{},
	)
	if err != nil {
		t.Fatalf("Failed to refresh database: %v", err)
	}

	return db
}

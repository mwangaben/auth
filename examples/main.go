package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/mwangaben/auth/middleware"
	"github.com/mwangaben/auth/passport"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// User model for the example
type User struct {
	ID       string `gorm:"primaryKey"`
	Email    string `gorm:"uniqueIndex"`
	Password string
	Name     string
}

// UserProvider implements passport.UserProvider
type UserProvider struct {
	db *gorm.DB
}

func (p *UserProvider) FindByCredentials(ctx context.Context, email, password string) (interface{}, error) {
	var user User
	if err := p.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	if !passport.VerifyPassword(user.Password, password) {
		return nil, nil
	}
	return &user, nil
}

func (p *UserProvider) FindByID(ctx context.Context, id string) (interface{}, error) {
	var user User
	if err := p.db.Where("id = ?", id).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *UserProvider) FindByEmail(ctx context.Context, email string) (interface{}, error) {
	var user User
	if err := p.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *UserProvider) GetUserID(user interface{}) string {
	if u, ok := user.(*User); ok {
		return u.ID
	}
	return ""
}

func main() {
	// Setup database
	db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto migrate
	db.AutoMigrate(&User{})

	// Create test user
	hashedPassword, _ := passport.HashPassword("password123")
	db.Create(&User{
		ID:       "user-1",
		Email:    "user@example.com",
		Password: hashedPassword,
		Name:     "Test User",
	})

	// Create user provider
	userProvider := &UserProvider{db: db}

	// Create passport
	p, err := passport.NewPassport(db, &passport.Config{
		TokenExpiry:   time.Hour * 24,
		RefreshExpiry: time.Hour * 24 * 7,
		Issuer:        "example",
		Audience:      "example",
	}, userProvider)
	if err != nil {
		log.Fatalf("Failed to create passport: %v", err)
	}

	// Login handler
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Authenticate user
		user, err := p.Authenticate(r.Context(), req.Email, req.Password)
		if err != nil || user == nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Issue token
		userID := p.GetUserID(user)
		token, err := p.IssueToken(r.Context(), userID, "", []string{"read", "write"})
		if err != nil {
			http.Error(w, "Failed to issue token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	})

	// Protected handler
	http.Handle("/protected", middleware.AuthMiddleware(p)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := middleware.GetUserFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "This is a protected route",
			"user":    user,
		})
	})))

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

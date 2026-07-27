package passport

import "context"

// UserProvider interface for authenticating users
type UserProvider interface {
	// FindByCredentials finds a user by email and password
	FindByCredentials(ctx context.Context, email, password string) (interface{}, error)

	// FindByID finds a user by ID
	FindByID(ctx context.Context, id string) (interface{}, error)

	// FindByEmail finds a user by email
	FindByEmail(ctx context.Context, email string) (interface{}, error)

	// GetUserID returns the user ID as a string
	GetUserID(user interface{}) string
}

// DefaultUserProvider is a simple implementation of UserProvider
type DefaultUserProvider struct {
	// This would be implemented by the application
}

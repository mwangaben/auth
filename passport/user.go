package passport

import "context"

// GetUserByID retrieves a user by ID from the provider
func (p *Passport) GetUserByID(ctx context.Context, userID string) (interface{}, error) {
	return p.userProvider.FindByID(ctx, userID)
}

// Authenticate authenticates a user by credentials
func (p *Passport) Authenticate(ctx context.Context, email, password string) (interface{}, error) {
	return p.userProvider.FindByCredentials(ctx, email, password)
}

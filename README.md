# Auth Package

A Laravel Passport-like authentication package for Go with JWT support.

## Features

- ✅ OAuth2 server implementation
- ✅ JWT token generation and validation
- ✅ Personal access tokens
- ✅ Refresh tokens
- ✅ Client management
- ✅ Password grant flow
- ✅ Token revocation
- ✅ Middleware support
- ✅ GORM integration
- ✅ Full test coverage

## Installation

```bash
go get github.com/mwangaben/auth
```

## Quick Start

### 1. Create a Passport instance
```go
import (
    "github.com/mwangaben/auth/passport"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

db, _ := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})

p, err := passport.NewPassport(db, &passport.Config{
    TokenExpiry:   time.Hour * 24,
    RefreshExpiry: time.Hour * 24 * 7,
    Issuer:        "myapp",
    Audience:      "myapp",
}, userProvider)
```

### 2. Implement UserProvider

```go
type UserProvider struct {
    db *gorm.DB
}

func (p *UserProvider) FindByCredentials(ctx context.Context, email, password string) (interface{}, error) {
    // Find user by email and verify password
}

func (p *UserProvider) FindByID(ctx context.Context, id string) (interface{}, error) {
    // Find user by ID
}

func (p *UserProvider) GetUserID(user interface{}) string {
    // Return user ID as string
}
```

### 3. Issue Tokens

```go
// Issue a token
token, err := p.IssueToken(ctx, userID, clientID, []string{"read", "write"})

// Issue a personal access token
token, err := p.IssuePersonalAccessToken(ctx, userID, "My Token", []string{"read"}, nil)
```

### 4. Use Middleware

```go
http.Handle("/protected", middleware.AuthMiddleware(p)(protectedHandler))
```

### Testing
```bash
make test
make test-cover
```

### License
##### MIT






# Auth

A Laravel Passport-like authentication package for Go with JWT support.

## Features

- ✅ OAuth2 server implementation
- ✅ JWT token generation and validation (RS256)
- ✅ Personal access tokens
- ✅ Refresh tokens with rotation and **independent lifetimes**
- ✅ Client management (bcrypt-hashed secrets)
- ✅ Password grant flow
- ✅ Token revocation
- ✅ Middleware support (`net/http`, pluggable)
- ✅ **GORM integration**
- ✅ **Ent integration**
- ✅ **Storage backend auto-detection**
- ✅ Full test coverage (both backends)
- ✅ Zero runtime dependencies beyond GORM, Ent, and the standard library

## Installation

```bash
go get github.com/mwangaben/auth
```

## Storage Backends

Passport is storage-agnostic. It ships with two backends:

| Backend | Driver constant | Pass to `NewPassport` |
|---|---|---|
| GORM | `storage.DriverGorm` | `*gorm.DB` from `gorm.io/gorm` |
| Ent  | `storage.DriverEnt`  | `*ent.Client` from `github.com/mwangaben/auth/storage/entstore/ent` |

The backend is **auto-detected** from the type of the `db` argument. You can
also force one explicitly via `Config.StorageDriver`:

```go
p, err := passport.NewPassport(db, &passport.Config{
    // ...
    StorageDriver: "ent", // or "gorm"
}, userProvider)
```

Both backends share the same SQL table names (`oauth_clients`,
`oauth_access_tokens`, `oauth_personal_access_tokens`). A database created by
one backend can be read by the other without migration.

## Token Lifetimes

Access and refresh tokens have **independent lifetimes**:

| Token | Default | Purpose |
|---|---|---|
| Access | 15 minutes | Authenticates each request. Short-lived by design. |
| Refresh | 7 days | Obtained at login, exchanged for new access tokens. Rotates on every use. |

When an access token expires, the client calls `/refresh` with its refresh
token to get a new pair. The old pair is revoked; the new pair is stored
with fresh expiries. This continues for up to 7 days, after which the user
must log in again.

**Why separate lifetimes?** A refresh token that expired at the same moment
as its access token would be useless. The whole point of a refresh token is
to outlive the access token it issued. See the `Config` section below for
tuning the defaults.

## Quick Start

### 1. Create a Passport instance

#### With GORM

```go
import (
    "time"

    "github.com/mwangaben/auth/passport"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
if err != nil {
    log.Fatalf("failed to open gorm: %v", err)
}

p, err := passport.NewPassport(db, &passport.Config{
    TokenExpiry:   15 * time.Minute,
    RefreshExpiry: 7 * 24 * time.Hour,
    Issuer:        "myapp",
    Audience:      "myapp",
}, userProvider)
if err != nil {
    log.Fatalf("failed to create passport: %v", err)
}
```

#### With Ent

```go
import (
    "time"

    "entgo.io/ent/dialect"
    entsql "entgo.io/ent/dialect/sql"
    _ "github.com/lib/pq"

    "github.com/mwangaben/auth/passport"
    "github.com/mwangaben/auth/storage/entstore/ent"
)

drv, err := entsql.Open(dialect.Postgres, dsn)
if err != nil {
    log.Fatalf("failed to open ent driver: %v", err)
}
client := ent.NewClient(ent.Driver(drv))
defer client.Close()

p, err := passport.NewPassport(client, &passport.Config{
    TokenExpiry:   15 * time.Minute,
    RefreshExpiry: 7 * 24 * time.Hour,
    Issuer:        "myapp",
    Audience:      "myapp",
}, userProvider)
if err != nil {
    log.Fatalf("failed to create passport: %v", err)
}
```

The Ent `client` is constructed from the schemas that ship with this package.
You do **not** need to define your own Ent schema for the OAuth tables.

### 2. Implement `UserProvider`

Passport doesn't know about your user model. You provide four methods:

```go
import (
    "context"

    "github.com/mwangaben/auth/passport"
    "gorm.io/gorm"
)

type UserProvider struct {
    db *gorm.DB
}

func (p *UserProvider) FindByCredentials(ctx context.Context, email, password string) (interface{}, error) {
    var user User
    if err := p.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
        return nil, err
    }
    if !passport.VerifyPassword(user.Password, password) {
        return nil, nil
    }
    return &user, nil
}

func (p *UserProvider) FindByID(ctx context.Context, id string) (interface{}, error) {
    var user User
    if err := p.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
        return nil, err
    }
    return &user, nil
}

func (p *UserProvider) FindByEmail(ctx context.Context, email string) (interface{}, error) {
    var user User
    if err := p.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
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
```

### 3. Issue Tokens

```go
// Access + refresh token pair (typical login flow)
token, err := p.IssueToken(ctx, userID, clientID, []string{"read", "write"})

// Personal access token (long-lived, no refresh token)
token, err := p.IssuePersonalAccessToken(ctx, userID, "My CLI Token", []string{"read"}, nil)
```

`IssueToken` returns a `*TokenResponse`:

```go
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token,omitempty"`
    TokenType    string `json:"token_type"`

    // ExpiresIn is the access token's TTL in seconds. Clients should treat
    // it as "refresh after this many seconds". The refresh token's lifetime
    // is not exposed because clients don't need it.
    ExpiresIn int64 `json:"expires_in"`
}
```

### 4. Validate Tokens

```go
claims, err := p.ValidateToken(ctx, tokenString)
if err != nil {
    // token is invalid, expired, or revoked
}

userID := claims.UserID
scopes := claims.Scopes
```

Validation checks **both** the JWT signature and the database record
(revocation, access-token expiry). A token must pass both to be considered
valid.

If the access token is expired but the refresh token is still valid,
`ValidateToken` returns an error — the caller should then call `RefreshToken`.
This is the expected pattern; it does not mean the user is logged out.

### 5. Refresh Tokens

```go
newToken, err := p.RefreshToken(ctx, refreshToken)
```

Refresh is a **rotation**: the old refresh token is revoked, and a new
access + refresh pair is issued with fresh expiries. Reusing an old refresh
token will fail.

Refreshing only checks the refresh token's expiry. It succeeds even if the
current access token has already expired — that's the point.

### 6. Revoke Tokens

```go
// Revoke a single access token
err := p.RevokeToken(ctx, accessToken)

// Revoke every active token for a user (logout everywhere)
err := p.RevokeAllTokens(ctx, userID)
```

### 7. Client Management

```go
// Create a client — the plain-text secret is returned only once
client, secret, err := p.CreateClient(ctx, "My App", "https://example.com/callback", false, false)

// Verify a client secret
ok := p.VerifyClientSecret(client, presentedSecret)

// Revoke a client
err = p.RevokeClient(ctx, client.ID)
```

### 8. Middleware

```go
import "github.com/mwangaben/auth/middleware"

mux := http.NewServeMux()
mux.Handle("/protected", middleware.AuthMiddleware(p)(protectedHandler))
```

Inside the handler:

```go
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    user := middleware.GetUserFromContext(r.Context())       // interface{}
    claims := middleware.GetTokenFromContext(r.Context())    // *authjwt.Claims
    // ...
}
```

The claims type returned by `GetTokenFromContext` is
`github.com/mwangaben/auth/jwt.Claims`. Import it as:

```go
import authjwt "github.com/mwangaben/auth/jwt"
```

## Configuration

```go
type Config struct {
    // RS256 signing keys. If both are nil, a fresh key pair is generated
    // on startup. In production, provide these to persist across restarts.
    PrivateKey []byte
    PublicKey  []byte

    // Lifetime of access tokens. Defaults to 15 minutes.
    //
    // Should be short — minutes to hours. If an access token leaks, the
    // attacker can only use it until this expires. The refresh token exists
    // precisely so that a short access token doesn't force frequent logins.
    TokenExpiry time.Duration

    // Lifetime of refresh tokens. Defaults to 7 days.
    //
    // Should be long — days to weeks. This is the effective session length:
    // after this, the user must log in again.
    RefreshExpiry time.Duration

    // Standard JWT claims.
    Issuer   string
    Audience string

    // "gorm" | "ent" | "" (auto-detect).
    StorageDriver string
}
```

**`TokenExpiry` must be shorter than `RefreshExpiry`.** If you set them equal
or inverted, the refresh flow cannot work as designed. A future version of
the package may validate this at construction time; for now, it's your
responsibility.

## Background Cleanup

Every refresh inserts a new row in `oauth_access_tokens` and revokes the old
one (a flag change, not a delete). Without cleanup, the table grows
unbounded.

Wire a cleanup goroutine at application startup:

```go
go func() {
    ticker := time.NewTicker(time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        n, err := p.CleanupExpiredTokens(ctx)
        cancel()
        if err != nil {
            log.Printf("auth: token cleanup failed: %v", err)
            continue
        }
        if n > 0 {
            log.Printf("auth: deleted %d expired tokens", n)
        }
    }
}()
```

`CleanupExpiredTokens` deletes rows whose **both** access and refresh windows
have closed. Rows with a still-valid refresh token are kept — the user may
still refresh.

Hourly is a reasonable interval. Adjust to taste. The method is safe to call
concurrently with normal traffic.

## Package Overview

```
auth/
├── passport/       # Public API: NewPassport, IssueToken, ValidateToken, ...
├── jwt/            # Leaf package: JWT signing, verification, Claims type
├── storage/        # Backend-agnostic Repository interface
│   ├── gormstore/  # GORM implementation
│   └── entstore/   # Ent implementation
│       ├── schema/ # Ent schemas
│       └── ent/    # Generated Ent client (do not edit)
├── middleware/     # net/http middleware
├── models/         # GORM models (used by gormstore)
└── errors/         # Shared error values
```

The `jwt` package is a **leaf** — it has no internal dependencies. The
`passport` package orchestrates token policy; the `storage` layer only handles
persistence.

## Testing

The test suite exercises **both** backends against a real Postgres database:

```bash
# Run everything with the race detector
go test ./... -race -count=1

# Just the shared cross-backend conformance suite
go test ./tests/... -run TestBackends -v

# Focus on the Ent backend
go test ./tests/... -run TestEnt -v

# The two-expiry regression test
go test ./tests/... -run TestRefreshTokenOutlivesAccessToken -v
```

Test databases are created and torn down by the helpers in
`tests/test_utils.go`. Set `DB_*` environment variables to point at a
different Postgres instance:

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=postgres
export DB_PASSWORD=secret
export DB_NAME=auth_test
export DB_SSLMODE=disable
```

## Dependency Graph

```
passport ──► jwt
    │
    └──► storage ──► gormstore ──► models
              │
              └──► entstore ──► storage/entstore/ent (generated)
```

`jwt` is a leaf package — it has no internal dependencies. `passport`
orchestrates token policy; the storage layer only handles persistence.

## Migration from v1.0

`v1.1.0` introduced a storage abstraction supporting GORM and Ent. `v1.1.1`
fixed a bug in the token expiry model. Both change the public API in
mechanical ways.

### 1. `NewPassport` accepts `interface{}`

The first argument is now `interface{}` — pass `*gorm.DB` or `*ent.Client`.
Auto-detection selects the backend. To force one:

```go
p, err := passport.NewPassport(db, &passport.Config{
    StorageDriver: "ent", // or "gorm"
}, userProvider)
```

### 2. `ValidateToken` takes a `context.Context`

```go
// old
claims, err := p.ValidateToken(tokenString)

// new
claims, err := p.ValidateToken(ctx, tokenString)
```

Same for `RevokeToken`, `RevokeAllTokens`, `RefreshToken`, `CreateClient`,
`GetClient`, `VerifyClientSecret`, and every other public method on
`*Passport`.

### 3. `passport.Manager` is now `passport.Passport`

The type is still `*Passport`, but the constructor is `NewPassport`, not
`NewManager`. If you had a type alias pointing at `Manager`, remove it.

### 4. Storage backends share schema

The GORM and Ent backends use the **same table names**. If you were running
against GORM in v1.0 and want to switch to Ent:

1. Stop the application.
2. Update the `NewPassport` call to pass `*ent.Client`.
3. Restart.

No data migration needed. The Ent schema declares the same columns and
indexes as the GORM models.

### 5. `jwt` package is a leaf

The `jwt` package no longer imports `passport` or `storage`. If you were
relying on those imports for side effects (unlikely), remove the dependency.

The `jwt.Claims` type is unchanged — the same struct with the same JSON
tags. Existing JWTs continue to validate.

### 6. Auto-migration behavior

`NewPassport` now calls `AutoMigrate` on the selected backend during
construction. If your database user lacks DDL privileges, either:

- Grant them, or
- Call `passport.NewPassport` against a database that already has the
  tables (auto-migration is idempotent), or
- Run the migrations out-of-band using the GORM or Ent migration tooling.

## Migration from v1.1.0

`v1.1.1` splits the single `expires_at` column on `oauth_access_tokens` into
`access_expires_at` and `refresh_expires_at`. The application code no longer
has to know which of the two an "expiry" refers to; the storage layer exposes
both explicitly.

### 1. Schema change

If you use `AutoMigrate` (the default), the new columns are created
automatically on the next `NewPassport` call. If you manage migrations
manually, apply:

```sql
-- Backfill from the old column.
ALTER TABLE oauth_access_tokens
    ADD COLUMN access_expires_at TIMESTAMP;
UPDATE oauth_access_tokens SET access_expires_at = expires_at;
ALTER TABLE oauth_access_tokens
    ALTER COLUMN access_expires_at SET NOT NULL;

ALTER TABLE oauth_access_tokens
    ADD COLUMN refresh_expires_at TIMESTAMP;
-- Best guess: old row's refresh window was the same as its access window.
-- New code will use RefreshExpiry for refresh tokens issued after this point.
UPDATE oauth_access_tokens SET refresh_expires_at = expires_at;
ALTER TABLE oauth_access_tokens
    ALTER COLUMN refresh_expires_at SET NOT NULL;

ALTER TABLE oauth_access_tokens DROP COLUMN expires_at;

CREATE INDEX idx_oauth_access_tokens_access_expires_at
    ON oauth_access_tokens(access_expires_at);
CREATE INDEX idx_oauth_access_tokens_refresh_expires_at
    ON oauth_access_tokens(refresh_expires_at);
```

If your database is fresh (no production data), the simplest path is:

```sql
DROP TABLE oauth_access_tokens;
```

then let `AutoMigrate` recreate it with the correct schema.

### 2. Field rename in `storage.Token` and `models.OAuthToken`

```go
// old
tok.ExpiresAt
tok.IsExpired()
tok.IsValid()

// new
tok.AccessExpiresAt   // when validating an access token
tok.RefreshExpiresAt  // when validating a refresh token
tok.IsAccessTokenExpired()
tok.IsRefreshTokenExpired()
tok.IsAccessTokenValid()
tok.IsRefreshTokenValid()
```

Choose based on what the caller is asking. In nearly every case:

- **Validating a request's bearer token** → `AccessExpiresAt` / `IsAccessTokenExpired()`.
- **Handling a refresh request** → `RefreshExpiresAt` / `IsRefreshTokenExpired()`.
- **Cleanup** → both (the row is only dead when both windows have closed).

### 3. New `Repository` method

```go
DeleteExpiredTokens(ctx context.Context, before time.Time) (int, error)
```

Both backends implement it. Consumers should call it from a scheduled job
(see the "Background Cleanup" section above).

### 4. Default `TokenExpiry` reduced

Was `24 * time.Hour`, now `15 * time.Minute`. If you were relying on the
old default, set `Config.TokenExpiry` explicitly. The shorter default is
now safe because refresh tokens work correctly.

## License

MIT
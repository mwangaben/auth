// Package passport provides a Laravel Passport-like authentication
// layer for Go applications.
//
// Passport is storage-agnostic: it works with either GORM or Ent,
// auto-detected from the database handle passed to NewPassport.
//
// # Basic usage
//
//	db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
//	p, err := passport.NewPassport(db, &passport.Config{
//	    Issuer:   "myapp",
//	    Audience: "myapp",
//	}, userProvider)
//
//	// Issue a token
//	token, err := p.IssueToken(ctx, userID, clientID, []string{"read"})
//
//	// Validate on the next request
//	claims, err := p.ValidateToken(ctx, tokenString)
//
// # Storage backends
//
// Pass two different DB types to switch backends transparently:
//
//	// GORM
//	p, _ := passport.NewPassport(gormDB, cfg, provider)
//
//	// Ent
//	p, _ := passport.NewPassport(entClient, cfg, provider)
//
// See the storage package for the backend contract.
package passport

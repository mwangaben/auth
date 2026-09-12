// middleware/auth_test.go
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mwangaben/auth/passport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// stubs — replace with your real TestUserProvider from tests/
type nopProvider struct{}

func (nopProvider) FindByID(ctx context.Context, id string) (interface{}, error) {
	return &struct{ ID string }{ID: id}, nil
}
func (nopProvider) FindByCredentials(ctx context.Context, e, p string) (interface{}, error) {
	return nil, nil
}
func (nopProvider) FindByEmail(ctx context.Context, e string) (interface{}, error) { return nil, nil }
func (nopProvider) GetUserID(u interface{}) string                                 { return u.(*struct{ ID string }).ID }

func TestAuthMiddleware_MissingHeader(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	p, err := passport.NewPassport(db, &passport.Config{
		TokenExpiry: time.Hour, Issuer: "t", Audience: "t",
	}, nopProvider{})
	require.NoError(t, err)

	h := AuthMiddleware(p)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

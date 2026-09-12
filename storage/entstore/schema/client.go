// storage/entstore/schema/client.go
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"time"
)

// OAuthClient is the schema for OAuth clients.
// Renamed from `Client` to avoid collision with ent's predeclared `Client` type.
type OAuthClient struct{ ent.Schema }

func (OAuthClient) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("name"),
		field.String("secret"),
		field.String("redirect_uri").Optional(),
		field.Bool("personal_access_client").Default(false),
		field.Bool("password_client").Default(false),
		field.Bool("revoked").Default(false),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

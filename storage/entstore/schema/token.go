package schema

import (
	"entgo.io/ent/schema/index"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// OAuthToken is the schema for OAuth tokens.
// Renamed from `Token` to avoid collision with ent's predeclared `Token` type.
type OAuthToken struct{ ent.Schema }

func (OAuthToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("user_id"),
		field.String("client_id").Optional(),
		field.String("name").Optional(),
		field.Text("scopes").Optional(),
		field.Bool("revoked").Default(false),
		field.Text("access_token"),
		field.Text("refresh_token").Optional(),
		field.Time("expires_at"),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (OAuthToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("client_id"),
	}
}

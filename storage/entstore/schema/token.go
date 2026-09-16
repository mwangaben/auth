// storage/entstore/schema/token.go
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthToken is the Ent schema for the oauth_access_tokens table.
type OAuthToken struct{ ent.Schema }

func (OAuthToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "oauth_access_tokens"},
	}
}

func (OAuthToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("user_id").MaxLen(255),
		field.String("client_id").MaxLen(100).Optional(),
		field.String("name").MaxLen(255).Optional(),
		field.Text("scopes").Optional(),
		field.Bool("revoked").Default(false),
		field.Text("access_token"),
		field.Text("refresh_token").Optional(),

		// Independent expiry columns — see storage.Token docs.
		field.Time("access_expires_at"),
		field.Time("refresh_expires_at"),

		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (OAuthToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("client_id"),
		index.Fields("access_expires_at"),
		index.Fields("refresh_expires_at"),
	}
}

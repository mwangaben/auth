// storage/entstore/schema/personal_access_token.go
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"time"
)

type OAuthPersonalAccessToken struct{ ent.Schema }

func (OAuthPersonalAccessToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("token_id"),
		field.String("user_id"),
		field.String("name"),
		field.Bool("revoked").Default(false),
		field.Time("expires_at"),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (OAuthPersonalAccessToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("token_id"),
		index.Fields("user_id"),
	}
}

package authn

import "context"

type IdentifierType string

type Identifier struct {
	Type  IdentifierType
	Value string
}

type IdentifierResolver interface {
	Resolve(ctx context.Context, identifier Identifier) (identifierID string, err error)
}

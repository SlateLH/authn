package authn

import "context"

type Identity struct {
	ID string
}

type IdentityResolver interface {
	Resolve(ctx context.Context, identifier Identifier) (identityID string, err error)
}

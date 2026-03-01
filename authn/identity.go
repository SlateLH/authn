package authn

import (
	"context"
	"errors"
)

var ErrIdentityNotFound = errors.New("identity not found")

type Identity struct {
	ID string
}

type IdentityResolver interface {
	Resolve(ctx context.Context, identifier Identifier) (identityID string, err error)
}

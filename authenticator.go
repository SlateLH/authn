package authn

import (
	"context"
	"errors"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthenticationResult struct {
	Identity Identity
}

type Authenticator interface {
	Method() Method
	Authenticate(ctx context.Context, identityID string, creds Credentials) (AuthenticationResult, error)
}

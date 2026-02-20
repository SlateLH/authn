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
	Authenticate(ctx context.Context, creds Credentials) (AuthenticationResult, error)
}

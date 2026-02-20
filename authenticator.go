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

type Authenticator[Input any] interface {
	Authenticate(ctx context.Context, input Input) (AuthenticationResult, error)
}

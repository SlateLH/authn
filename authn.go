package authn

import (
	"context"
	"errors"
)

var (
	ErrInvalidMethod = errors.New("invalid method")
)

type Method string

type Service interface {
	Register(method Method, auth Authenticator)
	Authenticate(ctx context.Context, creds Credentials) (AuthenticationResult, error)
}

type service struct {
	methods map[Method]Authenticator
}

func (s *service) Register(method Method, auth Authenticator) {
	s.methods[method] = auth
}

func (s *service) Authenticate(ctx context.Context, creds Credentials) (AuthenticationResult, error) {
	auth, ok := s.methods[creds.Method()]
	if auth == nil || !ok {
		return AuthenticationResult{}, ErrInvalidMethod
	}

	return auth.Authenticate(ctx, creds)
}

func New() Service {
	methods := make(map[Method]Authenticator)

	return &service{
		methods: methods,
	}
}

package authn

import (
	"context"
	"errors"
)

var (
	errInvalidMethod           = errors.New("invalid method")
	errInvalidIdentityResolver = errors.New("invalid identity resolver")
)

type Method string

type Service interface {
	Register(auth Authenticator)
	Authenticate(ctx context.Context, creds Credentials) (AuthenticationResult, error)
}

type service struct {
	methods          map[Method]Authenticator
	identityResolver IdentityResolver
}

func (s *service) Register(auth Authenticator) {
	s.methods[auth.Method()] = auth
}

func (s *service) Authenticate(ctx context.Context, creds Credentials) (AuthenticationResult, error) {
	if s.identityResolver == nil {
		return AuthenticationResult{}, errInvalidIdentityResolver
	}

	if creds == nil {
		return AuthenticationResult{}, errInvalidMethod
	}

	auth, ok := s.methods[creds.Method()]
	if auth == nil || !ok {
		return AuthenticationResult{}, errInvalidMethod
	}

	identityID, err := s.identityResolver.Resolve(ctx, creds.Identifier())
	if err != nil {
		return AuthenticationResult{}, ErrInvalidCredentials
	}

	return auth.Authenticate(ctx, identityID, creds)
}

func New(identityResolver IdentityResolver) (Service, error) {
	if identityResolver == nil {
		return nil, errInvalidIdentityResolver
	}

	methods := make(map[Method]Authenticator)

	svc := &service{
		methods:          methods,
		identityResolver: identityResolver,
	}

	return svc, nil
}

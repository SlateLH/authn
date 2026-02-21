package authn

import (
	"context"
	"errors"
)

var (
	errInvalidMethod           = errors.New("invalid method")
	errInvalidIdentityResolver = errors.New("invalid identity resolver")
	errInvalidAuthenticator    = errors.New("invalid authenticator")
	errMethodAlreadyRegistered = errors.New("method already registered")
)

type Method string

type Service interface {
	/*
		This function is not guaranteed to be safe for concurrent use.
		The default implementation provided by authn (from [New]) is not safe for concurrency.
	*/
	Register(auth Authenticator) error
	Authenticate(ctx context.Context, creds Credentials) (AuthenticationResult, error)
}

type service struct {
	methods          map[Method]Authenticator
	identityResolver IdentityResolver
}

func (s *service) Register(auth Authenticator) error {
	if auth == nil {
		return errInvalidAuthenticator
	}

	existing, ok := s.methods[auth.Method()]
	if existing != nil || ok {
		return errMethodAlreadyRegistered
	}

	s.methods[auth.Method()] = auth
	return nil
}

func (s *service) Authenticate(ctx context.Context, creds Credentials) (AuthenticationResult, error) {
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

	result, err := auth.Authenticate(ctx, identityID, creds)
	if err != nil {
		return AuthenticationResult{}, ErrInvalidCredentials
	}

	return result, nil
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

package password

import (
	"context"
	"errors"

	"github.com/SlateLH/authn"
)

const Method authn.Method = "password"

var (
	errInvalidStore    = errors.New("invalid password store")
	errInvalidVerifier = errors.New("invalid password verifier")
)

type Credentials interface {
	Identifier() authn.Identifier
	Password() string
	Method() authn.Method
}

type credentials struct {
	identifier authn.Identifier
	password   string
}

func (c credentials) Identifier() authn.Identifier {
	return c.identifier
}

func (c credentials) Password() string {
	return c.password
}

func (c credentials) Method() authn.Method {
	return Method
}

func NewCredentials(identifier authn.Identifier, password string) Credentials {
	return &credentials{
		identifier: identifier,
		password:   password,
	}
}

type Store interface {
	FindHash(ctx context.Context, identityID string) (hash []byte, err error)
}

type Verifier interface {
	Verify(ctx context.Context, hash []byte, password string) error
}

type authenticator struct {
	store    Store
	verifier Verifier
}

func (a *authenticator) Method() authn.Method {
	return Method
}

func (a *authenticator) Authenticate(ctx context.Context, identityID string, creds authn.Credentials) (authn.AuthenticationResult, error) {
	c, ok := creds.(Credentials)
	if !ok {
		return authn.AuthenticationResult{}, authn.ErrInvalidCredentials
	}

	if c.Password() == "" {
		return authn.AuthenticationResult{}, authn.ErrInvalidCredentials
	}

	hash, err := a.store.FindHash(ctx, identityID)
	if err != nil {
		return authn.AuthenticationResult{}, authn.ErrInvalidCredentials
	}

	if err := a.verifier.Verify(ctx, hash, c.Password()); err != nil {
		return authn.AuthenticationResult{}, authn.ErrInvalidCredentials
	}

	identity := authn.Identity{
		ID: identityID,
	}

	result := authn.AuthenticationResult{
		Identity: identity,
	}

	return result, nil
}

func NewAuthenticator(
	store Store,
	verifier Verifier,
) (authn.Authenticator, error) {
	if store == nil {
		return nil, errInvalidStore
	}

	if verifier == nil {
		return nil, errInvalidVerifier
	}

	auth := &authenticator{
		store:    store,
		verifier: verifier,
	}

	return auth, nil
}

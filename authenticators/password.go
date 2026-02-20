package password

import (
	"context"
	"errors"

	"github.com/SlateLH/authn"
)

var (
	errInvalidIdentityResolver = errors.New("invalid identity resolver")
	errInvalidStore            = errors.New("invalid password store")
	errInvalidVerifier         = errors.New("invalid password verifier")
)

type Input struct {
	Identifier authn.Identifier
	Password   string
}

type Authenticator interface {
	Authenticate(ctx context.Context, input Input) (authn.AuthenticationResult, error)
}

type Store interface {
	FindHash(ctx context.Context, identityID string) (hash []byte, err error)
}

type Verifier interface {
	Verify(ctx context.Context, hash []byte, password string) error
}

type authenticator struct {
	identityResolver authn.IdentifierResolver
	store            Store
	verifier         Verifier
}

func (a *authenticator) validateDependencies() error {
	if a.identityResolver == nil {
		return errInvalidIdentityResolver
	}

	if a.store == nil {
		return errInvalidStore
	}

	if a.verifier == nil {
		return errInvalidVerifier
	}

	return nil
}

func (a *authenticator) Authenticate(ctx context.Context, input Input) (authn.AuthenticationResult, error) {
	if err := a.validateDependencies(); err != nil {
		return authn.AuthenticationResult{}, err
	}

	if input.Password == "" {
		return authn.AuthenticationResult{}, authn.ErrInvalidCredentials
	}

	identityID, err := a.identityResolver.Resolve(ctx, input.Identifier)
	if err != nil {
		return authn.AuthenticationResult{}, authn.ErrInvalidCredentials
	}

	hash, err := a.store.FindHash(ctx, identityID)
	if err != nil {
		return authn.AuthenticationResult{}, authn.ErrInvalidCredentials
	}

	if err := a.verifier.Verify(ctx, hash, input.Password); err != nil {
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
	identityResolver authn.IdentifierResolver,
	store Store,
	verifier Verifier,
) (Authenticator, error) {
	auth := &authenticator{
		identityResolver: identityResolver,
		store:            store,
		verifier:         verifier,
	}

	if err := auth.validateDependencies(); err != nil {
		return nil, err
	}

	return auth, nil
}

package password

import (
	"context"
	"errors"

	"github.com/SlateLH/authn"
)

const Method authn.Method = "password"

var (
	errInvalidIdentityResolver = errors.New("invalid identity resolver")
	errInvalidStore            = errors.New("invalid password store")
	errInvalidVerifier         = errors.New("invalid password verifier")
	ErrHashNotFound            = errors.New("hash not found")
	ErrWrongPassword           = errors.New("wrong password")
)

type Store interface {
	FindHash(ctx context.Context, identityID string) (hash []byte, err error)
}

type Verifier interface {
	Verify(ctx context.Context, hash []byte, password string) error
}

type authenticator struct {
	identityResolver authn.IdentityResolver
	store            Store
	verifier         Verifier
}

func (a *authenticator) Method() authn.Method {
	return Method
}

func (a *authenticator) Initiate(ctx context.Context, credentials authn.Credentials) (authn.Result, error) {
	if credentials == nil {
		return authn.Result{}, authn.ErrInvalidCredentials
	}

	if credentials.Method() != Method {
		return authn.Result{}, authn.ErrInvalidCredentials
	}

	creds, ok := credentials.(Credentials)
	if !ok {
		return authn.Result{}, authn.ErrInvalidCredentials
	}

	if creds.Password() == "" {
		return authn.Result{}, authn.ErrInvalidCredentials
	}

	identityID, err := a.identityResolver.Resolve(ctx, creds.Identifier())
	if err != nil {
		if errors.Is(err, authn.ErrIdentityNotFound) {
			return authn.Result{Status: authn.StatusFailed}, nil
		}

		return authn.Result{}, err
	}

	hash, err := a.store.FindHash(ctx, identityID)
	if err != nil {
		if errors.Is(err, ErrHashNotFound) {
			return authn.Result{Status: authn.StatusFailed}, nil
		}

		return authn.Result{}, err
	}

	err = a.verifier.Verify(ctx, hash, creds.Password())
	if err != nil {
		if errors.Is(err, ErrWrongPassword) {
			return authn.Result{Status: authn.StatusFailed}, nil
		}

		return authn.Result{}, err
	}

	identity := authn.Identity{
		ID: identityID,
	}

	result := authn.Result{
		Status:   authn.StatusAuthenticated,
		Identity: identity,
	}

	return result, nil
}

func (a *authenticator) Respond(ctx context.Context, session authn.Session, response authn.Response) (authn.Result, error) {
	return authn.Result{}, authn.ErrInvalidResponse
}

func NewAuthenticator(
	identityResolver authn.IdentityResolver,
	store Store,
	verifier Verifier,
) (authn.Authenticator, error) {
	if identityResolver == nil {
		return nil, errInvalidIdentityResolver
	}

	if store == nil {
		return nil, errInvalidStore
	}

	if verifier == nil {
		return nil, errInvalidVerifier
	}

	auth := &authenticator{
		identityResolver: identityResolver,
		store:            store,
		verifier:         verifier,
	}

	return auth, nil
}

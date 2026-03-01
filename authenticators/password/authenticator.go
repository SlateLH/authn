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
	ErrPasswordNotFound        = errors.New("password not found")
	ErrWrongPassword           = errors.New("wrong password")
)

type Store interface {
	FindPassword(ctx context.Context, identityID string) (password []byte, err error)
}

type Verifier interface {
	Verify(ctx context.Context, password []byte, plain string) error
}

type authenticator struct {
	identityResolver authn.IdentityResolver
	store            Store
	verifier         Verifier
}

func (a authenticator) Method() authn.Method {
	return Method
}

func (a authenticator) Initiate(ctx context.Context, credentials authn.Credentials) (authn.Result, error) {
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

	password, err := a.store.FindPassword(ctx, identityID)
	if err != nil {
		if errors.Is(err, ErrPasswordNotFound) {
			return authn.Result{Status: authn.StatusFailed}, nil
		}

		return authn.Result{}, err
	}

	err = a.verifier.Verify(ctx, password, creds.Password())
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

func (a authenticator) Respond(ctx context.Context, session authn.Session, response authn.Response) (authn.Result, error) {
	return authn.Result{}, authn.ErrInvalidResponse
}

type AuthenticatorDeps struct {
	IdentityResolver authn.IdentityResolver
	Store            Store
	Verifier         Verifier
}

func NewAuthenticator(deps AuthenticatorDeps) (authn.Authenticator, error) {
	if deps.IdentityResolver == nil {
		return nil, errInvalidIdentityResolver
	}

	if deps.Store == nil {
		return nil, errInvalidStore
	}

	if deps.Verifier == nil {
		return nil, errInvalidVerifier
	}

	auth := &authenticator{
		identityResolver: deps.IdentityResolver,
		store:            deps.Store,
		verifier:         deps.Verifier,
	}

	return auth, nil
}

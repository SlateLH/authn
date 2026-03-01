package totp

import (
	"context"
	"errors"
	"time"

	"github.com/SlateLH/authn"
	"github.com/oklog/ulid/v2"
)

const Method authn.Method = "totp"
const DefaultSessionDuration time.Duration = 15 * time.Minute

var (
	errInvalidIdentityResolver = errors.New("invalid identity resolver")
	errInvalidStore            = errors.New("invalid secret store")
	errInvalidVerifier         = errors.New("invalid code verifier")
	ErrSecretNotFound          = errors.New("secret not found")
	ErrWrongCode               = errors.New("wrong code")
)

type Store interface {
	FindSecret(ctx context.Context, identityID string) (secret []byte, err error)
}

type Verifier interface {
	Verify(ctx context.Context, secret []byte, code string) error
}

type authenticator struct {
	identityResolver authn.IdentityResolver
	store            Store
	verifier         Verifier
	clock            authn.Clock
	sessionDuration  time.Duration
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

	identityID, err := a.identityResolver.Resolve(ctx, creds.Identifier())
	if err != nil {
		if errors.Is(err, authn.ErrIdentityNotFound) {
			return authn.Result{Status: authn.StatusFailed}, nil
		}

		return authn.Result{}, err
	}

	_, err = a.store.FindSecret(ctx, identityID)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return authn.Result{Status: authn.StatusFailed}, nil
		}

		return authn.Result{}, err
	}

	session := Session{
		id:        ulid.MustNewDefault(time.Now().UTC()).String(),
		expiresAt: a.clock.Now().Add(a.sessionDuration),
		status:    authn.StatusChallenged,
		payload:   SessionPayload{IdentityID: identityID},
	}

	challenge := NewChallenge()

	result := authn.Result{
		Status:    authn.StatusChallenged,
		Session:   session,
		Challenge: challenge,
	}

	return result, nil
}

func (a authenticator) Respond(ctx context.Context, session authn.Session, response authn.Response) (authn.Result, error) {
	if session == nil || response == nil {
		return authn.Result{Status: authn.StatusFailed}, nil
	}

	if session.Method() != Method || response.Method() != Method {
		return authn.Result{Status: authn.StatusFailed}, nil
	}

	if session.Status() != authn.StatusChallenged {
		return authn.Result{Status: authn.StatusFailed}, nil
	}

	if a.clock.Now().After(session.ExpiresAt()) {
		return authn.Result{Status: authn.StatusFailed}, nil
	}

	s, ok := session.(Session)
	if !ok {
		return authn.Result{Status: authn.StatusFailed}, nil
	}

	r, ok := response.(Response)
	if !ok {
		return authn.Result{Status: authn.StatusFailed}, nil
	}

	identityID := s.Payload().IdentityID

	secret, err := a.store.FindSecret(ctx, identityID)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return authn.Result{Status: authn.StatusFailed}, nil
		}

		return authn.Result{}, err
	}

	err = a.verifier.Verify(ctx, secret, r.Code())
	if err != nil {
		if errors.Is(err, ErrWrongCode) {
			return authn.Result{Status: authn.StatusFailed}, nil
		}

		return authn.Result{}, err
	}

	result := authn.Result{
		Status: authn.StatusAuthenticated,
		Identity: authn.Identity{
			ID: identityID,
		},
	}

	return result, nil
}

var _ authn.Authenticator = (*authenticator)(nil)

type AuthenticatorDeps struct {
	IdentityResolver authn.IdentityResolver
	Store            Store
	Verifier         Verifier
	Clock            authn.Clock
}

type AuthenticatorConfig struct {
	SessionDuration time.Duration
}

func NewAuthenticator(deps AuthenticatorDeps, cfg AuthenticatorConfig) (authn.Authenticator, error) {
	if deps.IdentityResolver == nil {
		return nil, errInvalidIdentityResolver
	}

	if deps.Store == nil {
		return nil, errInvalidStore
	}

	if deps.Verifier == nil {
		return nil, errInvalidVerifier
	}

	clock := deps.Clock
	if clock == nil {
		clock = authn.SystemClock{}
	}

	sessionDuration := cfg.SessionDuration
	if sessionDuration == 0 {
		sessionDuration = DefaultSessionDuration
	}

	auth := &authenticator{
		identityResolver: deps.IdentityResolver,
		store:            deps.Store,
		verifier:         deps.Verifier,
		clock:            clock,
		sessionDuration:  sessionDuration,
	}

	return auth, nil
}

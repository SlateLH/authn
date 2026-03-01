package totp_test

import (
	"context"
	"testing"
	"time"

	"github.com/SlateLH/authn/authn"
	"github.com/SlateLH/authn/authn/authenticators/totp"
)

type mockIdentityResolver struct {
	identityID string
	err        error
}

func (m mockIdentityResolver) Resolve(ctx context.Context, identifier authn.Identifier) (identityID string, err error) {
	return m.identityID, m.err
}

type mockStore struct {
	secret []byte
	err    error
}

func (m mockStore) FindSecret(ctx context.Context, identityID string) (secret []byte, err error) {
	return m.secret, m.err
}

type mockVerifier struct {
	err error
}

func (m mockVerifier) Verify(ctx context.Context, secret []byte, code string) error {
	return m.err
}

type mockCredentials struct {
	identifier authn.Identifier
	method     authn.Method
}

func (m mockCredentials) Identifier() authn.Identifier {
	return m.identifier
}

func (m mockCredentials) Method() authn.Method {
	return m.method
}

type mockClock struct {
	now time.Time
}

func (m mockClock) Now() time.Time {
	return m.now
}

func TestNewInvalidDependencies(t *testing.T) {
	testCases := []struct {
		identityResolver authn.IdentityResolver
		store            totp.Store
		verifier         totp.Verifier
	}{
		{
			store:    mockStore{},
			verifier: mockVerifier{},
		},
		{
			identityResolver: mockIdentityResolver{},
			verifier:         mockVerifier{},
		},
		{
			identityResolver: mockIdentityResolver{},
			store:            mockStore{},
		},
	}

	for _, tc := range testCases {
		deps := totp.AuthenticatorDeps{
			IdentityResolver: tc.identityResolver,
			Store:            tc.store,
			Verifier:         tc.verifier,
		}

		_, err := totp.NewAuthenticator(deps, totp.AuthenticatorConfig{})

		if err == nil {
			t.Errorf("expected err not to be nil")
		}
	}
}

func TestNew(t *testing.T) {
	deps := totp.AuthenticatorDeps{
		IdentityResolver: mockIdentityResolver{},
		Store:            mockStore{},
		Verifier:         mockVerifier{},
	}

	_, err := totp.NewAuthenticator(deps, totp.AuthenticatorConfig{})

	if err != nil {
		t.Errorf("expected err to be nil, received \"%v\"", err)
	}
}

func TestInitiateInvalidCredentials(t *testing.T) {
	testCases := []struct {
		creds authn.Credentials
	}{
		{creds: nil},
		{creds: mockCredentials{method: "mock method"}},
	}

	deps := totp.AuthenticatorDeps{
		IdentityResolver: mockIdentityResolver{},
		Store:            mockStore{},
		Verifier:         mockVerifier{},
	}

	auth, _ := totp.NewAuthenticator(deps, totp.AuthenticatorConfig{})

	for _, tc := range testCases {
		_, err := auth.Initiate(context.Background(), tc.creds)

		if err == nil {
			t.Errorf("expected err not to be nil")
		}
	}
}

func TestInitiateFailed(t *testing.T) {
	testCases := []struct {
		identityResolver authn.IdentityResolver
		store            totp.Store
		verifier         totp.Verifier
	}{
		{
			identityResolver: mockIdentityResolver{err: authn.ErrIdentityNotFound},
			store:            mockStore{},
			verifier:         mockVerifier{},
		},
		{
			identityResolver: mockIdentityResolver{},
			store:            mockStore{err: totp.ErrSecretNotFound},
			verifier:         mockVerifier{},
		},
	}

	for _, tc := range testCases {
		deps := totp.AuthenticatorDeps{
			IdentityResolver: tc.identityResolver,
			Store:            tc.store,
			Verifier:         tc.verifier,
		}

		auth, _ := totp.NewAuthenticator(deps, totp.AuthenticatorConfig{})
		result, _ := auth.Initiate(t.Context(), totp.NewCredentials(authn.Identifier{}))

		if result.Status != authn.StatusFailed {
			t.Errorf("expected result status to be \"%s\", received \"%s\"", authn.StatusFailed, result.Status)
		}
	}
}

func TestInitiate(t *testing.T) {
	identityID := "mock identity"
	sessionDuration := 1 * time.Minute
	now := time.Now()

	deps := totp.AuthenticatorDeps{
		IdentityResolver: mockIdentityResolver{identityID: identityID},
		Store:            mockStore{},
		Verifier:         mockVerifier{},
		Clock:            mockClock{now: now},
	}

	cfg := totp.AuthenticatorConfig{
		SessionDuration: sessionDuration,
	}

	auth, _ := totp.NewAuthenticator(deps, cfg)
	result, _ := auth.Initiate(context.Background(), totp.NewCredentials(authn.Identifier{}))

	if result.Status != authn.StatusChallenged {
		t.Errorf("expected status to be \"%s\", received \"%s\"", authn.StatusChallenged, result.Status)
	}

	if result.Session == nil {
		t.Errorf("expected session not to be nil")
	}

	session, ok := result.Session.(totp.Session)
	if !ok {
		t.Errorf("expected session to be totp session")
	}

	if session.Status() != authn.StatusChallenged {
		t.Errorf("expected session status to be \"%s\", received \"%s\"", authn.StatusChallenged, result.Session.Status())
	}

	if session.ExpiresAt() != now.Add(sessionDuration) {
		t.Errorf("expected session expiresAt to be %v, received %v", now.Add(sessionDuration), session.ExpiresAt())
	}

	if session.Payload().IdentityID != identityID {
		t.Errorf("expected session payload identity ID to be \"%s\", received \"%s\"", identityID, session.Payload().IdentityID)
	}

	if result.Challenge == nil {
		t.Errorf("expected challenge not to be nil")
	}
}

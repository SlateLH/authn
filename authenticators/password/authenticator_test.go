package password_test

import (
	"context"
	"testing"

	"github.com/SlateLH/authn"
	"github.com/SlateLH/authn/authenticators/password"
)

type mockIdentityResolver struct {
	identityID string
	err        error
}

func (m *mockIdentityResolver) Resolve(ctx context.Context, identifier authn.Identifier) (identityID string, err error) {
	return m.identityID, m.err
}

type mockStore struct {
	password []byte
	err      error
}

func (m *mockStore) FindPassword(ctx context.Context, identityID string) (password []byte, err error) {
	return m.password, m.err
}

type mockVerifier struct {
	err error
}

func (m *mockVerifier) Verify(ctx context.Context, password []byte, plain string) error {
	return m.err
}

type mockCredentials struct {
	identifier authn.Identifier
	method     authn.Method
}

func (m *mockCredentials) Identifier() authn.Identifier {
	return m.identifier
}

func (m *mockCredentials) Method() authn.Method {
	return m.method
}

func TestNewInvalidDependencies(t *testing.T) {
	testCases := []struct {
		identityResolver authn.IdentityResolver
		store            password.Store
		verifier         password.Verifier
	}{
		{
			store:    &mockStore{},
			verifier: &mockVerifier{},
		},
		{
			identityResolver: &mockIdentityResolver{},
			verifier:         &mockVerifier{},
		},
		{
			identityResolver: &mockIdentityResolver{},
			store:            &mockStore{},
		},
	}

	for _, tc := range testCases {
		deps := password.AuthenticatorDeps{
			IdentityResolver: tc.identityResolver,
			Store:            tc.store,
			Verifier:         tc.verifier,
		}

		_, err := password.NewAuthenticator(deps)

		if err == nil {
			t.Errorf("expected err not to be nil")
		}
	}
}

func TestNew(t *testing.T) {
	deps := password.AuthenticatorDeps{
		IdentityResolver: &mockIdentityResolver{},
		Store:            &mockStore{},
		Verifier:         &mockVerifier{},
	}

	_, err := password.NewAuthenticator(deps)

	if err != nil {
		t.Errorf("expected err to be nil, received \"%v\"", err)
	}
}

func TestInitiateInvalidCredentials(t *testing.T) {
	testCases := []struct {
		creds authn.Credentials
	}{
		{creds: nil},
		{creds: &mockCredentials{method: "mock method"}},
		{creds: &mockCredentials{method: password.Method}},
		{creds: password.NewCredentials(authn.Identifier{}, "")},
	}

	deps := password.AuthenticatorDeps{
		IdentityResolver: &mockIdentityResolver{},
		Store:            &mockStore{},
		Verifier:         &mockVerifier{},
	}

	auth, _ := password.NewAuthenticator(deps)

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
		store            password.Store
		verifier         password.Verifier
	}{
		{
			identityResolver: &mockIdentityResolver{err: authn.ErrIdentityNotFound},
			store:            &mockStore{},
			verifier:         &mockVerifier{},
		},
		{
			identityResolver: &mockIdentityResolver{},
			store:            &mockStore{err: password.ErrPasswordNotFound},
			verifier:         &mockVerifier{},
		},
		{
			identityResolver: &mockIdentityResolver{},
			store:            &mockStore{},
			verifier:         &mockVerifier{err: password.ErrWrongPassword},
		},
	}

	for _, tc := range testCases {
		deps := password.AuthenticatorDeps{
			IdentityResolver: tc.identityResolver,
			Store:            tc.store,
			Verifier:         tc.verifier,
		}

		auth, _ := password.NewAuthenticator(deps)
		result, _ := auth.Initiate(t.Context(), password.NewCredentials(authn.Identifier{}, "mock password"))

		if result.Status != authn.StatusFailed {
			t.Errorf("expected result status to be \"%s\", received \"%s\"", authn.StatusFailed, result.Status)
		}
	}
}

func TestRespond(t *testing.T) {
	deps := password.AuthenticatorDeps{
		IdentityResolver: &mockIdentityResolver{},
		Store:            &mockStore{},
		Verifier:         &mockVerifier{},
	}

	auth, _ := password.NewAuthenticator(deps)
	_, err := auth.Respond(context.Background(), nil, nil)

	if err == nil {
		t.Errorf("expected err not to be nil")
	}
}

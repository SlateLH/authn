package password_test

import (
	"context"
	"errors"
	"testing"

	"github.com/SlateLH/authn"
	password "github.com/SlateLH/authn/authenticators"
)

type mockCredentials struct{}

func (m *mockCredentials) Method() authn.Method {
	return "mock method"
}

type mockidentityResolver struct {
	identityID string
	err        error
}

func (m *mockidentityResolver) Resolve(ctx context.Context, identifier authn.Identifier) (identityID string, err error) {
	return m.identityID, m.err
}

type mockStore struct {
	hash []byte
	err  error
}

func (m *mockStore) FindHash(ctx context.Context, identityID string) (hash []byte, err error) {
	return m.hash, m.err
}

type mockVerifier struct {
	err error
}

func (m *mockVerifier) Verify(ctx context.Context, hash []byte, password string) error {
	return m.err
}

func TestNewAuthenticatorInvalidDependencies(t *testing.T) {
	testCases := []struct {
		identityResolver authn.IdentityResolver
		store            password.Store
		verifier         password.Verifier
	}{
		{identityResolver: nil, store: &mockStore{}, verifier: &mockVerifier{}},
		{identityResolver: &mockidentityResolver{}, store: nil, verifier: &mockVerifier{}},
		{identityResolver: &mockidentityResolver{}, store: &mockStore{}, verifier: nil},
	}

	for _, tc := range testCases {
		_, err := password.NewAuthenticator(tc.identityResolver, tc.store, tc.verifier)

		if err == nil {
			t.Errorf("expected err to not be nil")
		}
	}
}

func TestNewAuthenticatorValidDependencies(t *testing.T) {
	_, err := password.NewAuthenticator(&mockidentityResolver{}, &mockStore{}, &mockVerifier{})

	if err != nil {
		t.Errorf("expected err to be nil, received \"%v\"", err)
	}
}

func TestAuthenticateInvalidCredentials(t *testing.T) {
	testCases := []struct {
		identityResolver authn.IdentityResolver
		store            password.Store
		verifier         password.Verifier
		creds            authn.Credentials
	}{
		{
			identityResolver: &mockidentityResolver{err: nil},
			store:            &mockStore{err: nil},
			verifier:         &mockVerifier{err: nil},
			creds:            &mockCredentials{},
		},
		{
			identityResolver: &mockidentityResolver{err: nil},
			store:            &mockStore{err: nil},
			verifier:         &mockVerifier{err: nil},
			creds:            password.Credentials{},
		},
		{
			identityResolver: &mockidentityResolver{err: errors.New("mock identity resolver error")},
			store:            &mockStore{err: nil},
			verifier:         &mockVerifier{err: nil},
			creds:            password.Credentials{Password: "mock password"},
		},
		{
			identityResolver: &mockidentityResolver{err: nil},
			store:            &mockStore{err: errors.New("mock store error")},
			verifier:         &mockVerifier{err: nil},
			creds:            password.Credentials{Password: "mock password"},
		},
		{
			identityResolver: &mockidentityResolver{err: nil},
			store:            &mockStore{err: nil},
			verifier:         &mockVerifier{err: errors.New("mock verifier error")},
			creds:            password.Credentials{Password: "mock password"},
		},
	}

	for _, tc := range testCases {
		authenticator, _ := password.NewAuthenticator(tc.identityResolver, tc.store, tc.verifier)
		_, err := authenticator.Authenticate(context.Background(), tc.creds)

		if err == nil {
			t.Errorf("expected err to not be nil")
		}
	}
}

func TestAuthenticateValidCredentials(t *testing.T) {
	identityID := "mock identity ID"
	creds := password.Credentials{
		Password: "mock password",
	}

	authenticator, _ := password.NewAuthenticator(
		&mockidentityResolver{identityID: identityID, err: nil},
		&mockStore{err: nil},
		&mockVerifier{err: nil},
	)

	result, err := authenticator.Authenticate(context.Background(), creds)

	if err != nil {
		t.Errorf("expected err to be nil, received \"%v\"", err)
	}

	if identityID != result.Identity.ID {
		t.Errorf("expected identity ID to be \"%v\", received \"%v\"", identityID, result.Identity.ID)
	}
}

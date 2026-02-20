package password_test

import (
	"context"
	"errors"
	"testing"

	"github.com/SlateLH/authn"
	password "github.com/SlateLH/authn/authenticators"
)

type mockCredentials struct {
	identifier authn.Identifier
}

func (m *mockCredentials) Identifier() authn.Identifier {
	return m.identifier
}

func (m *mockCredentials) Method() authn.Method {
	return "mock method"
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
		store    password.Store
		verifier password.Verifier
	}{
		{store: nil, verifier: &mockVerifier{}},
		{store: &mockStore{}, verifier: nil},
	}

	for _, tc := range testCases {
		_, err := password.NewAuthenticator(tc.store, tc.verifier)

		if err == nil {
			t.Errorf("expected err to not be nil")
		}
	}
}

func TestNewAuthenticatorValidDependencies(t *testing.T) {
	_, err := password.NewAuthenticator(&mockStore{}, &mockVerifier{})

	if err != nil {
		t.Errorf("expected err to be nil, received \"%v\"", err)
	}
}

func TestAuthenticateInvalidCredentials(t *testing.T) {
	testCases := []struct {
		store      password.Store
		verifier   password.Verifier
		identityID string
		creds      authn.Credentials
	}{
		{
			store:    &mockStore{},
			verifier: &mockVerifier{},
		},
		{
			store:    &mockStore{},
			verifier: &mockVerifier{},
			creds:    &mockCredentials{},
		},
		{
			store:    &mockStore{},
			verifier: &mockVerifier{},
			creds:    password.NewCredentials(authn.Identifier{}, ""),
		},
		{
			store:    &mockStore{err: errors.New("mock store error")},
			verifier: &mockVerifier{},
			creds:    password.NewCredentials(authn.Identifier{}, "mock password"),
		},
		{
			store:    &mockStore{},
			verifier: &mockVerifier{err: errors.New("mock verifier error")},
			creds:    password.NewCredentials(authn.Identifier{}, "mock password"),
		},
	}

	for _, tc := range testCases {
		authenticator, _ := password.NewAuthenticator(tc.store, tc.verifier)
		_, err := authenticator.Authenticate(context.Background(), tc.identityID, tc.creds)

		if err == nil {
			t.Errorf("expected err to not be nil")
		}
	}
}

func TestAuthenticateValidCredentials(t *testing.T) {
	identityID := "mock identity ID"
	creds := password.NewCredentials(authn.Identifier{}, "mock password")
	authenticator, _ := password.NewAuthenticator(&mockStore{}, &mockVerifier{})
	result, err := authenticator.Authenticate(context.Background(), identityID, creds)

	if err != nil {
		t.Errorf("expected err to be nil, received \"%v\"", err)
	}

	if identityID != result.Identity.ID {
		t.Errorf("expected identity ID to be \"%s\", received \"%s\"", identityID, result.Identity.ID)
	}
}

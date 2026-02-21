package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/SlateLH/authn"
)

const mockMethod authn.Method = "mock method"

type mockCredentials struct {
	identifier authn.Identifier
}

func (m *mockCredentials) Identifier() authn.Identifier {
	return m.identifier
}

func (m *mockCredentials) Method() authn.Method {
	return mockMethod
}

type mockIdentityResolver struct {
	identityID string
	err        error
}

func (m *mockIdentityResolver) Resolve(ctx context.Context, identifier authn.Identifier) (identityID string, err error) {
	return m.identityID, m.err
}

type mockAuthenticator struct {
	authenticationResult authn.AuthenticationResult
	err                  error
}

func (m *mockAuthenticator) Method() authn.Method {
	return mockMethod
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, identityID string, creds authn.Credentials) (authn.AuthenticationResult, error) {
	return m.authenticationResult, m.err
}

func TestNewInvalidIdentityResolver(t *testing.T) {
	_, err := authn.New(nil)

	if err == nil {
		t.Errorf("expected err to not be nil")
	}
}

func TestNewValidIdentityResolver(t *testing.T) {
	_, err := authn.New(&mockIdentityResolver{})

	if err != nil {
		t.Errorf("expected err to be nil, received \"%v\"", err)
	}
}

func TestRegisterInvalidAuthenticator(t *testing.T) {
	svc, _ := authn.New(&mockIdentityResolver{})
	err := svc.Register(nil)

	if err == nil {
		t.Errorf("expected err to not be nil")
	}
}

func TestRegisterMethodAlreadyRegistered(t *testing.T) {
	svc, _ := authn.New(&mockIdentityResolver{})
	svc.Register(&mockAuthenticator{})
	err := svc.Register(&mockAuthenticator{})

	if err == nil {
		t.Errorf("expected err to not be nil")
	}
}

func TestAuthenticateInvalidMethod(t *testing.T) {
	testCases := []struct {
		creds authn.Credentials
	}{
		{creds: nil},
		{creds: &mockCredentials{}},
	}

	svc, _ := authn.New(&mockIdentityResolver{})

	for _, tc := range testCases {
		_, err := svc.Authenticate(context.Background(), tc.creds)

		if err == nil {
			t.Errorf("expected err to not be nil")
		}
	}
}

func TestAuthenticateIdentityResolutionFailure(t *testing.T) {
	svc, _ := authn.New(&mockIdentityResolver{err: errors.New("mock identity resolver error")})
	svc.Register(&mockAuthenticator{})

	_, err := svc.Authenticate(context.Background(), &mockCredentials{})

	if err == nil {
		t.Errorf("expected err to not be nil")
	}
}

func TestAuthenticate(t *testing.T) {
	identityID := "mock identity ID"
	result := authn.AuthenticationResult{
		Identity: authn.Identity{
			ID: identityID,
		},
	}

	var err error

	svc, _ := authn.New(&mockIdentityResolver{identityID: identityID})
	svc.Register(&mockAuthenticator{authenticationResult: result})
	actualResult, err := svc.Authenticate(context.Background(), &mockCredentials{})

	if identityID != actualResult.Identity.ID {
		t.Errorf("expected identity ID to be \"%s\", received \"%s\"", identityID, actualResult.Identity.ID)
	}

	if err != nil {
		t.Errorf("expected err to be nil, received \"%v\"", err)
	}
}

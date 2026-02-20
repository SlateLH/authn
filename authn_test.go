package authn_test

import (
	"context"
	"testing"

	"github.com/SlateLH/authn"
)

const mockMethod authn.Method = "mock method"

type mockCredentials struct{}

func (m *mockCredentials) Method() authn.Method {
	return mockMethod
}

type mockAuthenticator struct {
	authenticationResult authn.AuthenticationResult
	err                  error
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, creds authn.Credentials) (authn.AuthenticationResult, error) {
	return m.authenticationResult, m.err
}

func TestAuthenticateInvalidMethod(t *testing.T) {
	_, err := authn.New().Authenticate(context.Background(), &mockCredentials{})

	if err == nil {
		t.Errorf("expected err to not be nil")
	}
}

func TestAuthenticateValidMethod(t *testing.T) {
	result := authn.AuthenticationResult{
		Identity: authn.Identity{
			ID: "mock identity ID",
		},
	}

	var err error

	svc := authn.New()
	svc.Register(mockMethod, &mockAuthenticator{authenticationResult: result, err: err})
	actualResult, actualErr := svc.Authenticate(context.Background(), &mockCredentials{})

	if err != actualErr {
		t.Errorf("expected err to be \"%v\", received \"%v\"", err, actualErr)
	}

	if result != actualResult {
		t.Errorf("expected result to be %v, received %v", result, actualResult)
	}
}

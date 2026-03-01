package authn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SlateLH/authn"
)

const mockMethod authn.Method = "mock method"

type mockCredentials struct {
	method     authn.Method
	identifier authn.Identifier
}

func (m *mockCredentials) Identifier() authn.Identifier {
	return m.identifier
}

func (m *mockCredentials) Method() authn.Method {
	return m.method
}

type mockChallenge struct {
	t          authn.ChallengeType
	payload    []byte
	marshalErr error
}

func (m *mockChallenge) Type() authn.ChallengeType {
	return m.t
}

func (m *mockChallenge) Marshal() ([]byte, error) {
	return m.payload, m.marshalErr
}

type mockSession struct {
	id         string
	method     authn.Method
	expiresAt  time.Time
	status     authn.Status
	payload    []byte
	marshalErr error
}

func (m *mockSession) ID() string {
	return m.id
}

func (m *mockSession) Method() authn.Method {
	return m.method
}

func (m *mockSession) ExpiresAt() time.Time {
	return m.expiresAt
}

func (m *mockSession) Status() authn.Status {
	return m.status
}

func (m *mockSession) Marshal() ([]byte, error) {
	return m.payload, m.marshalErr
}

type mockAuthenticator struct {
	method authn.Method
	result authn.Result
	err    error
}

func (m *mockAuthenticator) Method() authn.Method {
	return m.method
}

func (m *mockAuthenticator) Initiate(ctx context.Context, creds authn.Credentials) (authn.Result, error) {
	return m.result, m.err
}

func (m *mockAuthenticator) Respond(ctx context.Context, session authn.Session, response authn.Response) (authn.Result, error) {
	return m.result, m.err
}

func TestRegisterInvalidAuthenticator(t *testing.T) {
	err := authn.New().Register(nil)

	if err == nil {
		t.Errorf("expected err not to be nil")
	}
}

func TestRegisterMethodAlreadyRegistered(t *testing.T) {
	svc := authn.New()
	svc.Register(&mockAuthenticator{method: mockMethod})
	err := svc.Register(&mockAuthenticator{method: mockMethod})

	if err == nil {
		t.Errorf("expected err not to be nil")
	}
}

func TestInitiateInvalidMethod(t *testing.T) {
	testCases := []struct {
		creds authn.Credentials
	}{
		{creds: nil},
		{creds: &mockCredentials{method: mockMethod}},
	}

	svc := authn.New()

	for _, tc := range testCases {
		_, err := svc.Initiate(context.Background(), tc.creds)

		if err == nil {
			t.Errorf("expected err not to be nil")
		}
	}
}

func TestInitiateInvalidCredentials(t *testing.T) {
	svc := authn.New()
	svc.Register(&mockAuthenticator{method: mockMethod, err: errors.New("mock initiate error")})

	_, err := svc.Initiate(context.Background(), &mockCredentials{method: mockMethod})

	if err == nil {
		t.Errorf("expected err not to be nil")
	}
}

func TestInitiateInvalidResult(t *testing.T) {
	testCases := []struct {
		result authn.Result
	}{
		{
			result: authn.Result{Status: authn.StatusAuthenticated},
		},
		{
			result: authn.Result{
				Status:    authn.StatusAuthenticated,
				Identity:  authn.Identity{ID: "mock identity id"},
				Challenge: &mockChallenge{},
			},
		},
		{
			result: authn.Result{
				Status:   authn.StatusAuthenticated,
				Identity: authn.Identity{ID: "mock identity id"},
				Session:  &mockSession{},
			},
		},
		{
			result: authn.Result{
				Status:    authn.StatusChallenged,
				Identity:  authn.Identity{ID: "mock identity id"},
				Challenge: &mockChallenge{},
				Session:   &mockSession{},
			},
		},
		{
			result: authn.Result{
				Status:  authn.StatusChallenged,
				Session: &mockSession{},
			},
		},
		{
			result: authn.Result{
				Status:    authn.StatusChallenged,
				Challenge: &mockChallenge{},
			},
		},
		{
			result: authn.Result{
				Status:   authn.StatusPending,
				Identity: authn.Identity{ID: "mock identity id"},
			},
		},
		{
			result: authn.Result{
				Status:    authn.StatusPending,
				Challenge: &mockChallenge{},
			},
		},
		{
			result: authn.Result{
				Status:  authn.StatusPending,
				Session: &mockSession{},
			},
		},
		{
			result: authn.Result{
				Status:   authn.StatusFailed,
				Identity: authn.Identity{ID: "mock identity id"},
			},
		},
		{
			result: authn.Result{
				Status:    authn.StatusFailed,
				Challenge: &mockChallenge{},
			},
		},
		{
			result: authn.Result{
				Status:  authn.StatusFailed,
				Session: &mockSession{},
			},
		},
		{
			result: authn.Result{
				Status: "unexpected status",
			},
		},
	}

	svc := authn.New()

	for _, tc := range testCases {
		svc.Register(&mockAuthenticator{method: mockMethod, result: tc.result})
		_, err := svc.Initiate(context.Background(), &mockCredentials{method: mockMethod})

		if err == nil {
			t.Errorf("expected err not to be nil")
		}
	}
}

func TestInitiate(t *testing.T) {
	status := authn.StatusAuthenticated
	identityID := "mock identity ID"
	result := authn.Result{
		Status: status,
		Identity: authn.Identity{
			ID: identityID,
		},
	}

	var err error

	svc := authn.New()
	svc.Register(&mockAuthenticator{method: mockMethod, result: result})
	actualResult, err := svc.Initiate(context.Background(), &mockCredentials{method: mockMethod})

	if identityID != actualResult.Identity.ID {
		t.Errorf("expected identity ID to be \"%s\", received \"%s\"", identityID, actualResult.Identity.ID)
	}

	if err != nil {
		t.Errorf("expected err to be nil, received \"%v\"", err)
	}
}

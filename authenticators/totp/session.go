package totp

import (
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/SlateLH/authn"
	"github.com/oklog/ulid/v2"
)

type sessionPayload struct {
	IdentityID string `json:"identityId"`
}

type Session interface {
	ID() string
	Method() authn.Method
	ExpiresAt() time.Time
	Status() authn.Status
	Marshal() ([]byte, error)
	Payload() sessionPayload
}

type session struct {
	id        string
	expiresAt time.Time
	status    authn.Status
	payload   sessionPayload
}

func (s session) ID() string {
	return s.id
}

func (s session) Method() authn.Method {
	return Method
}

func (s session) ExpiresAt() time.Time {
	return s.expiresAt
}

func (s session) Status() authn.Status {
	return s.status
}

func (s session) Marshal() ([]byte, error) {
	return json.Marshal(s.payload)
}

func (s session) Payload() sessionPayload {
	return s.payload
}

type sessionOption func(*session)

func WithId(id string) sessionOption {
	return func(s *session) {
		s.id = id
	}
}

func NewSession(expiresAt time.Time, status authn.Status, payload sessionPayload, options ...sessionOption) Session {
	t := time.Now().UTC()
	entropy := ulid.Monotonic(rand.Reader, 0)

	s := session{
		id:        ulid.MustNew(ulid.Timestamp(t), entropy).String(),
		expiresAt: expiresAt,
		status:    status,
		payload:   payload,
	}

	for _, option := range options {
		option(&s)
	}

	return s
}

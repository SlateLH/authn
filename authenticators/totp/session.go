package totp

import (
	"time"

	"github.com/SlateLH/authn"
)

type SessionPayload struct {
	IdentityID string
}

type Session struct {
	id        string
	expiresAt time.Time
	status    authn.Status
	payload   SessionPayload
}

func (s Session) ID() string {
	return s.id
}

func (s Session) Method() authn.Method {
	return Method
}

func (s Session) ExpiresAt() time.Time {
	return s.expiresAt
}

func (s Session) Status() authn.Status {
	return s.status
}

func (s Session) Payload() SessionPayload {
	return s.payload
}

var _ authn.Session = (*Session)(nil)

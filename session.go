package authn

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidSession  = errors.New("invalid session")
	ErrSessionNotFound = errors.New("session not found")
)

type Session interface {
	ID() string
	Method() Method
	ExpiresAt() time.Time
	Status() Status
}

type SessionStore interface {
	Find(ctx context.Context, sessionID string) (Session, error)
}

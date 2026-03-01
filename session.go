package authn

import (
	"errors"
	"time"
)

var ErrInvalidSession = errors.New("invalid session")

type Session interface {
	ID() string
	Method() Method
	ExpiresAt() time.Time
	Status() Status
	Marshal() ([]byte, error)
}

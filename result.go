package authn

import "errors"

var ErrInvalidResult = errors.New("invalid result")

type Result struct {
	Status    Status
	Identity  Identity
	Challenge Challenge
	Session   Session
}

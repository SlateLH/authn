package authn

import "errors"

var ErrInvalidCredentials = errors.New("invalid credentials")

type Credentials interface {
	Identifier() Identifier
	Method() Method
}

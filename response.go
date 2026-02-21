package authn

import "errors"

var ErrInvalidResponse = errors.New("invalid response")

type Response interface {
	Method() Method
}

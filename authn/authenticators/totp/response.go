package totp

import "github.com/SlateLH/authn/authn"

type Response interface {
	Code() string
	Method() authn.Method
}

type response struct {
	code string
}

func (r response) Code() string {
	return r.code
}

func (r response) Method() authn.Method {
	return Method
}

func NewResponse(code string) Response {
	return response{code: code}
}

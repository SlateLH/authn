package totp

import "github.com/SlateLH/authn/authn"

type Credentials interface {
	Identifier() authn.Identifier
	Method() authn.Method
}

type credentials struct {
	identifier authn.Identifier
}

func (c credentials) Identifier() authn.Identifier {
	return c.identifier
}

func (c credentials) Method() authn.Method {
	return Method
}

func NewCredentials(identifier authn.Identifier) Credentials {
	return credentials{
		identifier: identifier,
	}
}

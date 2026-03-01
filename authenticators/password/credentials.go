package password

import "github.com/SlateLH/authn"

type Credentials interface {
	Identifier() authn.Identifier
	Password() string
	Method() authn.Method
}

type credentials struct {
	identifier authn.Identifier
	password   string
}

func (c credentials) Identifier() authn.Identifier {
	return c.identifier
}

func (c credentials) Password() string {
	return c.password
}

func (c credentials) Method() authn.Method {
	return Method
}

var _ authn.Credentials = (*credentials)(nil)

func NewCredentials(identifier authn.Identifier, password string) Credentials {
	return credentials{
		identifier: identifier,
		password:   password,
	}
}

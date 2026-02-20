package authn

type Credentials interface {
	Identifier() Identifier
	Method() Method
}

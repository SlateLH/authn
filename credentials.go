package authn

type Credentials interface {
	Method() Method
}

package authn

type IdentifierType string

type Identifier struct {
	Type  IdentifierType
	Value string
}

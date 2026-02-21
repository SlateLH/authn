package authn

import (
	"context"
)

type Method string
type Status string

const (
	StatusAuthenticated Status = "authenticated"
	StatusChallenged    Status = "challenged"
	StatusPending       Status = "pending"
	StatusFailed        Status = "failed"
)

type Authenticator interface {
	Method() Method
	Initiate(ctx context.Context, credentials Credentials) (Result, error)
	Respond(ctx context.Context, session Session, response Response) (Result, error)
}

package authn

import (
	"context"
	"errors"
	"fmt"
)

var ErrInvalidMethod = errors.New("invalid method")

type Service interface {
	/*
		This function is not guaranteed to be safe for concurrent use.
		The default implementation provided by authn (from [New]) is not safe for concurrency.
	*/
	Register(auth Authenticator) error
	Initiate(ctx context.Context, credentials Credentials) (Result, error)
	Respond(ctx context.Context, session Session, response Response) (Result, error)
}

type service struct {
	methods map[Method]Authenticator
	clock   Clock
}

func (s *service) Register(auth Authenticator) error {
	if auth == nil {
		return errors.New("invalid authenticator")
	}

	existing, ok := s.methods[auth.Method()]
	if existing != nil || ok {
		return fmt.Errorf("method \"%s\" already registered", auth.Method())
	}

	s.methods[auth.Method()] = auth
	return nil
}

func (s *service) Initiate(ctx context.Context, credentials Credentials) (Result, error) {
	if credentials == nil {
		return Result{}, ErrInvalidCredentials
	}

	auth, ok := s.methods[credentials.Method()]
	if auth == nil || !ok {
		return Result{}, ErrInvalidMethod
	}

	result, err := auth.Initiate(ctx, credentials)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
	}

	if err := validateResult(result); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidResult, err)
	}

	return result, nil
}

func (s *service) Respond(ctx context.Context, session Session, response Response) (Result, error) {
	if session == nil || response == nil {
		return Result{Status: StatusFailed}, nil
	}

	if session.Method() != response.Method() {
		return Result{}, fmt.Errorf("session method \"%s\" does not match response method \"%s\"", session.Method(), response.Method())
	}

	if s.clock.Now().After(session.ExpiresAt()) {
		return Result{Status: StatusFailed}, nil
	}

	auth, ok := s.methods[session.Method()]
	if auth == nil || !ok {
		return Result{}, ErrInvalidMethod
	}

	result, err := auth.Respond(ctx, session, response)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if err := validateResult(result); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidResult, err)
	}

	if result.Session != nil && session.Status() != result.Status {
		return Result{}, fmt.Errorf("session status \"%s\" does not match result session status \"%s\"", session.Status(), result.Session.Status())
	}

	if result.Session != nil && session.Method() != result.Session.Method() {
		return Result{}, fmt.Errorf("session method \"%s\" does not match result session method \"%s\"", session.Method(), result.Session.Method())
	}

	if err := validateTransition(session.Status(), result.Status); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidResult, err)
	}

	return result, nil
}

type serviceOption func(*service)

func WithClock(clock Clock) serviceOption {
	return func(s *service) {
		s.clock = clock
	}
}

func New(options ...serviceOption) Service {
	methods := make(map[Method]Authenticator)

	svc := &service{
		methods: methods,
		clock:   SystemClock{},
	}

	for _, option := range options {
		option(svc)
	}

	return svc
}

func validateResult(result Result) error {
	switch result.Status {
	case StatusAuthenticated:
		if result.Identity.ID == "" {
			return errors.New("authenticated result missing identity")
		}
		if result.Challenge != nil {
			return errors.New("authenticated result contains challenge")
		}
		if result.Session != nil {
			return errors.New("authenticated result contains session")
		}
		return nil
	case StatusChallenged:
		if result.Identity.ID != "" {
			return errors.New("challenged result contains identity")
		}
		if result.Challenge == nil {
			return errors.New("challenged result is missing challenge")
		}
		if result.Session == nil {
			return errors.New("challenged result is missing session")
		}
		return nil
	case StatusPending:
		if result.Identity.ID != "" {
			return errors.New("pending result contains identity")
		}
		if result.Challenge != nil {
			return errors.New("pending result contains challenge")
		}
		if result.Session == nil {
			return errors.New("pending result is missing session")
		}
		return nil
	case StatusFailed:
		if result.Identity.ID != "" {
			return errors.New("failed result contains identity")
		}
		if result.Challenge != nil {
			return errors.New("failed result contains challenge")
		}
		if result.Session != nil {
			return errors.New("failed result contains session")
		}
		return nil
	default:
		return fmt.Errorf("unexpected status \"%s\"", result.Status)
	}
}

func validateTransition(previous Status, next Status) error {
	switch previous {
	case StatusChallenged:
		switch next {
		case StatusAuthenticated, StatusChallenged, StatusFailed:
			return nil
		}
	case StatusPending:
		switch next {
		case StatusAuthenticated, StatusPending, StatusFailed:
			return nil
		}
	}

	return errors.New("invalid transition")
}

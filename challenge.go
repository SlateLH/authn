package authn

type ChallengeType string

type Challenge interface {
	Type() ChallengeType
	Marshal() ([]byte, error)
}

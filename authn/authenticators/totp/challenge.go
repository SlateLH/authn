package totp

import "github.com/SlateLH/authn/authn"

const ChallengeType authn.ChallengeType = "totp"

type Challenge interface {
	Type() authn.ChallengeType
	Marshal() ([]byte, error)
}

type challenge struct{}

func (c challenge) Type() authn.ChallengeType {
	return ChallengeType
}

func (c challenge) Marshal() ([]byte, error) {
	return []byte{}, nil
}

func NewChallenge() Challenge {
	return challenge{}
}

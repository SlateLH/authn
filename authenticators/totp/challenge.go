package totp

import "github.com/SlateLH/authn"

const ChallengeType authn.ChallengeType = "totp"

type Challenge interface {
	Type() authn.ChallengeType
}

type challenge struct{}

func (c challenge) Type() authn.ChallengeType {
	return ChallengeType
}

func NewChallenge() Challenge {
	return challenge{}
}

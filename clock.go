package authn

import "time"

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (c SystemClock) Now() time.Time {
	return time.Now()
}

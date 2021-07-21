package factory

import (
	"time"

	"k8s.io/client-go/util/workqueue"
)

type RateLimitedAddAfterWorkqueue interface {
	workqueue.RateLimitingInterface

	// AddRateLimitedAfter adds the items to the queue after the given duration,
	// but not earlier than the rate-limited allows. I.e. this is a combination of
	// AddAfter and AddRateLimited.
	AddRateLimitedAfter(item interface{}, duration time.Duration)
}

type addRateLimitedAfterWorkqueue struct {
	workqueue.RateLimitingInterface
	rateLimiter workqueue.RateLimiter
}

var _ RateLimitedAddAfterWorkqueue = addRateLimitedAfterWorkqueue{}

// AddRateLimitedAfter adds the items to the queue after the given duration,
// but not earlier than the rate-limited allows. I.e. this is a combination of
// AddAfter and AddRateLimited.
func (q addRateLimitedAfterWorkqueue) AddRateLimitedAfter(item interface{}, duration time.Duration) {
	if rlDelay := q.rateLimiter.When(item); rlDelay > duration {
		duration = rlDelay
	}
	q.RateLimitingInterface.AddAfter(item, duration)
}

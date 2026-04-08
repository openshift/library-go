// Package endpointcheck provides a retry-with-backoff loop for endpoint
// health checks. It skips the backoff sleep after context.DeadlineExceeded
// errors (since the request timeout already provided sufficient delay) and
// stops immediately on backoff.Permanent errors.
package endpointcheck

import (
	"context"
	"errors"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/openshift/library-go/pkg/operator/resource/retry"
)

// CheckFunc is called on each attempt with the parent context and the
// per-request timeout. Return nil on success, a regular error to trigger
// a retry, or backoff.Permanent(err) to abort immediately.
type CheckFunc func(ctx context.Context, requestTimeout time.Duration) error

// Check runs checkFn up to maxAttempts times, sleeping according to
// retryBackoff between attempts. If checkFn returns context.DeadlineExceeded
// the next backoff interval is shortened by the elapsed request time, since
// the request timeout already consumed wall-clock time.
func Check(ctx context.Context, requestTimeout time.Duration, retryBackoff backoff.BackOff, maxAttempts uint64, checkFn CheckFunc) error {
	if maxAttempts == 0 {
		return nil
	}

	cuttableBoff := retry.NewCuttableBackOff(retryBackoff)
	boff := backoff.WithContext(backoff.WithMaxRetries(cuttableBoff, maxAttempts-1), ctx)
	return backoff.Retry(func() error {
		start := time.Now()
		err := checkFn(ctx, requestTimeout)
		if errors.Is(err, context.DeadlineExceeded) {
			cuttableBoff.CutNextBy(time.Since(start))
		}
		return err
	}, boff)
}

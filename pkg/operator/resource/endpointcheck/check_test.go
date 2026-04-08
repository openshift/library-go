package endpointcheck

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cenkalti/backoff/v4"
)

func TestCheck_SucceedsImmediately(t *testing.T) {
	var called atomic.Int32
	checkFn := func(ctx context.Context) error {
		called.Add(1)
		return nil
	}

	err := Check(context.Background(), backoff.NewConstantBackOff(time.Second), 3, checkFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := called.Load(); n != 1 {
		t.Errorf("checkFn called %d times, want 1", n)
	}
}

func TestCheck_RetriesOnError(t *testing.T) {
	const attemptCount = 4
	const retryInterval = 10 * time.Second

	tests := []struct {
		name        string
		failFirstN  int32
		wantErr     bool
		wantElapsed time.Duration
	}{
		{
			name:        "succeeds on last attempt",
			failFirstN:  int32(attemptCount - 1),
			wantErr:     false,
			wantElapsed: time.Duration(attemptCount-1) * retryInterval,
		},
		{
			name:        "fails after all attempts exhausted",
			failFirstN:  int32(attemptCount),
			wantErr:     true,
			wantElapsed: time.Duration(attemptCount-1) * retryInterval,
		},
		{
			name:        "succeeds immediately",
			failFirstN:  0,
			wantErr:     false,
			wantElapsed: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				checkFn := func(ctx context.Context) error {
					if calls.Add(1) <= tt.failFirstN {
						return errors.New("fail")
					}
					return nil
				}

				start := time.Now()
				done := make(chan error, 1)
				go func() {
					done <- Check(context.Background(), backoff.NewConstantBackOff(retryInterval), attemptCount, checkFn)
				}()
				synctest.Wait()

				err := <-done
				if (err != nil) != tt.wantErr {
					t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				}
				if elapsed := time.Since(start); elapsed != tt.wantElapsed {
					t.Errorf("Check() took %v, wanted %v", elapsed, tt.wantElapsed)
				}
			})
		})
	}
}

func TestCheck_PermanentErrorStopsRetries(t *testing.T) {
	var calls atomic.Int32
	checkFn := func(ctx context.Context) error {
		calls.Add(1)
		return backoff.Permanent(errors.New("permanent"))
	}

	err := Check(context.Background(), backoff.NewConstantBackOff(time.Millisecond), 3, checkFn)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("checkFn called %d times, want 1 (permanent error should stop retries)", n)
	}
}

func TestCheck_TimeoutCutsBackoff(t *testing.T) {
	const retryInterval = 10 * time.Second
	const requestTimeout = 5 * time.Second

	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		checkFn := func(ctx context.Context) error {
			if calls.Add(1) == 1 {
				// Simulate a request that ran for the full timeout before failing.
				time.Sleep(requestTimeout)
				return context.DeadlineExceeded
			}
			return nil
		}

		start := time.Now()
		done := make(chan error, 1)
		go func() {
			done <- Check(context.Background(), backoff.NewConstantBackOff(retryInterval), 2, checkFn)
		}()

		err := <-done
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Without cutting, total would be requestTimeout + retryInterval = 15s.
		// With cutting, the backoff is reduced by requestTimeout, so total ≈ 10s.
		elapsed := time.Since(start)
		if elapsed >= requestTimeout+retryInterval {
			t.Errorf("elapsed %v >= %v; backoff was not cut after timeout", elapsed, requestTimeout+retryInterval)
		}
	})
}

func TestCheck_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	checkFn := func(ctx context.Context) error {
		return errors.New("retry")
	}

	err := Check(ctx, backoff.NewConstantBackOff(time.Millisecond), 3, checkFn)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("expected error from cancelled context")
	}
}

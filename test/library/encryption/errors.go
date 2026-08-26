/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package encryption

import (
	"context"
	gonet "net"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/wait"
)

// isConnectionRefusedError checks if the error string include "connection refused"
// TODO: find a "go-way" to detect this error, probably using *os.SyscallError
func isConnectionRefusedError(err error) bool {
	return strings.Contains(err.Error(), "connection refused")
}

func isGolangNetTimeout(err error) bool {
	if err, ok := err.(*gonet.OpError); !ok {
		return false
	} else {
		return err.Timeout() || err.Temporary()
	}
}

// transientAPIError returns true if the provided error indicates that a retry
// against an HA server has a good chance to succeed.
func transientAPIError(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.IsServiceUnavailable(err), errors.IsServerTimeout(err), errors.IsTooManyRequests(err), net.IsProbableEOF(err), net.IsConnectionReset(err), net.IsNoRoutesError(err), isConnectionRefusedError(err), isGolangNetTimeout(err):
		return true
	default:
		return false
	}
}

func orError(a, b func(error) bool) func(error) bool {
	return func(err error) bool {
		return a(err) || b(err)
	}
}

// onErrorWithTimeout retries fn until it succeeds, the timeout elapses, or fn
// returns an error that errorFunc does not classify as retriable.
//
// It is built on wait.PollUntilContextTimeout so the timeout is actually honored:
// unlike wait.ExponentialBackoff, the number of retries is bounded by the wall
// clock, not by a fixed step count. This matters on single-node clusters where
// the API server can be unavailable for far longer than a handful of quick
// backoff steps while a new revision rolls out.
//
// On timeout the last retriable error is returned (rather than the generic
// "timed out" error) so callers get an actionable message.
func onErrorWithTimeout(timeout time.Duration, errorFunc func(error) bool, fn func() error) error {
	var lastMatchingError error
	err := wait.PollUntilContextTimeout(context.Background(), waitPollInterval, timeout, true, func(context.Context) (bool, error) {
		err := fn()
		switch {
		case err == nil:
			return true, nil
		case errorFunc(err):
			lastMatchingError = err
			return false, nil
		default:
			return false, err
		}
	})
	if wait.Interrupted(err) && lastMatchingError != nil {
		err = lastMatchingError
	}
	return err
}

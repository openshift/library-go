package apiservice

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/library-go/pkg/operator/events"
)

var cmpOpts = cmp.Options{cmpopts.EquateEmpty()}

func makeAPIService(group, version string) *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: version + "." + group},
		Spec:       apiregistrationv1.APIServiceSpec{Group: group, Version: version},
	}
}

// apiServiceCheckFuncFromErrors returns an apiServiceCheckFunc that returns errors
// from the given slice in order for each call. Once the slice is exhausted, it
// returns nil.
func apiServiceCheckFuncFromErrors(errs ...error) (apiServiceCheckFunc, *int) {
	call := 0
	return func(_ context.Context, _ rest.Interface, _ *apiregistrationv1.APIService, _ time.Duration) error {
		if call < len(errs) {
			err := errs[call]
			call++
			return err
		}
		call++
		return nil
	}, &call
}

type checkResult struct {
	Calls         int
	Messages      []string
	EventReasons  []string
	EventMessages []string
	Elapsed       time.Duration
}

func runCheck(t *testing.T, ctx context.Context, apiServices []*apiregistrationv1.APIService, checkFn apiServiceCheckFunc, calls *int) checkResult {
	t.Helper()
	recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))
	start := time.Now()
	msgs := checkDiscoveryForByAPIServicesWithCheckFn(ctx, recorder, nil, apiServices, checkFn)
	elapsed := time.Since(start)

	var reasons, eventMsgs []string
	for _, e := range recorder.Events() {
		reasons = append(reasons, e.Reason)
		eventMsgs = append(eventMsgs, e.Message)
	}

	return checkResult{
		Messages:      msgs,
		Calls:         *calls,
		EventReasons:  reasons,
		EventMessages: eventMsgs,
		Elapsed:       elapsed,
	}
}

func TestCheckDiscoveryForByAPIServices_AllSucceedOnFirstAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		checkFn, calls := apiServiceCheckFuncFromErrors()
		got := runCheck(t, context.Background(), []*apiregistrationv1.APIService{
			makeAPIService("apps.openshift.io", "v1"),
			makeAPIService("build.openshift.io", "v1"),
		}, checkFn, calls)

		got.Elapsed = 0
		want := checkResult{Calls: 2}
		if diff := cmp.Diff(want, got, cmpOpts); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestCheckDiscoveryForByAPIServices_FailThenSucceedOnRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		checkFn, calls := apiServiceCheckFuncFromErrors(errors.New("transient"))
		got := runCheck(t, context.Background(), []*apiregistrationv1.APIService{
			makeAPIService("apps.openshift.io", "v1"),
		}, checkFn, calls)

		got.Elapsed = 0
		want := checkResult{Calls: 2}
		if diff := cmp.Diff(want, got, cmpOpts); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestCheckDiscoveryForByAPIServices_ExhaustsAllRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// WithMaxRetries(b, 2) allows 3 attempts total.
		checkFn, calls := apiServiceCheckFuncFromErrors(
			errors.New("fail1"),
			errors.New("fail2"),
			errors.New("fail3"),
		)
		got := runCheck(t, context.Background(), []*apiregistrationv1.APIService{
			makeAPIService("apps.openshift.io", "v1"),
		}, checkFn, calls)

		got.Elapsed = 0
		want := checkResult{
			Calls:         3,
			Messages:      []string{`"apps.openshift.io.v1" is not ready: fail3`},
			EventReasons:  []string{"OpenShiftAPICheckFailed"},
			EventMessages: []string{`"apps.openshift.io.v1" failed with fail3`},
		}
		if diff := cmp.Diff(want, got, cmpOpts); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestCheckDiscoveryForByAPIServices_RetriesReducedAfterFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// First API service: 3 attempts, all fail.
		// After first failure, retryCount is set to 0, so second API service
		// gets WithMaxRetries(b, 0) = 1 attempt, which also fails.
		// Total: 3 + 1 = 4 calls.
		checkFn, calls := apiServiceCheckFuncFromErrors(
			errors.New("fail1"),
			errors.New("fail2"),
			errors.New("fail3"),
			errors.New("fail4"),
		)
		got := runCheck(t, context.Background(), []*apiregistrationv1.APIService{
			makeAPIService("apps.openshift.io", "v1"),
			makeAPIService("build.openshift.io", "v1"),
		}, checkFn, calls)

		got.Elapsed = 0
		want := checkResult{
			Calls: 4,
			Messages: []string{
				`"apps.openshift.io.v1" is not ready: fail3`,
				`"build.openshift.io.v1" is not ready: fail4`,
			},
			EventReasons: []string{
				"OpenShiftAPICheckFailed",
				"OpenShiftAPICheckFailed",
			},
			EventMessages: []string{
				`"apps.openshift.io.v1" failed with fail3`,
				`"build.openshift.io.v1" failed with fail4`,
			},
		}
		if diff := cmp.Diff(want, got, cmpOpts); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestCheckDiscoveryForByAPIServices_TimeoutCutsBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// First attempt simulates a full 10s request timeout, second succeeds.
		call := 0
		checkFn := func(_ context.Context, _ rest.Interface, _ *apiregistrationv1.APIService, requestTimeout time.Duration) error {
			call++
			if call == 1 {
				time.Sleep(requestTimeout) // simulate the timeout consuming wall-clock time
				return context.DeadlineExceeded
			}
			return nil
		}

		got := runCheck(t, context.Background(), []*apiregistrationv1.APIService{
			makeAPIService("apps.openshift.io", "v1"),
		}, checkFn, &call)

		want := checkResult{Calls: 2}
		// The backoff is 5s and the request consumed 10s, so the backoff should
		// be fully cut. Total elapsed ≈ requestTimeout (10s), not 10s + 5s.
		if got.Elapsed > 11*time.Second {
			t.Errorf("expected backoff to be cut after timeout, but elapsed %v", got.Elapsed)
		}
		got.Elapsed = 0
		if diff := cmp.Diff(want, got, cmpOpts); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestCheckDiscoveryForByAPIServices_NonTimeoutRespectsBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// First attempt fails with a non-timeout error, second succeeds.
		checkFn, calls := apiServiceCheckFuncFromErrors(errors.New("transient"))
		got := runCheck(t, context.Background(), []*apiregistrationv1.APIService{
			makeAPIService("apps.openshift.io", "v1"),
		}, checkFn, calls)

		want := checkResult{Calls: 2}
		// The backoff is 5s. A non-timeout error should wait the full backoff.
		if got.Elapsed < 5*time.Second {
			t.Errorf("expected backoff delay of 5s for non-timeout error, but fake clock advanced %v", got.Elapsed)
		}
		got.Elapsed = 0
		if diff := cmp.Diff(want, got, cmpOpts); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestCheckDiscoveryForByAPIServices_ContextCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		checkFn := func(_ context.Context, _ rest.Interface, _ *apiregistrationv1.APIService, _ time.Duration) error {
			calls++
			cancel()
			return errors.New("fail")
		}

		// Pass multiple API services to verify that only the first one
		// records a failure and the rest are skipped after context cancellation.
		got := runCheck(t, ctx, []*apiregistrationv1.APIService{
			makeAPIService("apps.openshift.io", "v1"),
			makeAPIService("build.openshift.io", "v1"),
			makeAPIService("image.openshift.io", "v1"),
		}, checkFn, &calls)

		got.Elapsed = 0
		want := checkResult{
			Calls:         1,
			Messages:      []string{`"apps.openshift.io.v1" is not ready: context canceled`},
			EventReasons:  []string{"OpenShiftAPICheckFailed"},
			EventMessages: []string{`"apps.openshift.io.v1" failed with context canceled`},
		}
		if diff := cmp.Diff(want, got, cmpOpts); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

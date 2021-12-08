package controllercmd

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/events/eventstesting"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestControllerBuilder_getOnStartedLeadingFunc(t *testing.T) {
	nonZeroExits := []string{}
	b := ControllerBuilder{
		nonZeroExitFn: func(args ...interface{}) {
			nonZeroExits = append(nonZeroExits, fmt.Sprintf("%#v", args))
		},
		startFunc: func(ctx context.Context, controllerContext *ControllerContext) error {
			time.Sleep(1 * time.Second)
			return nil
		},
	}

	// controllers finished prematurely, without being asked to finish
	b.getOnStartedLeadingFunc(&ControllerContext{EventRecorder: eventstesting.NewTestingEventRecorder(t)}, 3*time.Second)(context.TODO())
	if len(nonZeroExits) != 1 || !strings.Contains(nonZeroExits[0], "controllers terminated prematurely") {
		t.Errorf("expected controllers to exit prematurely, got %#v", nonZeroExits)
	}

	// controllers finished gracefully after context was cancelled, with zero exit status
	nonZeroExits = []string{}
	ctx, cancel := context.WithCancel(context.TODO())
	go func() {
		defer cancel()
		time.Sleep(1 * time.Second)
	}()
	b.startFunc = func(ctx context.Context, controllerContext *ControllerContext) error {
		time.Sleep(2 * time.Second)
		return nil
	}
	b.getOnStartedLeadingFunc(&ControllerContext{EventRecorder: eventstesting.NewTestingEventRecorder(t)}, 5*time.Second)(ctx)
	if len(nonZeroExits) > 0 {
		t.Errorf("expected controllers to exit gracefully, but got %#v", nonZeroExits)
	}

	// controllers passed the graceful termination duration and are force killed
	nonZeroExits = []string{}
	ctx, cancel = context.WithCancel(context.TODO())
	go func() {
		defer cancel()
		time.Sleep(1 * time.Second)
	}()
	b.startFunc = func(ctx context.Context, controllerContext *ControllerContext) error {
		time.Sleep(3 * time.Second)
		return nil
	}
	b.getOnStartedLeadingFunc(&ControllerContext{EventRecorder: eventstesting.NewTestingEventRecorder(t)}, 1*time.Second)(ctx)
	if len(nonZeroExits) != 1 && !strings.Contains(nonZeroExits[0], "some controllers failed to shutdown in 1s") {
		t.Errorf("expected controllers to failed finish in 1s, got %#v", nonZeroExits)
	}
}

func TestControllerBuilder_GracefulShutdown(t *testing.T) {
	nonZeroExitCh := make(chan struct{})
	startedCh := make(chan struct{})
	ctx, shutdown := context.WithCancel(context.Background())

	b := &ControllerBuilder{
		nonZeroExitFn: func(args ...interface{}) {
			t.Logf("non-zero exit detected: %+v", args)
			close(nonZeroExitCh)
		},
		startFunc: func(ctx context.Context, controllerContext *ControllerContext) error {
			close(startedCh)
			<-ctx.Done()
			return nil
		},
	}

	// wait for controller to run, then give it 1s and shutdown
	go func() {
		defer shutdown()
		<-startedCh
		time.Sleep(time.Second)
	}()

	stoppedCh := make(chan struct{})
	go func() {
		defer close(stoppedCh)
		b.getOnStartedLeadingFunc(&ControllerContext{EventRecorder: eventstesting.NewTestingEventRecorder(t)}, 10*time.Second)(ctx)
	}()

	select {
	case <-nonZeroExitCh:
		t.Fatal("unexpected non-zero shutdown")
	case <-stoppedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("unexpected timeout while terminating")
	}
}

func TestControllerBuilder_OnLeadingFunc_ControllerError(t *testing.T) {
	startedCh := make(chan struct{})
	stoppedCh := make(chan struct{})
	ctx := context.Background()

	fatals := []string{}

	b := &ControllerBuilder{
		nonZeroExitFn: func(args ...interface{}) {
			fatals = append(fatals, fmt.Sprintf("%v", args[0]))
			t.Logf("non-zero exit detected: %+v", args)
		},
		startFunc: func(ctx context.Context, controllerContext *ControllerContext) error {
			defer close(startedCh)
			return fmt.Errorf("controller failed")
		},
	}

	go func() {
		defer close(stoppedCh)
		b.getOnStartedLeadingFunc(&ControllerContext{EventRecorder: eventstesting.NewTestingEventRecorder(t)}, 10*time.Second)(ctx)
	}()

	<-startedCh

	select {
	case <-stoppedCh:
		if len(fatals) == 0 {
			t.Fatal("expected non-zero exit, got none")
		}
		found := false
		// this is weird, but normally klog.Fatal() just terminate process.
		// however, since we mock the klog.Fatal() we will see both controller failure
		// and "controllers terminated prematurely"...
		for _, msg := range fatals {
			if msg == `graceful termination failed, controllers failed with error: controller failed` {
				found = true
			}
		}
		if !found {
			t.Fatalf("controller failed message not found in fatals: %#v", fatals)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unexpected timeout while terminating")
	}
}

func TestControllerBuilder_OnLeadingFunc_NonZeroExit(t *testing.T) {
	nonZeroExitCh := make(chan struct{})
	startedCh := make(chan struct{})
	ctx, shutdown := context.WithCancel(context.Background())

	b := &ControllerBuilder{
		nonZeroExitFn: func(args ...interface{}) {
			t.Logf("non-zero exit detected: %+v", args)
			close(nonZeroExitCh)
		},
		startFunc: func(ctx context.Context, controllerContext *ControllerContext) error {
			close(startedCh)
			<-ctx.Done()
			time.Sleep(10 * time.Second) // simulate controllers taking too much time to finish
			return nil
		},
	}

	// wait for controller to run, then give it 1s and shutdown
	go func() {
		defer shutdown()
		<-startedCh
		time.Sleep(2 * time.Second)
	}()

	go func() {
		b.getOnStartedLeadingFunc(&ControllerContext{EventRecorder: eventstesting.NewTestingEventRecorder(t)}, time.Second)(ctx) // graceful time is just 1s
	}()

	select {
	case <-nonZeroExitCh:
		t.Logf("got non-zero exit")
		return
	case <-time.After(5 * time.Second):
		t.Fatal("unexpected timeout while terminating")
	}
}

func TestInfraStatusTopologyLeaderElection(t *testing.T) {
	testCases := []struct {
		desc     string
		infra    *configv1.InfrastructureStatus
		original configv1.LeaderElection
		expected configv1.LeaderElection
	}{
		{
			desc:  "should not set SNO config when infra is nil",
			infra: nil,
			original: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
			expected: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
		},
		{
			desc: "should not set SNO config when infra is HighlyAvailableTopologyMode",
			infra: &configv1.InfrastructureStatus{
				ControlPlaneTopology: configv1.HighlyAvailableTopologyMode,
			},
			original: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
			expected: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
		},
		{
			desc: "should set SNO leader election config when SingleReplicaToplogy Controlplane",
			infra: &configv1.InfrastructureStatus{
				ControlPlaneTopology: configv1.SingleReplicaTopologyMode,
			},
			original: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
			expected: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 270 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 240 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 60 * time.Second},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			leConfig := infraStatusTopologyLeaderElection(tc.infra, tc.original)
			if !reflect.DeepEqual(tc.expected, leConfig) {
				t.Errorf("expected %#v, got %#v", tc.expected, leConfig)
			}
		})
	}
}

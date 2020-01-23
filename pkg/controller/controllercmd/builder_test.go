package controllercmd

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestControllerBuilder_OnLeadingFunc(t *testing.T) {
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

	stopCh := make(chan struct{})
	go func() {
		defer close(stopCh)
		b.getOnStartedLeadingFunc(ctx, &ControllerContext{}, 10*time.Second)(ctx)
	}()

	select {
	case <-nonZeroExitCh:
		t.Fatal("unexpected non-zero shutdown")
	case <-stopCh:
	case <-time.After(5 * time.Second):
		t.Fatal("unexpected timeout while terminating")
	}
}

func TestControllerBuilder_OnLeadingFunc_ControllerError(t *testing.T) {
	startedCh := make(chan struct{})
	stopCh := make(chan struct{})
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
		defer close(stopCh)
		b.getOnStartedLeadingFunc(ctx, &ControllerContext{}, 10*time.Second)(ctx)
	}()

	<-startedCh

	select {
	case <-stopCh:
		if len(fatals) == 0 {
			t.Fatal("expected non-zero exit, got none")
		}
		found := false
		// this is weird, but normally klog.Fatal() just terminate process.
		// however, since we mock the klog.Fatal() we will see both controller failure
		// and "controllers terminated prematurely"...
		for _, msg := range fatals {
			if msg == `controllers failed with error: controller failed` {
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
		b.getOnStartedLeadingFunc(ctx, &ControllerContext{}, time.Second)(ctx) // graceful time is just 1s
	}()

	select {
	case <-nonZeroExitCh:
		t.Logf("got non-zero exit")
		return
	case <-time.After(5 * time.Second):
		t.Fatal("unexpected timeout while terminating")
	}
}

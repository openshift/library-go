package factory

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/tools/cache"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events/eventstesting"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type fakeInformer struct {
	hasSyncedDelay       time.Duration
	eventHandler         cache.ResourceEventHandler
	addEventHandlerCount int
	hasSyncedCount       int
	sync.Mutex
}

func (f *fakeInformer) AddEventHandler(handler cache.ResourceEventHandler) {
	f.Lock()
	defer func() { f.addEventHandlerCount++; f.Unlock() }()
	f.eventHandler = handler
}

func (f *fakeInformer) HasSynced() bool {
	f.Lock()
	defer func() { f.hasSyncedCount++; f.Unlock() }()
	time.Sleep(f.hasSyncedDelay)
	return true
}

func TestBaseController_ExitOneIfCachesWontSync(t *testing.T) {
	c := &baseController{
		syncContext:      NewSyncContext("test", eventstesting.NewTestingEventRecorder(t)),
		cacheSyncTimeout: 1 * time.Second,
		cachesToSync: []cache.InformerSynced{
			func() bool {
				return false
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if os.Getenv("BE_CRASHER") == "1" {
		c.Run(ctx, 1)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBaseController_ExitOneIfCachesWontSync")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	e, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("unexpected error %#v", err)
	}

	exitCode := e.ExitCode()
	if exitCode != 1 {
		t.Fatalf("expected exit code %d, got %d", 1, exitCode)
	}
}

func TestBaseController_ReturnOnGracefulShutdownWhileWaitingForCachesToSync(t *testing.T) {
	c := &baseController{
		syncContext:      NewSyncContext("test", eventstesting.NewTestingEventRecorder(t)),
		cacheSyncTimeout: 666 * time.Minute,
		cachesToSync: []cache.InformerSynced{
			func() bool {
				return false
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // close context immediately

	c.Run(ctx, 1)
}

func TestBaseController_Reconcile(t *testing.T) {
	operatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{},
		&operatorv1.OperatorStatus{},
		nil,
	)
	c := &baseController{
		name:           "TestController",
		operatorClient: operatorClient,

		handleSyncDegraded: true,
	}

	c.sync = func(ctx context.Context, controllerContext SyncContext) error {
		return nil
	}
	if err := c.reconcile(context.TODO(), NewSyncContext("TestController", eventstesting.NewTestingEventRecorder(t))); err != nil {
		t.Fatal(err)
	}
	_, status, _, err := operatorClient.GetOperatorState()
	if err != nil {
		t.Fatal(err)
	}
	if !v1helpers.IsOperatorConditionPresentAndEqual(status.Conditions, "TestControllerDegraded", "False") {
		t.Fatalf("expected TestControllerDegraded to be False, got %#v", status.Conditions)
	}
	c.sync = func(ctx context.Context, controllerContext SyncContext) error {
		return fmt.Errorf("error")
	}
	if err := c.reconcile(context.TODO(), NewSyncContext("TestController", eventstesting.NewTestingEventRecorder(t))); err == nil {
		t.Fatal("expected error, got none")
	}
	_, status, _, err = operatorClient.GetOperatorState()
	if err != nil {
		t.Fatal(err)
	}
	if !v1helpers.IsOperatorConditionPresentAndEqual(status.Conditions, "TestControllerDegraded", "True") {
		t.Fatalf("expected TestControllerDegraded to be False, got %#v", status.Conditions)
	}
	condition := v1helpers.FindOperatorCondition(status.Conditions, "TestControllerDegraded")
	if condition.Reason != "SyncError" {
		t.Errorf("expected condition reason 'SyncError', got %q", condition.Reason)
	}
	if condition.Message != "error" {
		t.Errorf("expected condition message 'error', got %q", condition.Message)
	}
}

func TestBaseController_Run(t *testing.T) {
	informer := &fakeInformer{hasSyncedDelay: 200 * time.Millisecond}
	controllerCtx, cancel := context.WithCancel(context.Background())
	syncCount := 0
	postStartHookSyncCount := 0
	postStartHookDone := false

	c := &baseController{
		name:         "test",
		cachesToSync: []cache.InformerSynced{informer.HasSynced},
		sync: func(ctx context.Context, syncCtx SyncContext) error {
			defer func() { syncCount++ }()
			defer t.Logf("Sync() call with %q", syncCtx.QueueKey())
			if syncCtx.QueueKey() == "postStartHookKey" {
				postStartHookSyncCount++
				return fmt.Errorf("test error")
			}
			return nil
		},
		syncContext: NewSyncContext("test", eventstesting.NewTestingEventRecorder(t)),
		resyncEvery: 200 * time.Millisecond,
		postStartHooks: []PostStartHook{func(ctx context.Context, syncContext SyncContext) error {
			defer func() {
				postStartHookDone = true
			}()
			syncContext.Queue().Add("postStartHookKey")
			<-ctx.Done()
			t.Logf("post start hook terminated")
			return nil
		}},
	}

	time.AfterFunc(1*time.Second, func() {
		cancel()
	})
	c.Run(controllerCtx, 1)

	informer.Lock()
	if informer.hasSyncedCount == 0 {
		t.Errorf("expected HasSynced() called at least once, got 0")
	}
	informer.Unlock()
	if syncCount == 0 {
		t.Errorf("expected at least one sync call, got 0")
	}
	if postStartHookSyncCount == 0 {
		t.Errorf("expected the post start hook queue key, got none")
	}
	if !postStartHookDone {
		t.Errorf("expected the post start hook to be terminated when context is cancelled")
	}
}

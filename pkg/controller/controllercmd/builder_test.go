package controllercmd

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s.io/client-go/rest"

	"github.com/openshift/library-go/pkg/crypto"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"

	"github.com/openshift/library-go/pkg/operator/events/eventstesting"
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

func TestControllerBuilder_WithServer_Serve_Metrics_And_Debug(t *testing.T) {
	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	startedCh := make(chan struct{})
	b := &ControllerBuilder{
		componentNamespace: "test",
		eventRecorder:      eventstesting.NewTestingEventRecorder(t),
		startFunc: func(ctx context.Context, controllerContext *ControllerContext) error {
			close(startedCh)
			<-ctx.Done()
			return nil
		},
	}

	// make certificates for local server
	config, err := crypto.MakeSelfSignedCAConfigForSubject(pkix.Name{CommonName: "127.0.0.1:8888"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	certFile, _ := ioutil.TempFile(os.TempDir(), "test-")
	defer os.Remove(certFile.Name())
	keyFile, _ := ioutil.TempFile(os.TempDir(), "test-")
	defer os.Remove(keyFile.Name())
	if err := config.WriteCertConfigFile(certFile.Name(), keyFile.Name()); err != nil {
		t.Fatal(err)
	}

	go func() {
		b := b.WithServer(configv1.HTTPServingInfo{
			ServingInfo: configv1.ServingInfo{
				BindAddress: "127.0.0.1:8888",
				CertInfo: configv1.CertInfo{
					CertFile: certFile.Name(),
					KeyFile:  keyFile.Name(),
				},
			},
		}, operatorv1alpha1.DelegatedAuthentication{Disabled: true}, operatorv1alpha1.DelegatedAuthorization{Disabled: true})

		// override the authorizer
		b.authorizer = nil
		if err := b.Run(ctx, nil); err != nil {
			t.Errorf("failed to run: %v", err)
		}
	}()

	// wait for the server to start
	<-startedCh

	// make poor man HTTP client
	debugClient, err := rest.RESTClientFor(&rest.Config{
		Host:            "127.0.0.1:8888",
		ContentConfig:   rest.ContentConfig{GroupVersion: &schema.GroupVersion{}, NegotiatedSerializer: runtime.NewSimpleNegotiatedSerializer(runtime.SerializerInfo{})},
		TLSClientConfig: rest.TLSClientConfig{Insecure: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	debugBytes, err := debugClient.Get().AbsPath("/debug/pprof/allocs").DoRaw(ctx)
	if err != nil {
		t.Fatalf("failed to query pprof data: %v", err)
	}
	if len(debugBytes) == 0 {
		t.Errorf("allocs should not be empty")
	}

	metricsBytes, err := debugClient.Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		t.Fatalf("failed to query metrics data: %v", err)
	}
	if len(metricsBytes) == 0 {
		t.Errorf("metrics should not be empty")
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

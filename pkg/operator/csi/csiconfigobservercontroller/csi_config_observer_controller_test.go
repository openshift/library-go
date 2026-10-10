package csiconfigobservercontroller

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"

	opv1 "github.com/openshift/api/operator/v1"
	fakeconfig "github.com/openshift/client-go/config/clientset/versioned/fake"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	controllerName            = "TestCSIDriverControllerServiceController"
	operandName               = "test-csi-driver"
	defaultHTTPProxyValue     = "http://foo.bar.proxy"
	alternativeHTTPProxyValue = "http://foo.bar.proxy.alternative"
	noHTTPProxyValue          = ""
)

var (
	defaultServingInfo = map[string]any{
		"servingInfo": map[string]any{
			"cipherSuites": []any{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
				"TLS_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			},
			"minTLSVersion": string("VersionTLS12"),
		},
	}
)

type testCase struct {
	name            string
	initialObjects  testObjects
	expectedObjects testObjects
	expectErr       bool
}

type testObjects struct {
	proxy  *configv1.Proxy
	driver *fakeDriverInstance
}

type testContext struct {
	controller     *CSIConfigObserverController
	operatorClient v1helpers.OperatorClient
}

func newTestContext(test testCase, t *testing.T) *testContext {
	// Add the fake proxy to the informer
	configClient := fakeconfig.NewSimpleClientset(test.initialObjects.proxy)
	configInformerFactory := configinformers.NewSharedInformerFactory(configClient, 0)
	configInformerFactory.Config().V1().Proxies().Informer().GetIndexer().Add(test.initialObjects.proxy)

	// fakeDriverInstance also fulfils the OperatorClient interface
	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&test.initialObjects.driver.Spec,
		&test.initialObjects.driver.Status,
		nil, /*triggerErr func*/
	)

	controller := NewCSIConfigObserverController(
		controllerName,
		fakeOperatorClient,
		configInformerFactory,
		events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now())),
	)

	return &testContext{
		controller:     controller,
		operatorClient: fakeOperatorClient,
	}
}

// Drivers

type driverModifier func(*fakeDriverInstance) *fakeDriverInstance

func makeFakeDriverInstance(modifiers ...driverModifier) *fakeDriverInstance {
	instance := &fakeDriverInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cluster",
			Generation: 0,
		},
		Spec: opv1.OperatorSpec{
			ManagementState: opv1.Managed,
			ObservedConfig: runtime.RawExtension{
				Raw: nil,
				Object: &unstructured.Unstructured{
					Object: map[string]any{"targetcsiconfig": defaultServingInfo},
				},
			},
		},
		Status: opv1.OperatorStatus{},
	}
	for _, modifier := range modifiers {
		instance = modifier(instance)
	}
	return instance
}

func withHTTPProxy(proxy string) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		observedConfigCopy := i.Spec.ObservedConfig.DeepCopy()

		// Copy existing config
		config := observedConfigCopy.Object.(*unstructured.Unstructured).Object

		// Overwrite any proxy configuration that might exist
		unstructured.SetNestedStringMap(config, map[string]string{"HTTP_PROXY": proxy}, ProxyConfigPath()...)

		// Write the new observed config
		i.Spec.ObservedConfig = runtime.RawExtension{Object: &unstructured.Unstructured{Object: config}}
		return i
	}
}

// Proxy

func makeFakeProxyInstance(proxy string) *configv1.Proxy {
	instance := &configv1.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cluster",
			Generation: 0,
		},
		Spec:   configv1.ProxySpec{},
		Status: configv1.ProxyStatus{},
	}
	if proxy != "" {
		instance.Spec = configv1.ProxySpec{HTTPProxy: proxy}
		instance.Status = configv1.ProxyStatus{HTTPProxy: proxy}
	}
	return instance

}

func TestSync(t *testing.T) {
	testCases := []testCase{
		{
			name: "proxy exists: config is observed",
			initialObjects: testObjects{
				proxy:  makeFakeProxyInstance(defaultHTTPProxyValue),
				driver: makeFakeDriverInstance(),
			},
			expectedObjects: testObjects{
				driver: makeFakeDriverInstance(withHTTPProxy(defaultHTTPProxyValue)),
			},
		},
		{
			name: "no proxy: config is observed",
			initialObjects: testObjects{
				proxy:  makeFakeProxyInstance(noHTTPProxyValue),
				driver: makeFakeDriverInstance(),
			},
			expectedObjects: testObjects{
				driver: makeFakeDriverInstance(),
			},
		},
		{
			name: "proxy exists, but observed config is different: new config is observed",
			initialObjects: testObjects{
				proxy:  makeFakeProxyInstance(defaultHTTPProxyValue),
				driver: makeFakeDriverInstance(withHTTPProxy(alternativeHTTPProxyValue)),
			},
			expectedObjects: testObjects{
				driver: makeFakeDriverInstance(withHTTPProxy(defaultHTTPProxyValue)),
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Initialize
			ctx := newTestContext(test, t)

			// Act
			err := ctx.controller.Controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now()))))

			// Assert
			// Check error
			if err != nil && !test.expectErr {
				t.Fatalf("sync() returned unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Fatal("sync() unexpectedly succeeded when error was expected")
			}

			// Check expectedObjects.driver.Spec
			if test.expectedObjects.driver != nil {
				actualSpec, _, _, err := ctx.operatorClient.GetOperatorState()
				if err != nil {
					t.Fatalf("Failed to get Driver: %v", err)
				}

				if !equality.Semantic.DeepEqual(test.expectedObjects.driver.Spec, *actualSpec) {
					t.Fatalf("Unexpected Driver %+v content:\n%s", operandName, cmp.Diff(test.expectedObjects.driver.Spec, *actualSpec))
				}
			}
		})
	}
}

// TestObserveTLSSecurityProfileWithFeatureGates verifies that the
// FeatureGate-aware controller only observes TLS group (curve) preferences when
// the TLSGroupPreferences feature gate is enabled. With no APIServer/cluster
// object the observer falls back to the Intermediate profile, whose baked Groups
// would leak as curvePreferences if gating were missing.
func TestObserveTLSSecurityProfileWithFeatureGates(t *testing.T) {
	notObserved := make(chan struct{}) // never closed => initial gates not observed

	tests := []struct {
		name                   string
		featureGateAccess      featuregates.FeatureGateAccess
		expectCurvePreferences bool
		expectSyncError        bool
	}{
		{
			name: "gate enabled: curvePreferences observed",
			featureGateAccess: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateTLSGroupPreferences}, nil),
			expectCurvePreferences: true,
		},
		{
			name: "gate disabled: curvePreferences not observed",
			featureGateAccess: featuregates.NewHardcodedFeatureGateAccess(
				nil, []configv1.FeatureGateName{features.FeatureGateTLSGroupPreferences}),
			expectCurvePreferences: false,
		},
		{
			name:                   "initial gates not observed: fail hard",
			featureGateAccess:      featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, notObserved, nil),
			expectCurvePreferences: false,
			expectSyncError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := makeFakeProxyInstance(noHTTPProxyValue)
			configClient := fakeconfig.NewSimpleClientset(proxy)
			configInformerFactory := configinformers.NewSharedInformerFactory(configClient, 0)
			configInformerFactory.Config().V1().Proxies().Informer().GetIndexer().Add(proxy)

			driver := makeFakeDriverInstance()
			fakeOperatorClient := v1helpers.NewFakeOperatorClient(&driver.Spec, &driver.Status, nil)

			controller := NewCSIConfigObserverControllerWithFeatureGates(
				controllerName,
				fakeOperatorClient,
				configInformerFactory,
				events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now())),
				tt.featureGateAccess,
			)

			err := controller.Controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now()))))
			if tt.expectSyncError && err == nil {
				t.Fatalf("sync() expected an error, got none")
			}
			if !tt.expectSyncError && err != nil {
				t.Fatalf("sync() returned unexpected error: %v", err)
			}

			actualSpec, _, _, err := fakeOperatorClient.GetOperatorState()
			if err != nil {
				t.Fatalf("Failed to get Driver: %v", err)
			}
			observedConfig := actualSpec.ObservedConfig.Object.(*unstructured.Unstructured).Object

			got, found, err := unstructured.NestedSlice(observedConfig, CurvePreferencesPath()...)
			if err != nil {
				t.Fatalf("failed to read curvePreferences: %v", err)
			}
			if tt.expectCurvePreferences {
				if !found {
					t.Fatalf("expected curvePreferences to be observed, got none; config: %+v", observedConfig)
				}
				if len(got) == 0 {
					t.Fatalf("expected non-empty curvePreferences, got empty")
				}
			} else if found {
				t.Fatalf("expected curvePreferences NOT to be observed, got: %v", got)
			}
		})
	}
}

// fakeInstance is a fake CSI driver instance that also fullfils the OperatorClient interface
type fakeDriverInstance struct {
	metav1.ObjectMeta
	Spec   opv1.OperatorSpec
	Status opv1.OperatorStatus
}

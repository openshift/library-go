package csidrivernodeservicecontroller

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ghodss/yaml"
	"github.com/google/go-cmp/cmp"
	"github.com/openshift/library-go/pkg/operator/csi/csiconfigobservercontroller"
)

const (
	defaultContainerName  = "csi-driver"
	defaultHTTPProxyValue = "http://foo.bar.proxy"
)

func TestWithObservedProxyDaemonSetHook(t *testing.T) {
	const (
		replica0 = 0
		replica1 = 1
		replica2 = 2
	)
	var (
		argsLevel2 = 2
	)
	testCases := []struct {
		name              string
		initialDriver     *fakeDriverInstance
		initialDaemonSet  *appsv1.DaemonSet
		expectedDaemonSet *appsv1.DaemonSet
		expectError       bool
	}{
		{
			name:          "no observed proxy config",
			initialDriver: makeFakeDriverInstance(), // CR has no observed proxy config
			initialDaemonSet: getDaemonSet(
				argsLevel2,
				defaultImages(),
				withDaemonSetHTTPProxyAnnotation(defaultContainerName),
				withDaemonSetGeneration(1, 0)),
			expectedDaemonSet: getDaemonSet( // no container has proxy ENV set
				argsLevel2,
				defaultImages(),
				withDaemonSetHTTPProxyAnnotation(defaultContainerName),
				withDaemonSetGeneration(1, 0)),
			expectError: false,
		},
		{
			name: "observed proxy config, annotation present",
			initialDriver: makeFakeDriverInstance(
				withObservedHTTPProxy(defaultHTTPProxyValue, nil /* config path*/),
			),
			initialDaemonSet: getDaemonSet(
				argsLevel2,
				defaultImages(),
				withDaemonSetHTTPProxyAnnotation(defaultContainerName),
				withDaemonSetGeneration(1, 0)),
			expectedDaemonSet: getDaemonSet(
				argsLevel2,
				defaultImages(),
				withDaemonSetGeneration(1, 0),
				withDaemonSetHTTPProxyAnnotation(defaultContainerName),
				withDaemonSetHTTPProxyEnv(defaultHTTPProxyValue, defaultContainerName)), // proxy ENV was added to container
			expectError: false,
		},
		{
			name: "observed proxy config, annotation present with WRONG container name",
			initialDriver: makeFakeDriverInstance(
				withObservedHTTPProxy(defaultHTTPProxyValue, nil /* config path*/),
			),
			initialDaemonSet: getDaemonSet(
				argsLevel2,
				defaultImages(),
				withDaemonSetHTTPProxyAnnotation("csi-driver-non-existent"), // this container doesn't exist
				withDaemonSetGeneration(1, 0)),
			expectedDaemonSet: getDaemonSet( // no container has proxy ENV is set
				argsLevel2,
				defaultImages(),
				withDaemonSetGeneration(1, 0),
				withDaemonSetHTTPProxyAnnotation("csi-driver-non-existent")),
			expectError: false,
		},
		{
			name: "observed proxy config, annotation NOT present",
			initialDriver: makeFakeDriverInstance(
				withObservedHTTPProxy(defaultHTTPProxyValue, nil /* config path*/),
			),
			initialDaemonSet: getDaemonSet( // inject-proxy annotation not added
				argsLevel2,
				defaultImages(),
				withDaemonSetGeneration(1, 0)),
			expectedDaemonSet: getDaemonSet( // no container has proxy ENV set
				argsLevel2,
				defaultImages(),
				withDaemonSetGeneration(1, 0)),
			expectError: false,
		},
		{
			name: "invalid observed proxy config",
			initialDriver: makeFakeDriverInstance(
				withInvalidObservedHTTPProxy(defaultHTTPProxyValue, nil /* config path*/),
			),
			initialDaemonSet: getDaemonSet(
				argsLevel2,
				defaultImages(),
				withDaemonSetHTTPProxyAnnotation(defaultContainerName),
				withDaemonSetGeneration(1, 0)),
			expectedDaemonSet: getDaemonSet( // no container has proxy ENV set
				argsLevel2,
				defaultImages(),
				withDaemonSetHTTPProxyAnnotation(defaultContainerName),
				withDaemonSetGeneration(1, 0)),
			expectError: true, // report an error
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fn := WithObservedProxyDaemonSetHook()
			err := fn(&tc.initialDriver.Spec, tc.initialDaemonSet)
			if err != nil && !tc.expectError {
				t.Errorf("Expected no error running hook function, got: %v", err)

			}
			if !equality.Semantic.DeepEqual(tc.initialDaemonSet, tc.expectedDaemonSet) {
				t.Errorf("Unexpected DaemonSet content:\n%s", cmp.Diff(tc.initialDaemonSet, tc.expectedDaemonSet))
			}
		})
	}
}

func withObservedHTTPProxy(proxy string, path []string) driverModifier {
	if len(path) == 0 {
		path = csiconfigobservercontroller.ProxyConfigPath()
	}
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		observedConfig := map[string]interface{}{}
		unstructured.SetNestedStringMap(observedConfig, map[string]string{"HTTP_PROXY": proxy}, path...)
		d, _ := yaml.Marshal(observedConfig)
		i.Spec.ObservedConfig = runtime.RawExtension{Raw: d, Object: &unstructured.Unstructured{Object: observedConfig}}
		return i
	}
}

func withInvalidObservedHTTPProxy(proxy string, path []string) driverModifier {
	if len(path) == 0 {
		path = csiconfigobservercontroller.ProxyConfigPath()
	}
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		observedConfig := map[string]interface{}{}
		unstructured.SetNestedStringMap(observedConfig, map[string]string{"HTTP_PROXY": proxy}, path...)
		invalidYAML := []byte("[observedConfig:")
		i.Spec.ObservedConfig = runtime.RawExtension{Raw: invalidYAML, Object: &unstructured.Unstructured{Object: observedConfig}}
		return i
	}
}

func withDaemonSetHTTPProxyAnnotation(containerName string) daemonSetModifier {
	return func(instance *appsv1.DaemonSet) *appsv1.DaemonSet {
		instance.Annotations = map[string]string{"config.openshift.io/inject-proxy": containerName}
		return instance
	}
}

func withDaemonSetHTTPProxyEnv(proxy, containerName string) daemonSetModifier {
	return func(instance *appsv1.DaemonSet) *appsv1.DaemonSet {
		containers := instance.Spec.Template.Spec.Containers
		for i := range containers {
			if containers[i].Name == containerName {
				containers[i].Env = append(containers[i].Env, v1.EnvVar{Name: "HTTP_PROXY", Value: proxy})
			}
		}
		return instance
	}
}

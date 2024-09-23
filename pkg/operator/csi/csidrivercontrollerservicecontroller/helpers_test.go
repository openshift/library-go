package csidrivercontrollerservicecontroller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/google/go-cmp/cmp"
	"sigs.k8s.io/yaml"

	configv1 "github.com/openshift/api/config/v1"
	fakeconfig "github.com/openshift/client-go/config/clientset/versioned/fake"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/operator/csi/csiconfigobservercontroller"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
)

const (
	defaultContainerName  = "csi-driver"
	defaultHTTPProxyValue = "http://foo.bar.proxy"
)

func TestWithObservedProxyDeploymentHook(t *testing.T) {
	const (
		replica0 = 0
		replica1 = 1
		replica2 = 2
	)
	var (
		argsLevel2 = 2
	)
	testCases := []struct {
		name               string
		initialDriver      *fakeDriverInstance
		initialDeployment  *appsv1.Deployment
		expectedDeployment *appsv1.Deployment
		expectError        bool
	}{
		{
			name:          "no observed proxy config",
			initialDriver: makeFakeDriverInstance(), // CR has no observed proxy config
			initialDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentHTTPProxyAnnotation(defaultContainerName),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment( // no container has proxy ENV set
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentHTTPProxyAnnotation(defaultContainerName),
				withDeploymentGeneration(1, 0)),
			expectError: false,
		},
		{
			name: "observed proxy config, annotation present",
			initialDriver: makeFakeDriverInstance(
				withObservedHTTPProxy(defaultHTTPProxyValue, nil /* config path*/),
			),
			initialDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentHTTPProxyAnnotation(defaultContainerName),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentGeneration(1, 0),
				withDeploymentHTTPProxyAnnotation(defaultContainerName),
				withDeploymentHTTPProxyEnv(defaultHTTPProxyValue, defaultContainerName)), // proxy ENV was added to container
			expectError: false,
		},
		{
			name: "observed proxy config, annotation present with WRONG container name",
			initialDriver: makeFakeDriverInstance(
				withObservedHTTPProxy(defaultHTTPProxyValue, nil /* config path*/),
			),
			initialDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentHTTPProxyAnnotation("csi-driver-non-existent"), // this container doesn't exist
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment( // no container has proxy ENV is set
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentGeneration(1, 0),
				withDeploymentHTTPProxyAnnotation("csi-driver-non-existent")),
			expectError: false,
		},
		{
			name: "observed proxy config, annotation NOT present",
			initialDriver: makeFakeDriverInstance(
				withObservedHTTPProxy(defaultHTTPProxyValue, nil /* config path*/),
			),
			initialDeployment: makeDeployment( // inject-proxy annotation not added
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment( // no container has proxy ENV set
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentGeneration(1, 0)),
			expectError: false,
		},
		{
			name: "invalid observed proxy config",
			initialDriver: makeFakeDriverInstance(
				withInvalidObservedHTTPProxy(defaultHTTPProxyValue, nil /* config path*/),
			),
			initialDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentHTTPProxyAnnotation(defaultContainerName),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment( // no container has proxy ENV set
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentHTTPProxyAnnotation(defaultContainerName),
				withDeploymentGeneration(1, 0)),
			expectError: true, // report an error
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fn := WithObservedProxyDeploymentHook()
			err := fn(&tc.initialDriver.Spec, tc.initialDeployment)
			if err != nil && !tc.expectError {
				t.Errorf("Expected no error running hook function, got: %v", err)

			}
			if !equality.Semantic.DeepEqual(tc.initialDeployment, tc.expectedDeployment) {
				t.Errorf("Unexpected Deployment content:\n%s", cmp.Diff(tc.initialDeployment, tc.expectedDeployment))
			}
		})
	}
}

func TestWithReplicasHook(t *testing.T) {
	argsLevel2 := 2
	testCases := []struct {
		name               string
		infra              *configv1.Infrastructure
		initialDeployment  *appsv1.Deployment
		expectedDeployment *appsv1.Deployment
	}{
		{
			name:  "highly available topology",
			infra: makeInfraWithCPTopology(configv1.HighlyAvailableTopologyMode),
			initialDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0),
			),
			expectedDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentReplicas(2),
				withDeploymentGeneration(1, 0),
			),
		},
		{
			name:  "single replica topology",
			infra: makeInfraWithCPTopology(configv1.SingleReplicaTopologyMode),
			initialDeployment: makeDeployment(defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0),
			),
			expectedDeployment: makeDeployment(defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0),
			),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initialInfras := []runtime.Object{tc.infra}
			configClient := fakeconfig.NewSimpleClientset(initialInfras...)
			configInformerFactory := configinformers.NewSharedInformerFactory(configClient, 0)
			configInformerFactory.Config().V1().Infrastructures().Informer().GetIndexer().Add(initialInfras[0])

			fn := WithReplicasHook(configInformerFactory)
			err := fn(nil, tc.initialDeployment)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !equality.Semantic.DeepEqual(tc.initialDeployment, tc.expectedDeployment) {
				t.Errorf("Unexpected Deployment content:\n%s", cmp.Diff(tc.initialDeployment, tc.expectedDeployment))
			}
		})
	}
}

func setEnvVars(image images) {
	os.Setenv(driverImageEnvName, image.csiDriver)
	os.Setenv(provisionerImageEnvName, image.provisioner)
	os.Setenv(attacherImageEnvName, image.attacher)
	os.Setenv(snapshotterImageEnvName, image.snapshotter)
	os.Setenv(resizerImageEnvName, image.resizer)
	os.Setenv(livenessProbeImageEnvName, image.livenessProbe)
	os.Setenv(kubeRBACProxyImageEnvName, image.kubeRBACProxy)
}

func TestManifestHooks(t *testing.T) {
	argsLevel2 := 2
	testCases := []struct {
		name               string
		initialOperator    *fakeDriverInstance
		initialManifest    []byte
		image              images
		infraObjectName    string
		expectedDeployment *appsv1.Deployment
		expectError        bool
	}{
		{
			name:            "replace all images",
			initialOperator: makeFakeDriverInstance(),
			initialManifest: makeFakeManifest(),
			image:           defaultImages(),
			infraObjectName: infraConfigName,
			expectedDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentReplicas(1),
				withDeploymentGeneration(0, 0)),
			expectError: false,
		},
		{
			name:            "replace no images, except for CSI Driver image",
			initialOperator: makeFakeDriverInstance(),
			initialManifest: makeFakeManifest(),
			image:           images{csiDriver: "quay.io/openshift/origin-test-csi-driver:latest"},
			infraObjectName: infraConfigName,
			expectedDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				images{csiDriver: "quay.io/openshift/origin-test-csi-driver:latest"},
				withDeploymentReplicas(1),
				withDeploymentGeneration(0, 0)),
			expectError: false,
		},
		{
			name:            "incorrect infra object, so expect an error",
			initialOperator: makeFakeDriverInstance(),
			initialManifest: makeFakeManifest(),
			image:           defaultImages(),
			infraObjectName: "dummy",
			expectedDeployment: makeDeployment(
				defaultClusterID,
				argsLevel2,
				defaultImages(),
				withDeploymentReplicas(1),
				withDeploymentGeneration(0, 0)),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setEnvVars(tc.image)
			infraObj := makeInfra()
			infraObj.ObjectMeta.Name = tc.infraObjectName
			initialInfras := []runtime.Object{infraObj}
			configClient := fakeconfig.NewSimpleClientset(initialInfras...)
			configInformerFactory := configinformers.NewSharedInformerFactory(configClient, 0)
			configInformerFactory.Config().V1().Infrastructures().Informer().GetIndexer().Add(initialInfras[0])

			fn := WithPlaceholdersHook(configInformerFactory)
			manifest, err := fn(&tc.initialOperator.Spec, tc.initialManifest)
			if err != nil && !tc.expectError {
				t.Errorf("Expected no error running hook function, got: %v", err)
			}
			if len(manifest) > 0 && !equality.Semantic.DeepEqual(resourceread.ReadDeploymentV1OrDie(manifest), tc.expectedDeployment) {
				t.Errorf("Unexpected Deployment content:\n%s", cmp.Diff(resourceread.ReadDeploymentV1OrDie(manifest), tc.expectedDeployment))
			}
		})
	}
}

func TestWithControlPlaneTopologyHook(t *testing.T) {
	argsLevel2 := 2
	tests := []struct {
		name               string
		infra              *configv1.Infrastructure
		initialDeployment  *appsv1.Deployment
		expectedDeployment *appsv1.Deployment
	}{
		{
			name:               "highly available topology",
			infra:              makeInfraWithCPTopology(configv1.HighlyAvailableTopologyMode),
			initialDeployment:  makeDeployment(defaultClusterID, argsLevel2, defaultImages()),
			expectedDeployment: makeDeployment(defaultClusterID, argsLevel2, defaultImages()),
		},
		{
			name:               "external topology",
			infra:              makeInfraWithCPTopology(configv1.ExternalTopologyMode),
			initialDeployment:  makeDeployment(defaultClusterID, argsLevel2, defaultImages()),
			expectedDeployment: makeDeployment(defaultClusterID, argsLevel2, defaultImages(), withNodeSelector(map[string]string{})),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initialInfras := []runtime.Object{test.infra}
			configClient := fakeconfig.NewSimpleClientset(initialInfras...)
			configInformerFactory := configinformers.NewSharedInformerFactory(configClient, 0)
			configInformerFactory.Config().V1().Infrastructures().Informer().GetIndexer().Add(initialInfras[0])

			fn := WithControlPlaneTopologyHook(configInformerFactory)
			err := fn(nil, test.initialDeployment)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !equality.Semantic.DeepEqual(test.initialDeployment, test.expectedDeployment) {
				t.Errorf("Unexpected Deployment content:\n%s", cmp.Diff(test.initialDeployment, test.expectedDeployment))
			}
		})
	}
}

func withNodeSelector(nodeSelector map[string]string) deploymentModifier {
	return func(deployment *appsv1.Deployment) *appsv1.Deployment {
		deployment.Spec.Template.Spec.NodeSelector = nodeSelector
		return deployment
	}
}

func makeInfraWithCPTopology(mode configv1.TopologyMode) *configv1.Infrastructure {
	infra := makeInfra()
	infra.Status.ControlPlaneTopology = mode
	return infra
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

func withObservedServingInfo(ciphers []string, version string) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		observedConfig := map[string]interface{}{}
		if len(ciphers) > 0 {
			unstructured.SetNestedStringSlice(observedConfig, ciphers, csiconfigobservercontroller.CipherSuitesPath()...)
		}
		// The observer may return an empty string for MinTLSVersion.
		unstructured.SetNestedField(observedConfig, version, csiconfigobservercontroller.MinTLSVersionPath()...)
		d, _ := json.Marshal(observedConfig)
		i.Spec.ObservedConfig = runtime.RawExtension{Raw: d, Object: &unstructured.Unstructured{Object: observedConfig}}
		return i
	}
}

func withDeploymentHTTPProxyAnnotation(containerName string) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		instance.Annotations = map[string]string{"config.openshift.io/inject-proxy": containerName}
		return instance
	}
}

func withDeploymentHTTPProxyEnv(proxy, containerName string) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		containers := instance.Spec.Template.Spec.Containers
		for i := range containers {
			if containers[i].Name == containerName {
				containers[i].Env = append(containers[i].Env, v1.EnvVar{Name: "HTTP_PROXY", Value: proxy})
			}
		}
		return instance
	}
}

func makeNode(suffix string, labels map[string]string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("node-%s", suffix),
			Labels: labels,
		},
	}
}

func TestWithLeaderElectionReplacerHook(t *testing.T) {
	in := `
            - --leader-election-lease-duration=${LEADER_ELECTION_LEASE_DURATION}
            - --leader-election-renew-deadline=${LEADER_ELECTION_RENEW_DEADLINE}
            - --leader-election-retry-period=${LEADER_ELECTION_RETRY_PERIOD}
`
	expected := `
            - --leader-election-lease-duration=1s
            - --leader-election-renew-deadline=2s
            - --leader-election-retry-period=3s
`
	le := configv1.LeaderElection{
		LeaseDuration: metav1.Duration{Duration: time.Second},
		RenewDeadline: metav1.Duration{Duration: 2 * time.Second},
		RetryPeriod:   metav1.Duration{Duration: 3 * time.Second},
	}
	hook := WithLeaderElectionReplacerHook(le)
	out, err := hook(nil, []byte(in))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if string(out) != expected {
		t.Errorf("expected %q, got %q", expected, string(out))
	}
}

func makeServingInfoManifest(ciphers string, version string) []byte {
	manifest := `
           - --tls-cipher-suites=${TLS_CIPHER_SUITES}
           - --tls-min-version=${TLS_MIN_VERSION}
`
	if ciphers != "" {
		manifest = strings.ReplaceAll(manifest, "${TLS_CIPHER_SUITES}", ciphers)
	}
	if version != "" {
		manifest = strings.ReplaceAll(manifest, "${TLS_MIN_VERSION}", version)
	}
	return []byte(manifest)
}

func TestWithServingInfoHook(t *testing.T) {
	testCases := []struct {
		name             string
		initialDriver    *fakeDriverInstance
		initialManifest  []byte
		expectedManifest []byte
		expectedError    bool
	}{
		{
			name:             "no observed serving info",
			initialDriver:    makeFakeDriverInstance(),
			initialManifest:  makeServingInfoManifest("" /*ciphers*/, "" /*version*/),
			expectedManifest: makeServingInfoManifest("" /*ciphers*/, "" /*version*/),
		},
		{
			name:             "observed serving info, manifest patched",
			initialDriver:    makeFakeDriverInstance(withObservedServingInfo([]string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, "VersionTLS12")),
			initialManifest:  makeServingInfoManifest("" /*ciphers*/, "" /*version*/),
			expectedManifest: makeServingInfoManifest("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "VersionTLS12"),
		},
		{
			name:             "observed ciphers only, default version is used",
			initialDriver:    makeFakeDriverInstance(withObservedServingInfo([]string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, "")),
			initialManifest:  makeServingInfoManifest("" /*ciphers*/, "" /*version*/),
			expectedManifest: makeServingInfoManifest("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", defaultMinTLSVersion),
		},
		{
			name:             "observed version only, error is returned",
			initialDriver:    makeFakeDriverInstance(withObservedServingInfo(nil, "VersionTLS12")),
			initialManifest:  makeServingInfoManifest("" /*ciphers*/, "" /*version*/),
			expectedManifest: nil,
			expectedError:    true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hook := WithServingInfo()
			out, err := hook(&tc.initialDriver.Spec, tc.initialManifest)
			if err != nil {
				if !tc.expectedError {
					t.Errorf("unexpected error: %s", err)
				} else {
					return // Success
				}
			}
			if !bytes.Equal(out, tc.expectedManifest) {
				t.Errorf("expected %q, got %q", string(tc.expectedManifest), string(out))
			}

		})
	}
}

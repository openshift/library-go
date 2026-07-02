package preflight

import (
	"context"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
)

const (
	testNamespace           = "openshift-kube-apiserver"
	testConfigHash          = "abc123"
	testOperatorImage       = "quay.io/openshift-release-dev/ocp-v5.0-art-dev@sha256:test"
	configHashAnnotationKey = "encryption.apiserver.operator.openshift.io/kms-preflight-config-hash"
	testDeployerTimeout     = 10 * time.Second
	testReferenceDataNS     = "openshift-config"
)

var testOperatorCommand = []string{"cluster-kube-apiserver-operator", "kms-preflight"}

var expectedDeployPodYAML = `
apiVersion: v1
kind: Pod
metadata:
  name: kms-preflight
  namespace: openshift-kube-apiserver
  labels:
    app: openshift-kms-preflight
  annotations:
    encryption.apiserver.operator.openshift.io/kms-preflight-config-hash: abc123
spec:
  restartPolicy: Never
  serviceAccountName: kms-preflight
  priorityClassName: system-cluster-critical
  nodeSelector:
    node-role.kubernetes.io/master: ""
  tolerations:
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoSchedule
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoExecute
  initContainers:
    - name: vault-kms-plugin-1
      image: registry.example.com/kms-plugin@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
      args:
        - -listen-address=unix:///var/run/kmsplugin/kms.sock
        - -vault-address=https://vault.example.com
        - -transit-mount=
        - -transit-key=test-transit-key
        - -approle-role-id=test-role-id
        - -approle-secret-id-path=/var/run/secrets/kms-plugin/kms-plugin-secret-vault-approle-secret_secret-id-1
        - -tls-ca-file=/var/run/secrets/kms-plugin/kms-plugin-configmap-vault-ca-bundle_ca-bundle.crt-1
        - -metrics-port=0
      imagePullPolicy: IfNotPresent
      restartPolicy: Always
      terminationMessagePolicy: FallbackToLogsOnError
      resources:
        requests:
          memory: 64Mi
          cpu: 10m
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
        readOnlyRootFilesystem: true
        seccompProfile:
          type: RuntimeDefault
      volumeMounts:
        - name: kms-plugin-socket
          mountPath: /var/run/kmsplugin
        - name: kms-plugins-data
          mountPath: /var/run/secrets/kms-plugin
          readOnly: true
  containers:
    - name: kms-preflight-check
      image: quay.io/openshift-release-dev/ocp-v5.0-art-dev@sha256:test
      command: ["cluster-kube-apiserver-operator","kms-preflight"]
      args:
        - --kms-call-timeout=10s
        - --config-hash=$(CONFIG_HASH)
        - --pod-name=$(POD_NAME)
        - --pod-namespace=$(POD_NAMESPACE)
      env:
      - name: POD_NAME
        valueFrom:
          fieldRef:
            fieldPath: metadata.name
      - name: POD_NAMESPACE
        valueFrom:
          fieldRef:
            fieldPath: metadata.namespace
      - name: CONFIG_HASH
        value: abc123
      resources:
        requests:
          memory: 50Mi
          cpu: 5m
      volumeMounts:
        - name: kms-plugin-socket
          mountPath: /var/run/kmsplugin
  volumes:
    - name: kms-plugin-socket
      emptyDir: {}
    - name: kms-plugins-data
      secret:
        secretName: kms-preflight-encryption-config
`

func testReferenceDataObjects(t *testing.T) []runtime.Object {
	t.Helper()

	return []runtime.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vault-approle-secret",
				Namespace: testReferenceDataNS,
			},
			Data: map[string][]byte{
				"role-id":   []byte("test-role-id"),
				"secret-id": []byte("test-secret-id"),
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vault-ca-bundle",
				Namespace: testReferenceDataNS,
			},
			Data: map[string]string{
				"ca-bundle.crt": "test-ca-cert",
			},
		},
	}
}

func testPreflightEncryptionConfigSecret(t *testing.T) *corev1.Secret {
	t.Helper()

	var secretData encryptiondata.KMSPluginsReferenceData
	if err := secretData.SetFromRawKey("1", "vault-approle-secret_role-id", []byte("test-role-id")); err != nil {
		t.Fatalf("failed to set secret reference data: %v", err)
	}
	if err := secretData.SetFromRawKey("1", "vault-approle-secret_secret-id", []byte("test-secret-id")); err != nil {
		t.Fatalf("failed to set secret reference data: %v", err)
	}

	var configMapData encryptiondata.KMSPluginsReferenceData
	if err := configMapData.SetFromRawKey("1", "vault-ca-bundle_ca-bundle.crt", []byte("test-ca-cert")); err != nil {
		t.Fatalf("failed to set configmap reference data: %v", err)
	}

	config := testPreflightEncryptionConfigFromData(t, secretData, configMapData)
	secret, err := encryptiondata.ToSecret(testNamespace, preflightEncryptionConfigSecretName, config)
	if err != nil {
		t.Fatalf("failed to build encryption config secret: %v", err)
	}
	return secret
}

func testPreflightEncryptionConfigFromData(
	t *testing.T,
	secretData encryptiondata.KMSPluginsReferenceData,
	configMapData encryptiondata.KMSPluginsReferenceData,
) *encryptiondata.Config {
	t.Helper()

	return &encryptiondata.Config{
		Encryption: &apiserverconfigv1.EncryptionConfiguration{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EncryptionConfiguration",
				APIVersion: "apiserver.config.k8s.io/v1",
			},
			Resources: []apiserverconfigv1.ResourceConfiguration{{
				Resources: []string{"secrets"},
				Providers: []apiserverconfigv1.ProviderConfiguration{{
					KMS: &apiserverconfigv1.KMSConfiguration{
						APIVersion: "v2",
						Name:       "1_secrets",
						Endpoint:   kmsSocketEndpoint,
						Timeout:    &metav1.Duration{Duration: testDeployerTimeout},
					},
				}, {
					Identity: &apiserverconfigv1.IdentityConfiguration{},
				}},
			}},
		},
		KMSPlugins: map[string]configv1.KMSPluginConfig{
			"1": encryptiontesting.DefaultKMSPluginConfig,
		},
		KMSPluginsSecretData:    secretData,
		KMSPluginsConfigMapData: configMapData,
	}
}

func newTestDeployer(t *testing.T, objects ...runtime.Object) (*PodPreflightDeployer, *fake.Clientset) {
	t.Helper()

	allObjects := append(testReferenceDataObjects(t), objects...)
	kubeClient := fake.NewSimpleClientset(allObjects...)
	deployer := NewPodPreflightDeployer(
		testNamespace,
		kubeClient.CoreV1(),
		kubeClient.RbacV1(),
		events.NewInMemoryRecorder("kms-preflight-deployer-test", clock.RealClock{}),
		testOperatorImage,
		testOperatorCommand,
		testDeployerTimeout,
	)
	return deployer, kubeClient
}

func assertNoActionMatching(t *testing.T, actions []clienttesting.Action, verb, resource string) {
	t.Helper()

	for _, action := range actions {
		if action.Matches(verb, resource) {
			t.Fatalf("unexpected %s %s action: %#v", verb, resource, action)
		}
	}
}

func TestPodPreflightDeployer_Deploy(t *testing.T) {
	ctx := context.Background()
	deployer, kubeClient := newTestDeployer(t)
	encryptionConfigSecret := testPreflightEncryptionConfigSecret(t)

	expectedPod, err := resourceread.ReadPodV1([]byte(expectedDeployPodYAML))
	if err != nil {
		t.Fatalf("failed to parse expected pod YAML: %v", err)
	}

	if err := deployer.Deploy(ctx, testConfigHash, encryptionConfigSecret); err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	actions := kubeClient.Actions()
	if len(actions) != 11 {
		t.Fatalf("expected 11 actions, got %d: %#v", len(actions), actions)
	}
	if !actions[0].Matches("delete", "pods") {
		t.Fatalf("unexpected action: %#v", actions[0])
	}
	if !actions[1].Matches("delete", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[1])
	}
	if !actions[2].Matches("create", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[2])
	}
	secretCreateAction, ok := actions[2].(clienttesting.CreateAction)
	if !ok {
		t.Fatalf("expected CreateAction, got %T", actions[2])
	}
	createdSecret, ok := secretCreateAction.GetObject().(*corev1.Secret)
	if !ok {
		t.Fatalf("expected *corev1.Secret, got %T", secretCreateAction.GetObject())
	}
	if len(createdSecret.Finalizers) != 0 {
		t.Fatalf("expected finalizers to be stripped before create, got %v", createdSecret.Finalizers)
	}
	if !actions[3].Matches("get", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[3])
	}
	if !actions[4].Matches("get", "serviceaccounts") {
		t.Fatalf("unexpected action: %#v", actions[4])
	}
	if !actions[5].Matches("create", "serviceaccounts") {
		t.Fatalf("unexpected action: %#v", actions[5])
	}
	if !actions[6].Matches("get", "roles") {
		t.Fatalf("unexpected action: %#v", actions[6])
	}
	if !actions[7].Matches("create", "roles") {
		t.Fatalf("unexpected action: %#v", actions[7])
	}
	if !actions[8].Matches("get", "rolebindings") {
		t.Fatalf("unexpected action: %#v", actions[8])
	}
	if !actions[9].Matches("create", "rolebindings") {
		t.Fatalf("unexpected action: %#v", actions[9])
	}
	if !actions[10].Matches("create", "pods") {
		t.Fatalf("unexpected action: %#v", actions[10])
	}
	createAction, ok := actions[10].(clienttesting.CreateAction)
	if !ok {
		t.Fatalf("expected CreateAction, got %T", actions[4])
	}
	if createAction.GetNamespace() != testNamespace {
		t.Fatalf("unexpected namespace %q", createAction.GetNamespace())
	}

	actualPod, ok := createAction.GetObject().(*corev1.Pod)
	if !ok {
		t.Fatalf("expected *corev1.Pod, got %T", createAction.GetObject())
	}
	if !equality.Semantic.DeepEqual(expectedPod, actualPod) {
		t.Fatalf("pod does not match expected:\ngot:  %+v\nwant: %+v", actualPod, expectedPod)
	}
}

func TestPodPreflightDeployer_Deploy_emptyConfigHash(t *testing.T) {
	deployer, kubeClient := newTestDeployer(t)

	err := deployer.Deploy(context.Background(), "", testPreflightEncryptionConfigSecret(t))
	if err == nil || !strings.Contains(err.Error(), "configHash is empty") {
		t.Fatalf("expected configHash is empty error, got %v", err)
	}
	if len(kubeClient.Actions()) != 0 {
		t.Fatalf("expected no client actions, got %d: %#v", len(kubeClient.Actions()), kubeClient.Actions())
	}
}

func TestPodPreflightDeployer_Deploy_nilEncryptionConfigSecret(t *testing.T) {
	deployer, kubeClient := newTestDeployer(t)

	err := deployer.Deploy(context.Background(), testConfigHash, nil)
	if err == nil || !strings.Contains(err.Error(), "encryptionConfigSecret is nil") {
		t.Fatalf("expected encryptionConfigSecret is nil error, got %v", err)
	}
	if len(kubeClient.Actions()) != 0 {
		t.Fatalf("expected no client actions, got %d: %#v", len(kubeClient.Actions()), kubeClient.Actions())
	}
}

// Verifies that a forbidden secret create returns a wrapped error after cleanup,
// performs only cleanup + failed create (no secret get or pod create).
func TestPodPreflightDeployer_Deploy_secretCreateFailure(t *testing.T) {
	deployer, kubeClient := newTestDeployer(t)
	kubeClient.PrependReactor("create", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(corev1.Resource("secrets"), preflightEncryptionConfigSecretName, nil)
	})

	err := deployer.Deploy(context.Background(), testConfigHash, testPreflightEncryptionConfigSecret(t))
	if err == nil || !strings.Contains(err.Error(), "failed to create preflight encryption config secret") {
		t.Fatalf("expected secret create error, got %v", err)
	}

	actions := kubeClient.Actions()
	if len(actions) != 3 {
		t.Fatalf("expected 3 actions, got %d: %#v", len(actions), actions)
	}
	if !actions[0].Matches("delete", "pods") {
		t.Fatalf("unexpected action: %#v", actions[0])
	}
	if !actions[1].Matches("delete", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[1])
	}
	if !actions[2].Matches("create", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[2])
	}
	assertNoActionMatching(t, actions, "create", "pods")
	assertNoActionMatching(t, actions, "get", "secrets")
}

// Verifies that plugin sidecar injection failure returns a wrapped error, leaves
// the encryption config secret behind, and does not create a pod.
func TestPodPreflightDeployer_Deploy_pluginApplyFailure(t *testing.T) {
	deployer, kubeClient := newTestDeployer(t)

	config := testPreflightEncryptionConfigFromData(
		t,
		encryptiondata.KMSPluginsReferenceData{},
		encryptiondata.KMSPluginsReferenceData{},
	)
	secret, err := encryptiondata.ToSecret(testNamespace, "proposed-encryption-config", config)
	if err != nil {
		t.Fatalf("failed to build encryption config secret: %v", err)
	}

	err = deployer.Deploy(context.Background(), testConfigHash, secret)
	if err == nil || !strings.Contains(err.Error(), "failed to apply preflight plugin") {
		t.Fatalf("expected plugin apply error, got %v", err)
	}

	actions := kubeClient.Actions()
	if len(actions) != 4 {
		t.Fatalf("expected 4 actions, got %d: %#v", len(actions), actions)
	}
	if !actions[0].Matches("delete", "pods") {
		t.Fatalf("unexpected action: %#v", actions[0])
	}
	if !actions[1].Matches("delete", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[1])
	}
	if !actions[2].Matches("create", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[2])
	}
	if !actions[3].Matches("get", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[3])
	}
	assertNoActionMatching(t, actions, "create", "pods")
}

// Verifies that a forbidden pod create returns a wrapped error with the secret
// already created and no preflight pod present (partial deploy state).
func TestPodPreflightDeployer_Deploy_podCreateFailure(t *testing.T) {
	deployer, kubeClient := newTestDeployer(t)
	kubeClient.PrependReactor("create", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(corev1.Resource("pods"), preflightPodName, nil)
	})

	err := deployer.Deploy(context.Background(), testConfigHash, testPreflightEncryptionConfigSecret(t))
	if err == nil || !strings.Contains(err.Error(), "failed to create preflight pod") {
		t.Fatalf("expected pod create error, got %v", err)
	}

	actions := kubeClient.Actions()
	if len(actions) != 11 {
		t.Fatalf("expected 11 actions, got %d: %#v", len(actions), actions)
	}
	if !actions[0].Matches("delete", "pods") {
		t.Fatalf("unexpected action: %#v", actions[0])
	}
	if !actions[1].Matches("delete", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[1])
	}
	if !actions[2].Matches("create", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[2])
	}
	if !actions[3].Matches("get", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[3])
	}
	if !actions[4].Matches("get", "serviceaccounts") {
		t.Fatalf("unexpected action: %#v", actions[4])
	}
	if !actions[5].Matches("create", "serviceaccounts") {
		t.Fatalf("unexpected action: %#v", actions[5])
	}
	if !actions[6].Matches("get", "roles") {
		t.Fatalf("unexpected action: %#v", actions[6])
	}
	if !actions[7].Matches("create", "roles") {
		t.Fatalf("unexpected action: %#v", actions[7])
	}
	if !actions[8].Matches("get", "rolebindings") {
		t.Fatalf("unexpected action: %#v", actions[8])
	}
	if !actions[9].Matches("create", "rolebindings") {
		t.Fatalf("unexpected action: %#v", actions[9])
	}
	if !actions[10].Matches("create", "pods") {
		t.Fatalf("unexpected action: %#v", actions[10])
	}
}

// Verifies that initial cleanup failure aborts Deploy early with a wrapped error
// and performs no secret or pod creates.
func TestPodPreflightDeployer_Deploy_cleanupFailure(t *testing.T) {
	existingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightPodName,
			Namespace: testNamespace,
		},
	}
	deployer, kubeClient := newTestDeployer(t, existingPod)
	kubeClient.PrependReactor("delete", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(corev1.Resource("pods"), preflightPodName, nil)
	})

	err := deployer.Deploy(context.Background(), testConfigHash, testPreflightEncryptionConfigSecret(t))
	if err == nil || !strings.Contains(err.Error(), "failed to clean up existing preflight resources") {
		t.Fatalf("expected cleanup error, got %v", err)
	}

	actions := kubeClient.Actions()
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d: %#v", len(actions), actions)
	}
	if !actions[0].Matches("delete", "pods") {
		t.Fatalf("unexpected action: %#v", actions[0])
	}
	if !actions[1].Matches("delete", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[1])
	}
	assertNoActionMatching(t, actions, "create", "secrets")
	assertNoActionMatching(t, actions, "create", "pods")
}

func TestPodPreflightDeployer_Deploy_deletesStaleResources(t *testing.T) {
	ctx := context.Background()
	stalePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightPodName,
			Namespace: testNamespace,
		},
	}
	staleSecret := testPreflightEncryptionConfigSecret(t)
	staleSecret.Data = map[string][]byte{"stale": []byte("data")}
	deployer, kubeClient := newTestDeployer(t, stalePod, staleSecret)

	err := deployer.Deploy(ctx, testConfigHash, testPreflightEncryptionConfigSecret(t))
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	actions := kubeClient.Actions()
	if len(actions) != 11 {
		t.Fatalf("expected 11 actions, got %d: %#v", len(actions), actions)
	}
	if !actions[0].Matches("delete", "pods") {
		t.Fatalf("unexpected action: %#v", actions[0])
	}
	if !actions[1].Matches("delete", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[1])
	}
	if !actions[2].Matches("create", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[2])
	}
	if !actions[3].Matches("get", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[3])
	}
	if !actions[4].Matches("get", "serviceaccounts") {
		t.Fatalf("unexpected action: %#v", actions[4])
	}
	if !actions[5].Matches("create", "serviceaccounts") {
		t.Fatalf("unexpected action: %#v", actions[5])
	}
	if !actions[6].Matches("get", "roles") {
		t.Fatalf("unexpected action: %#v", actions[6])
	}
	if !actions[7].Matches("create", "roles") {
		t.Fatalf("unexpected action: %#v", actions[7])
	}
	if !actions[8].Matches("get", "rolebindings") {
		t.Fatalf("unexpected action: %#v", actions[8])
	}
	if !actions[9].Matches("create", "rolebindings") {
		t.Fatalf("unexpected action: %#v", actions[9])
	}
	if !actions[10].Matches("create", "pods") {
		t.Fatalf("unexpected action: %#v", actions[10])
	}
}

func TestPodPreflightDeployer_Status(t *testing.T) {
	scenarios := []struct {
		name        string
		objects     []runtime.Object
		expectPhase corev1.PodPhase
		expectErr   string
	}{
		{
			name:      "missing pod returns error",
			expectErr: "failed to get pod",
		},
		{
			name: "pod returns pod status",
			objects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      preflightPodName,
						Namespace: testNamespace,
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			expectPhase: corev1.PodRunning,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			deployer, _ := newTestDeployer(t, scenario.objects...)

			status, err := deployer.Status(context.Background())
			if scenario.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), scenario.expectErr) {
					t.Fatalf("expected error containing %q, got %v", scenario.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Status() error = %v", err)
			}
			if status.Phase != scenario.expectPhase {
				t.Fatalf("expected phase %q, got %q", scenario.expectPhase, status.Phase)
			}
		})
	}
}

func TestPodPreflightDeployer_Cleanup(t *testing.T) {
	existingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightPodName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				configHashAnnotationKey: testConfigHash,
			},
		},
	}
	existingSecret := testPreflightEncryptionConfigSecret(t)

	scenarios := []struct {
		name              string
		objects           []runtime.Object
		setupClient       func(*fake.Clientset)
		expectErr         string
		expectErrContains []string
		verifyActions     func(t *testing.T, actions []clienttesting.Action)
	}{
		{
			name:    "deletes existing pod and secret",
			objects: []runtime.Object{existingPod, existingSecret},
			verifyActions: func(t *testing.T, actions []clienttesting.Action) {
				if len(actions) != 2 {
					t.Fatalf("expected 2 actions, got %d: %#v", len(actions), actions)
				}
				if !actions[0].Matches("delete", "pods") {
					t.Fatalf("unexpected action: %#v", actions[0])
				}
				deleteAction, ok := actions[0].(clienttesting.DeleteAction)
				if !ok {
					t.Fatalf("expected DeleteAction, got %T", actions[0])
				}
				if deleteAction.GetName() != preflightPodName {
					t.Fatalf("unexpected pod name %q", deleteAction.GetName())
				}
				if deleteAction.GetNamespace() != testNamespace {
					t.Fatalf("unexpected namespace %q", deleteAction.GetNamespace())
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Fatalf("unexpected action: %#v", actions[1])
				}
			},
		},
		{
			name: "missing resources is not an error",
			verifyActions: func(t *testing.T, actions []clienttesting.Action) {
				if len(actions) != 2 {
					t.Fatalf("expected 2 actions, got %d: %#v", len(actions), actions)
				}
				if !actions[0].Matches("delete", "pods") {
					t.Fatalf("unexpected action: %#v", actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Fatalf("unexpected action: %#v", actions[1])
				}
			},
		},
		{
			name:    "delete pod error is returned",
			objects: []runtime.Object{existingPod},
			setupClient: func(kubeClient *fake.Clientset) {
				kubeClient.PrependReactor("delete", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(corev1.Resource("pods"), preflightPodName, nil)
				})
			},
			expectErr: "failed to delete pod",
			verifyActions: func(t *testing.T, actions []clienttesting.Action) {
				if len(actions) != 2 {
					t.Fatalf("expected 2 actions, got %d: %#v", len(actions), actions)
				}
				if !actions[0].Matches("delete", "pods") {
					t.Fatalf("unexpected action: %#v", actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Fatalf("unexpected action: %#v", actions[1])
				}
			},
		},
		{
			name:    "delete secret error is returned",
			objects: []runtime.Object{existingSecret},
			setupClient: func(kubeClient *fake.Clientset) {
				kubeClient.PrependReactor("delete", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(corev1.Resource("secrets"), preflightEncryptionConfigSecretName, nil)
				})
			},
			expectErr: "failed to delete secret",
			verifyActions: func(t *testing.T, actions []clienttesting.Action) {
				if len(actions) != 2 {
					t.Fatalf("expected 2 actions, got %d: %#v", len(actions), actions)
				}
				if !actions[0].Matches("delete", "pods") {
					t.Fatalf("unexpected action: %#v", actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Fatalf("unexpected action: %#v", actions[1])
				}
			},
		},
		// Verifies that when both pod and secret delete fail, Cleanup returns an
		// error containing messages for both failures.
		{
			name:    "both delete errors are returned",
			objects: []runtime.Object{existingPod, existingSecret},
			setupClient: func(kubeClient *fake.Clientset) {
				kubeClient.PrependReactor("delete", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(corev1.Resource("pods"), preflightPodName, nil)
				})
				kubeClient.PrependReactor("delete", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(corev1.Resource("secrets"), preflightEncryptionConfigSecretName, nil)
				})
			},
			expectErrContains: []string{"failed to delete pod", "failed to delete secret"},
			verifyActions: func(t *testing.T, actions []clienttesting.Action) {
				if len(actions) != 2 {
					t.Fatalf("expected 2 actions, got %d: %#v", len(actions), actions)
				}
				if !actions[0].Matches("delete", "pods") {
					t.Fatalf("unexpected action: %#v", actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Fatalf("unexpected action: %#v", actions[1])
				}
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			deployer, kubeClient := newTestDeployer(t, scenario.objects...)
			if scenario.setupClient != nil {
				scenario.setupClient(kubeClient)
			}

			err := deployer.Cleanup(context.Background())
			if len(scenario.expectErrContains) > 0 {
				if err == nil {
					t.Fatalf("expected cleanup error, got nil")
				}
				for _, fragment := range scenario.expectErrContains {
					if !strings.Contains(err.Error(), fragment) {
						t.Fatalf("expected error containing %q, got %v", fragment, err)
					}
				}
			} else if scenario.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), scenario.expectErr) {
					t.Fatalf("expected error containing %q, got %v", scenario.expectErr, err)
				}
				return
			} else if err != nil {
				t.Fatalf("Cleanup() error = %v", err)
			}
			if scenario.verifyActions != nil {
				scenario.verifyActions(t, kubeClient.Actions())
			}
		})
	}
}

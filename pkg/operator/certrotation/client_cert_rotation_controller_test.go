package certrotation

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
)

// TestCertRotationController_SyncWorker tests the SyncWorker method
func TestCertRotationController_SyncWorker(t *testing.T) {
	// Create signer certificate
	signer, err := crypto.MakeSelfSignedCAConfig("test-ca", time.Hour*24)
	if err != nil {
		panic(fmt.Sprintf("failed to create test CA: %v", err))
	}
	// Create CA bundle
	ca := &crypto.CA{
		Config:          signer,
		SerialGenerator: &crypto.RandomSerialGenerator{},
	}
	// Create target certificate signed by the CA
	targetCert, err := ca.MakeServerCert(sets.New("test.example.com", "localhost"), time.Hour*12)
	if err != nil {
		panic(fmt.Sprintf("failed to create server cert: %v", err))
	}

	tests := []struct {
		name            string
		existingObjects []runtime.Object
		setupReactors   func(*fake.Clientset)
		expectedError   string
		validateActions func(*testing.T, []clienttesting.Action)
	}{
		{
			name:            "successful sync with no existing resources - creates all",
			existingObjects: []runtime.Object{},
			validateActions: func(t *testing.T, actions []clienttesting.Action) {
				if len(actions) != 3 {
					t.Errorf("expected exactly 3 actions, got %d", len(actions))
				}
				firstAction := actions[0]
				if firstAction.GetVerb() != "create" || firstAction.GetResource().Resource != "secrets" {
					t.Errorf("unexpected first action: %v", firstAction)
				}
				firstActionSecret := firstAction.(clienttesting.CreateAction).GetObject().(*corev1.Secret)
				if firstActionSecret.GetName() != "test-signer-cert" {
					t.Errorf("unexpected first action object: %v", firstActionSecret)
				}

				secondAction := actions[1]
				if secondAction.GetVerb() != "create" || secondAction.GetResource().Resource != "configmaps" {
					t.Errorf("unexpected second action: %v", secondAction)
				}
				secondActionConfigMap := secondAction.(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
				if secondActionConfigMap.GetName() != "test-ca-bundle" {
					t.Errorf("unexpected second action object: %v", secondActionConfigMap)
				}

				thirdAction := actions[2]
				if thirdAction.GetVerb() != "create" || thirdAction.GetResource().Resource != "secrets" {
					t.Errorf("unexpected third action: %v", thirdAction)
				}
				thirdActionSecret := thirdAction.(clienttesting.CreateAction).GetObject().(*corev1.Secret)
				if thirdActionSecret.GetName() != "test-target-cert" {
					t.Errorf("unexpected third action object: %v", thirdActionSecret)
				}
			},
		},
		{
			name: "existing valid resources - no updates needed",
			existingObjects: []runtime.Object{
				createValidSigningCASecret("test-namespace", "test-signer-cert", signer),
				createValidCABundleConfigMap("test-namespace", "test-ca-bundle", signer),
				createValidTargetCertSecret("test-namespace", "test-target-cert", targetCert),
			},
			validateActions: func(t *testing.T, actions []clienttesting.Action) {
				for _, action := range actions {
					if action.GetVerb() == "create" {
						t.Errorf("unexpected create action: %v", action)
					}
					if action.GetVerb() == "update" {
						t.Errorf("unexpected update action: %v", action)
					}
				}
			},
		},
		{
			name: "error creating target cert secret",
			setupReactors: func(client *fake.Clientset) {
				client.PrependReactor("create", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					createAction := action.(clienttesting.CreateAction)
					if secret, ok := createAction.GetObject().(*corev1.Secret); ok && secret.Name == "test-signer-cert" {
						return true, nil, apierrors.NewBadRequest("nope")
					}
					return false, nil, nil
				})
			},
			validateActions: func(t *testing.T, actions []clienttesting.Action) {
				// Make sure we don't create target cert or ca bundle
				if len(actions) != 1 {
					t.Errorf("expected one action, got %v", len(actions))
				}
				action := actions[0]
				if action.GetVerb() != "create" {
					t.Errorf("unexpected action: %v", action)
				}
				createAction := action.(clienttesting.CreateAction)
				secret, ok := createAction.GetObject().(*corev1.Secret)
				if !ok {
					t.Errorf("unexpected object type: %T", createAction.GetObject())
				}
				if secret.Name != "test-signer-cert" {
					t.Errorf("unexpected create found: %v", action)
				}
			},
			expectedError: "nope",
		},
		{
			name: "error updating ca bundle",
			setupReactors: func(client *fake.Clientset) {
				client.PrependReactor("create", "configmaps", func(action clienttesting.Action) (bool, runtime.Object, error) {
					createAction := action.(clienttesting.CreateAction)
					if secret, ok := createAction.GetObject().(*corev1.ConfigMap); ok && secret.Name == "test-ca-bundle" {
						return true, nil, apierrors.NewBadRequest("nope")
					}
					return false, nil, nil
				})
			},
			validateActions: func(t *testing.T, actions []clienttesting.Action) {
				// Stop and don't create target secret
				if len(actions) != 2 {
					t.Errorf("expected two actions, got %v", len(actions))
				}
				for _, action := range actions {
					if action.GetVerb() == "create" && action.GetResource().Resource == "secrets" {
						createAction := action.(clienttesting.CreateAction)
						secret := createAction.GetObject().(*corev1.Secret)
						if secret.Name == "test-target-cert" {
							t.Errorf("unexpected create found: %v", action)
						}
					}
				}
			},
			expectedError: "nope",
		},
		{
			name: "stop at empty signer",
			existingObjects: []runtime.Object{
				createSigningCASecretNoMetadata("test-namespace", "test-signer-cert", signer),
			},
			setupReactors: func(client *fake.Clientset) {
				client.PrependReactor("update", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					createAction := action.(clienttesting.CreateAction)
					if secret, ok := createAction.GetObject().(*corev1.Secret); ok && secret.Name == "test-signer-cert" {
						return true, nil, apierrors.NewConflict(
							schema.GroupResource{Group: "secrets", Resource: "secrets"},
							"test-signer-cert",
							fmt.Errorf("you shall not pass"))
					}
					return false, nil, nil
				})
			},
			validateActions: func(t *testing.T, actions []clienttesting.Action) {
				// Make sure we don't create target cert or ca bundle
				if len(actions) != 1 {
					t.Errorf("expected one action, got %v", len(actions))
				}
				action := actions[0]
				if action.GetVerb() != "update" {
					t.Errorf("unexpected action: %v", action)
				}
				updateAction := action.(clienttesting.UpdateAction)
				secret, ok := updateAction.GetObject().(*corev1.Secret)
				if !ok {
					t.Errorf("unexpected object type: %T", updateAction.GetObject())
				}
				if secret.Name != "test-signer-cert" {
					t.Errorf("unexpected create found: %v", action)
				}
			},
			expectedError: "signingCertKeyPair is nil",
		},
		{
			name: "stop at empty CA bundle",
			existingObjects: []runtime.Object{
				createValidSigningCASecret("test-namespace", "test-signer-cert", signer),
				createCABundleConfigMapNoMetadata("test-namespace", "test-ca-bundle", signer),
			},
			setupReactors: func(client *fake.Clientset) {
				client.PrependReactor("update", "configmaps", func(action clienttesting.Action) (bool, runtime.Object, error) {
					createAction := action.(clienttesting.CreateAction)
					if secret, ok := createAction.GetObject().(*corev1.ConfigMap); ok && secret.Name == "test-ca-bundle" {
						return true, nil, apierrors.NewConflict(
							schema.GroupResource{Group: "configmaps", Resource: "configmaps"},
							"test-ca-bundle",
							fmt.Errorf("you shall not pass"))
					}
					return false, nil, nil
				})
			},
			validateActions: func(t *testing.T, actions []clienttesting.Action) {
				// Stop and don't create target secret
				if len(actions) != 1 {
					t.Errorf("expected one action, got %v", len(actions))
				}
				action := actions[0]
				createAction, ok := action.(clienttesting.CreateAction)
				if !ok {
					t.Errorf("unexpected action: %v", action)
				}
				configMap, ok := createAction.GetObject().(*corev1.ConfigMap)
				if !ok {
					t.Errorf("unexpected object type: %T", createAction.GetObject())
				}
				if configMap.Name != "test-ca-bundle" {
					t.Errorf("unexpected create found: %v", action)
				}
			},
			expectedError: "cabundleCerts is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client with existing objects
			fakeClient := fake.NewSimpleClientset(tt.existingObjects...)

			// Setup custom reactors if provided
			if tt.setupReactors != nil {
				tt.setupReactors(fakeClient)
			}

			// Create informer factory
			informerFactory := informers.NewSharedInformerFactory(fakeClient, 0)

			// Add existing objects to informer cache
			for _, obj := range tt.existingObjects {
				switch o := obj.(type) {
				case *corev1.Secret:
					informerFactory.Core().V1().Secrets().Informer().GetStore().Add(o)
				case *corev1.ConfigMap:
					informerFactory.Core().V1().ConfigMaps().Informer().GetStore().Add(o)
				}
			}

			// Create the controller
			controller := &CertRotationController{
				Name: "test-controller",
				RotatedSigningCASecret: RotatedSigningCASecret{
					Namespace:     "test-namespace",
					Name:          "test-signer-cert",
					Validity:      24 * time.Hour,
					Refresh:       12 * time.Hour,
					Informer:      informerFactory.Core().V1().Secrets(),
					Lister:        informerFactory.Core().V1().Secrets().Lister(),
					Client:        fakeClient.CoreV1(),
					EventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
				},
				CABundleConfigMap: CABundleConfigMap{
					Namespace:     "test-namespace",
					Name:          "test-ca-bundle",
					Informer:      informerFactory.Core().V1().ConfigMaps(),
					Lister:        informerFactory.Core().V1().ConfigMaps().Lister(),
					Client:        fakeClient.CoreV1(),
					EventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
					AdditionalAnnotations: AdditionalAnnotations{
						JiraComponent: "test",
					},
				},
				RotatedSelfSignedCertKeySecret: RotatedSelfSignedCertKeySecret{
					Namespace:     "test-namespace",
					Name:          "test-target-cert",
					Validity:      24 * time.Hour,
					Refresh:       12 * time.Hour,
					CertCreator:   &mockTargetCertCreator{},
					Informer:      informerFactory.Core().V1().Secrets(),
					Lister:        informerFactory.Core().V1().Secrets().Lister(),
					Client:        fakeClient.CoreV1(),
					EventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
				},
				StatusReporter: &testStatusReporter{},
			}

			// Run SyncWorker
			ctx := context.Background()
			err := controller.SyncWorker(ctx)

			// Check error
			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.expectedError)
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %q", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			// Validate actions if provided
			if tt.validateActions != nil {
				tt.validateActions(t, fakeClient.Actions())
			}
		})
	}
}

type testStatusReporter struct{}

func (t *testStatusReporter) Report(ctx context.Context, controllerName string, syncErr error) (bool, error) {
	return false, nil
}

// mockTargetCertCreator is a mock implementation of TargetCertCreator for testing
type mockTargetCertCreator struct{}

func (m *mockTargetCertCreator) NewCertificate(signer *crypto.CA, validity time.Duration) (*crypto.TLSCertificateConfig, error) {
	// Use the provided signer to create a real certificate with matching key
	certConfig, err := signer.MakeServerCert(sets.New("test-cert", "localhost"), validity)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %v", err)
	}

	return certConfig, nil
}

func (m *mockTargetCertCreator) NeedNewTargetCertKeyPair(currentCertSecret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration, refreshOnlyWhenExpired, creationRequired bool) string {
	if creationRequired {
		return "creation required"
	}
	// For testing, we don't need rotation unless explicitly required
	return ""
}

func (m *mockTargetCertCreator) SetAnnotations(cert *crypto.TLSCertificateConfig, annotations map[string]string) map[string]string {
	// Just return the annotations as-is for testing
	return annotations
}

func createValidSigningCASecret(namespace, name string, signer *crypto.TLSCertificateConfig) *corev1.Secret {
	certBytes, keyBytes, err := signer.GetPEMBytes()
	if err != nil {
		panic(fmt.Sprintf("failed to get PEM bytes: %v", err))
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				"auth.openshift.io/certificate-not-after":  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"auth.openshift.io/certificate-not-before": time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certBytes,
			"tls.key": keyBytes,
		},
	}
}

func createSigningCASecretNoMetadata(namespace, name string, signer *crypto.TLSCertificateConfig) *corev1.Secret {
	certBytes, keyBytes, err := signer.GetPEMBytes()
	if err != nil {
		panic(fmt.Sprintf("failed to get PEM bytes: %v", err))
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certBytes,
			"tls.key": keyBytes,
		},
	}
}

func createSigningCASecret(namespace, name string, signer *crypto.TLSCertificateConfig) *corev1.Secret {
	certBytes, keyBytes, err := signer.GetPEMBytes()
	if err != nil {
		panic(fmt.Sprintf("failed to get PEM bytes: %v", err))
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				"auth.openshift.io/certificate-not-after":  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"auth.openshift.io/certificate-not-before": time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certBytes,
			"tls.key": keyBytes,
		},
	}
}

func createValidCABundleConfigMap(namespace, name string, signer *crypto.TLSCertificateConfig) *corev1.ConfigMap {
	certBytes, _, err := signer.GetPEMBytes()
	if err != nil {
		panic(fmt.Sprintf("failed to get PEM bytes: %v", err))
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				annotations.OpenShiftComponent: "test",
			},
		},
		Data: map[string]string{
			"ca-bundle.crt": string(certBytes),
		},
	}
}

func createCABundleConfigMapNoMetadata(namespace, name string, signer *crypto.TLSCertificateConfig) *corev1.ConfigMap {
	certBytes, _, err := signer.GetPEMBytes()
	if err != nil {
		panic(fmt.Sprintf("failed to get PEM bytes: %v", err))
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: map[string]string{
			"ca-bundle.crt": string(certBytes),
		},
	}
}

func createValidTargetCertSecret(namespace, name string, serverCert *crypto.TLSCertificateConfig) *corev1.Secret {
	certBytes, keyBytes, err := serverCert.GetPEMBytes()
	if err != nil {
		panic(fmt.Sprintf("failed to get PEM bytes: %v", err))
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				"auth.openshift.io/certificate-not-after":  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"auth.openshift.io/certificate-not-before": time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certBytes,
			"tls.key": keyBytes,
		},
	}
}

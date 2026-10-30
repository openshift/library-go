package certrotation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openshift/api/annotations"
	"github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/pki"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

// TestCertRotationController_SyncWorker tests the SyncWorker method
func TestCertRotationController_SyncWorker(t *testing.T) {
	// Create signer certificate
	signer, err := crypto.NewSigningCertificate("test-ca", crypto.RSAKeyPairGenerator{Bits: 2048}, crypto.WithLifetime(time.Hour*24))
	if err != nil {
		panic(fmt.Sprintf("failed to create test CA: %v", err))
	}
	// Create CA bundle
	ca := &crypto.CA{
		Config:          signer,
		SerialGenerator: &crypto.RandomSerialGenerator{},
	}
	// Create target certificate signed by the CA
	targetCert, err := ca.NewServerCertificate(sets.New("test.example.com", "localhost"), crypto.RSAKeyPairGenerator{Bits: 2048}, crypto.WithLifetime(time.Hour*12))
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
				name: "test-controller",
				rotatedSigningCASecret: RotatedSigningCASecret{
					namespace:     "test-namespace",
					name:          "test-signer-cert",
					validity:      24 * time.Hour,
					refresh:       12 * time.Hour,
					informer:      informerFactory.Core().V1().Secrets(),
					lister:        informerFactory.Core().V1().Secrets().Lister(),
					client:        fakeClient.CoreV1(),
					eventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
					clock:         clock.RealClock{},
				},
				caBundleConfigMap: CABundleConfigMap{
					namespace:     "test-namespace",
					name:          "test-ca-bundle",
					informer:      informerFactory.Core().V1().ConfigMaps(),
					lister:        informerFactory.Core().V1().ConfigMaps().Lister(),
					client:        fakeClient.CoreV1(),
					eventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
					additionalAnnotations: AdditionalAnnotations{
						JiraComponent: "test",
					},
					clock: clock.RealClock{},
				},
				rotatedSelfSignedCertKeySecret: RotatedSelfSignedCertKeySecret{
					namespace:     "test-namespace",
					name:          "test-target-cert",
					validity:      24 * time.Hour,
					refresh:       12 * time.Hour,
					certCreator:   &mockTargetCertCreator{},
					informer:      informerFactory.Core().V1().Secrets(),
					lister:        informerFactory.Core().V1().Secrets().Lister(),
					client:        fakeClient.CoreV1(),
					eventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
					clock:         clock.RealClock{},
				},
				statusReporter: &testStatusReporter{},
			}

			// Run SyncWorker
			ctx := t.Context()
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

func (m *mockTargetCertCreator) NewCertificate(signer *crypto.CA, validity time.Duration, _ crypto.KeyPairGenerator) (*crypto.TLSCertificateConfig, error) {
	// Use the provided signer to create a real certificate with matching key
	certConfig, err := signer.NewServerCertificate(sets.New("test-cert", "localhost"), crypto.RSAKeyPairGenerator{Bits: 2048}, crypto.WithLifetime(validity))
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %v", err)
	}

	return certConfig, nil
}

func (m *mockTargetCertCreator) CertificateType() pki.CertificateType {
	return pki.CertificateTypeServing
}

func (m *mockTargetCertCreator) NeedNewTargetCertKeyPair(currentCertSecret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration, refreshOnlyWhenExpired, creationRequired bool, _ crypto.KeyPairGenerator) string {
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

type mockPKIProfileProvider struct {
	profile *v1alpha1.PKIProfile
}

func (m *mockPKIProfileProvider) PKIProfile() (*v1alpha1.PKIProfile, error) {
	return m.profile, nil
}

func TestCertRotationController_SyncWorker_AlgorithmRotationWithCrossSigning(t *testing.T) {
	type testcase struct {
		name string

		rotations int

		signerPKIProfiles []*v1alpha1.PKIProfile
		targetPKIProfile  *v1alpha1.PKIProfile

		certCreatorFn func(clock.PassiveClock) TargetCertCreator

		rotationDurationStep time.Duration

		verifyOptionFn func(*x509.VerifyOptions)

		expectedCertChainLengths         []int
		expectedInitialCABundleValidates []bool
	}

	rsa2048PKIProfile := &v1alpha1.PKIProfile{
		Defaults: v1alpha1.DefaultCertificateConfig{
			Key: v1alpha1.KeyConfig{
				Algorithm: v1alpha1.KeyAlgorithmRSA,
				RSA: v1alpha1.RSAKeyConfig{
					KeySize: 2048,
				},
			},
		},
	}

	ecdsaP256PKIProfile := &v1alpha1.PKIProfile{
		Defaults: v1alpha1.DefaultCertificateConfig{
			Key: v1alpha1.KeyConfig{
				Algorithm: v1alpha1.KeyAlgorithmECDSA,
				ECDSA: v1alpha1.ECDSAKeyConfig{
					Curve: v1alpha1.ECDSACurveP256,
				},
			},
		},
	}

	testcases := []testcase{
		{
			name:      "signer PKI key algorithm change, non-PKI serving certificate as target certificate, single rotation during original validity period, results in valid cross-signed serving cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm change, non-PKI client certificate as target certificate, single rotation during original validity period, results in valid cross-signed client cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 2},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm change, non-PKI peer certificate as target certificate, single rotation during original validity period, results in valid cross-signed peer cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm change, PKI serving certificate as target certificate, single rotation during original validity period, results in valid cross-signed serving cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm change, PKI client certificate as target certificate, single rotation during original validity period, results in valid cross-signed client cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 2},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm change, PKI peer certificate as target certificate, single rotation during original validity period, results in valid cross-signed peer cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm change, non-PKI serving certificate as target certificate, multiple rotations during original validity period, results in valid cross-signed serving cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3, 4},
			expectedInitialCABundleValidates: []bool{true, true},
		},
		{
			name:      "signer PKI key algorithm change, non-PKI client certificate as target certificate, multiple rotations during original validity period, results in valid cross-signed client cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 2, 3},
			expectedInitialCABundleValidates: []bool{true, true},
		},
		{
			name:      "signer PKI key algorithm change, non-PKI peer certificate as target certificate, multiple rotations during original validity period, results in valid cross-signed peer cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3, 4},
			expectedInitialCABundleValidates: []bool{true, true},
		},
		{
			name:      "signer PKI key algorithm change, PKI serving certificate as target certificate, multiple rotations during original validity period, results in valid cross-signed serving cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3, 4},
			expectedInitialCABundleValidates: []bool{true, true},
		},
		{
			name:      "signer PKI key algorithm change, PKI client certificate as target certificate, multiple rotations during original validity period, results in valid cross-signed client cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 2, 3},
			expectedInitialCABundleValidates: []bool{true, true},
		},
		{
			name:      "signer PKI key algorithm change, PKI peer certificate as target certificate, multiple rotations during original validity period, results in valid cross-signed peer cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
				ecdsaP256PKIProfile,
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			// ensure that we have progressed by at least some amount of time
			// greater than 1 second so that the unix time representation changes
			// such that we get a net-new signer name for target cert generation.
			rotationDurationStep: time.Minute,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3, 4},
			expectedInitialCABundleValidates: []bool{true, true},
		},
		// refresh time met
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed, non-PKI serving certificate as target certificate, results in valid cross-signed serving cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed twice, non-PKI serving certificate as target certificate, results in valid cross-signed serving cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3, 3},
			expectedInitialCABundleValidates: []bool{true, false},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed, non-PKI client certificate as target certificate, results in valid cross-signed client cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 2},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed twice, non-PKI client certificate as target certificate, results in valid cross-signed client cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 2, 2},
			expectedInitialCABundleValidates: []bool{true, false},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed, non-PKI peer certificate as target certificate, results in valid cross-signed peer cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed twice, non-PKI peer certificate as target certificate, results in valid cross-signed peer cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3, 3},
			expectedInitialCABundleValidates: []bool{true, false},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed, PKI serving certificate as target certificate, results in valid cross-signed serving cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed twice, PKI serving certificate as target certificate, results in valid cross-signed serving cert chain",
			rotations: 2,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3, 3},
			expectedInitialCABundleValidates: []bool{true, false},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed, PKI client certificate as target certificate, results in valid cross-signed client cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 2},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed twice, PKI client certificate as target certificate, results in valid cross-signed client cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 2, 2},
			expectedInitialCABundleValidates: []bool{true, false},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed, PKI peer certificate as target certificate, results in valid cross-signed peer cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3},
			expectedInitialCABundleValidates: []bool{true},
		},
		{
			name:      "signer PKI key algorithm unchanged, refresh time passed, PKI peer certificate as target certificate, results in valid cross-signed peer cert chain",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			rotationDurationStep: 13 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 3, 3},
			expectedInitialCABundleValidates: []bool{true, false},
		},
		// expiration
		{
			name:      "signer PKI key algorithm unchanged, expired, non-PKI serving certificate as target certificate, results in no cross-signed intermediate",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			rotationDurationStep: 25 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 2},
			expectedInitialCABundleValidates: []bool{false},
		},
		{
			name:      "signer PKI key algorithm unchanged, expired, non-PKI client certificate as target certificate, results in no cross-signed intermediate",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			rotationDurationStep: 25 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 1},
			expectedInitialCABundleValidates: []bool{false},
		},
		{
			name:      "signer PKI key algorithm unchanged, expired, non-PKI peer certificate as target certificate, results in no cross-signed intermediate",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			rotationDurationStep: 25 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 2},
			expectedInitialCABundleValidates: []bool{false},
		},
		{
			name:      "signer PKI key algorithm unchanged, expired, PKI serving certificate as target certificate, results in no cross-signed intermediate",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ServingRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					clock: clock,
				}
			},
			rotationDurationStep: 25 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 2},
			expectedInitialCABundleValidates: []bool{false},
		},
		{
			name:      "signer PKI key algorithm unchanged, expired, PKI client certificate as target certificate, results in no cross-signed intermediate",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &ClientRotation{
					userInfo: &user.DefaultInfo{
						Name:   "hsimpson",
						Groups: []string{"donut-lovers"},
					},
					clock: clock,
				}
			},
			rotationDurationStep: 25 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedCertChainLengths:         []int{1, 1},
			expectedInitialCABundleValidates: []bool{false},
		},
		{
			name:      "signer PKI key algorithm unchanged, expired, PKI peer certificate as target certificate, results in no cross-signed intermediate",
			rotations: 1,
			signerPKIProfiles: []*v1alpha1.PKIProfile{
				rsa2048PKIProfile,
			},
			targetPKIProfile: rsa2048PKIProfile,
			certCreatorFn: func(clock clock.PassiveClock) TargetCertCreator {
				return &PeerRotation{
					hostnames: func() []string {
						return []string{
							"certrotation.test.openshift.io",
						}
					},
					userInfo: &user.DefaultInfo{
						Name: "certrotation.test.openshift.io",
					},
					clock: clock,
				}
			},
			rotationDurationStep: 25 * time.Hour,
			verifyOptionFn: func(vo *x509.VerifyOptions) {
				vo.DNSName = "certrotation.test.openshift.io"
				vo.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			},
			expectedCertChainLengths:         []int{2, 2},
			expectedInitialCABundleValidates: []bool{false},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Create fake client
			fakeClient := fake.NewSimpleClientset()

			// Create informer factory
			informerFactory := informers.NewSharedInformerFactory(fakeClient, 0)

			secretInformer := informerFactory.Core().V1().Secrets()
			configMapInformer := informerFactory.Core().V1().ConfigMaps()

			now := time.Now()
			clockTime := clocktesting.NewFakePassiveClock(now)

			rotationIndex := 0

			var signerPKIProvider pki.PKIProfileProvider
			mockProvider := &mockPKIProfileProvider{}
			if len(tc.signerPKIProfiles) >= 1 {
				signerPKIProvider = mockProvider
				mockProvider.profile = tc.signerPKIProfiles[rotationIndex]
			}

			var targetPKIProvider pki.PKIProfileProvider
			if tc.targetPKIProfile != nil {
				targetPKIProvider = pki.NewStaticPKIProfileProvider(tc.targetPKIProfile)
			}

			// Create the controller
			controller := &CertRotationController{
				name:  "test-controller",
				clock: clockTime,
				rotatedSigningCASecret: RotatedSigningCASecret{
					namespace:          "test-namespace",
					name:               "test-signer-cert",
					validity:           24 * time.Hour,
					refresh:            12 * time.Hour,
					informer:           secretInformer,
					lister:             secretInformer.Lister(),
					client:             fakeClient.CoreV1(),
					eventRecorder:      events.NewInMemoryRecorder("test", clock.RealClock{}),
					pkiProfileProvider: signerPKIProvider,
					clock:              clockTime,
				},
				caBundleConfigMap: CABundleConfigMap{
					namespace:     "test-namespace",
					name:          "test-ca-bundle",
					informer:      configMapInformer,
					lister:        configMapInformer.Lister(),
					client:        fakeClient.CoreV1(),
					eventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
					additionalAnnotations: AdditionalAnnotations{
						JiraComponent: "test",
					},
					clock: clockTime,
				},
				rotatedSelfSignedCertKeySecret: RotatedSelfSignedCertKeySecret{
					namespace:          "test-namespace",
					name:               "test-target-cert",
					validity:           24 * time.Hour,
					refresh:            12 * time.Hour,
					certCreator:        tc.certCreatorFn(clockTime),
					informer:           secretInformer,
					lister:             secretInformer.Lister(),
					client:             fakeClient.CoreV1(),
					eventRecorder:      events.NewInMemoryRecorder("test", clock.RealClock{}),
					pkiProfileProvider: targetPKIProvider,
					clock:              clockTime,
				},
				statusReporter: &testStatusReporter{},
			}

			// Run SyncWorker
			ctx := t.Context()
			err := controller.SyncWorker(ctx)
			if err != nil {
				t.Fatalf("initial controller sync failed: %v", err)
			}

			// Ensure all the initial create actions occurred,
			// simulate the informer cache updates by manually updating the indexers,
			// and capture the initial CA bundle that was created for the initial signer configuration
			// to be used in later verification of the resulting target certificate chain post-change.

			actions := fakeClient.Actions()
			if len(actions) != 3 {
				t.Fatalf("expected initial controller sync to perform 3 actions but got %d", len(actions))
			}

			signerAction := actions[0]
			if signerAction.GetVerb() != "create" || signerAction.GetResource().Resource != "secrets" {
				t.Errorf("unexpected ca bundle action: %v", signerAction)
			}
			signerActionSecret := signerAction.(clienttesting.CreateAction).GetObject().(*corev1.Secret)
			secretInformer.Informer().GetIndexer().Add(signerActionSecret)

			caBundleAction := actions[1]
			if caBundleAction.GetVerb() != "create" || caBundleAction.GetResource().Resource != "configmaps" {
				t.Errorf("unexpected ca bundle action: %v", caBundleAction)
			}
			caBundleActionConfigMap := caBundleAction.(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
			configMapInformer.Informer().GetIndexer().Add(caBundleActionConfigMap)
			initialCABundle, ok := caBundleActionConfigMap.Data["ca-bundle.crt"]
			if !ok {
				t.Fatalf("no initial CA bundle data")
			}

			certAction := actions[2]
			if certAction.GetVerb() != "create" || certAction.GetResource().Resource != "secrets" {
				t.Errorf("unexpected ca bundle action: %v", certAction)
			}
			certActionSecret := certAction.(clienttesting.CreateAction).GetObject().(*corev1.Secret)
			secretInformer.Informer().GetIndexer().Add(certActionSecret)

			initialActions := 3
			for i := range tc.rotations {
				// Do some updates to simulate some time passing and any configuration changes that should occur.
				clockTime.SetTime(now.Add(tc.rotationDurationStep))
				now = now.Add(tc.rotationDurationStep)
				if len(tc.signerPKIProfiles) >= 1+(i+1) {
					mockProvider.profile = tc.signerPKIProfiles[(i + 1)]
				}

				err = controller.SyncWorker(ctx)
				if err != nil {
					t.Fatalf("rotation %d controller sync failed: %v", (i + 1), err)
				}

				// Ensure all the update actions have occurred.
				// Because cross-signing only matters when the signer has rotated, we should
				// see that exactly 3 additional updates have occurred:
				//     1. The signer CA secret has been updated.
				//     2. The CA bundle has been updated (because the signer CA is different)
				//     3. The target certificate has been updated (because the desired issuer (signer) configuration has changed)
				// Additionally, capture the updated CA bundle for use in later verification.

				actions = fakeClient.Actions()
				expectedActionsCount := initialActions + (3 * (i + 1))
				if len(actions) != expectedActionsCount {
					actionStrings := []string{}
					for _, action := range actions {
						name := "unknown"
						if uaction, ok := action.(clienttesting.UpdateAction); ok {
							name = uaction.GetObject().(metav1.Object).GetName()
						}
						actionStrings = append(actionStrings, fmt.Sprintf("%s - %s/%s - %s/%s", action.GetVerb(), action.GetResource().String(), action.GetSubresource(), action.GetNamespace(), name))
					}
					t.Fatalf("expected rotation %d controller sync to perform 3 additional actions to total %d actions but got %d. Actions: %s", i+1, expectedActionsCount, len(actions), strings.Join(actionStrings, "\n"))
				}

				rotationSignerAction := actions[expectedActionsCount-3]
				if signerAction.GetVerb() != "create" || signerAction.GetResource().Resource != "secrets" {
					t.Errorf("unexpected rotation ca bundle action: %v", signerAction)
				}
				rotationSignerActionSecret := rotationSignerAction.(clienttesting.CreateAction).GetObject().(*corev1.Secret)
				secretInformer.Informer().GetIndexer().Add(rotationSignerActionSecret)

				rotationCABundleAction := actions[expectedActionsCount-2]
				if rotationCABundleAction.GetVerb() != "update" || rotationCABundleAction.GetResource().Resource != "configmaps" {
					t.Errorf("unexpected rotation ca bundle action: %v", rotationCABundleAction)
				}
				rotationCABundleActionConfigMap := rotationCABundleAction.(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				rotationCABundle, ok := rotationCABundleActionConfigMap.Data["ca-bundle.crt"]
				if !ok {
					t.Fatalf("no rotation CA bundle data")
				}

				rotationTargetCertAction := actions[expectedActionsCount-1]
				if rotationTargetCertAction.GetVerb() != "update" || rotationTargetCertAction.GetResource().Resource != "secrets" {
					t.Errorf("unexpected rotation target cert action: %v", rotationTargetCertAction)
				}
				rotationTargetCertActionSecret := rotationTargetCertAction.(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				rotationTargetCertChain, ok := rotationTargetCertActionSecret.Data["tls.crt"]
				if !ok {
					t.Fatalf("no rotation target cert chain")
				}

				rotationTargetChainCerts := []*x509.Certificate{}
				for len(rotationTargetCertChain) > 0 {
					var block *pem.Block
					block, rotationTargetCertChain = pem.Decode(rotationTargetCertChain)
					if block == nil {
						break
					}

					if block.Type != "CERTIFICATE" {
						continue
					}

					// Parse the raw DER bytes inside the PEM block into an x509 Certificate
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						t.Fatalf("parsing rotation cert chain: %v", err)
					}

					rotationTargetChainCerts = append(rotationTargetChainCerts, cert)
				}

				if len(rotationTargetChainCerts) != tc.expectedCertChainLengths[i+1] {
					for _, cert := range rotationTargetChainCerts {
						fmt.Println(cert.Subject.CommonName, cert.Issuer.CommonName, cert.NotAfter.Before(now), cert.NotAfter, now)
					}
					t.Fatalf("expected the rotation cert chain to contain exactly %d certificates but got %d", tc.expectedCertChainLengths[i+1], len(rotationTargetChainCerts))
				}

				leaf := rotationTargetChainCerts[0]
				intermediates := []*x509.Certificate{}
				if len(rotationTargetChainCerts) > 1 {
					intermediates = rotationTargetChainCerts[1:]
				}

				initialRoots := x509.NewCertPool()
				ok = initialRoots.AppendCertsFromPEM([]byte(initialCABundle))
				if !ok {
					t.Fatal("parsing initial CA bundle certificates resulted in no appended certs")
				}

				updatedRoots := x509.NewCertPool()
				ok = updatedRoots.AppendCertsFromPEM([]byte(rotationCABundle))
				if !ok {
					t.Fatal("parsing rotation CA bundle certificates resulted in no appended certs")
				}

				intermediatesPool := x509.NewCertPool()
				for _, cert := range intermediates {
					intermediatesPool.AddCert(cert)
				}

				initialVerifyOptions := &x509.VerifyOptions{
					Roots:         initialRoots,
					Intermediates: intermediatesPool,
					CurrentTime:   clockTime.Now().Add(time.Minute),
				}

				rotationVerifyOptions := &x509.VerifyOptions{
					Roots:         updatedRoots,
					Intermediates: intermediatesPool,
					CurrentTime:   clockTime.Now().Add(time.Minute),
				}

				if tc.verifyOptionFn != nil {
					tc.verifyOptionFn(initialVerifyOptions)
					tc.verifyOptionFn(rotationVerifyOptions)
				}

				_, err = leaf.Verify(*initialVerifyOptions)
				if err != nil && tc.expectedInitialCABundleValidates[i] {
					t.Fatalf("failed to verify the new leaf certificate using the initial CA bundle: %v", err)
				} else if err == nil && !tc.expectedInitialCABundleValidates[i] {
					t.Fatal("successfully verified the new leaf certificate using the initial CA bundle, but expected it to fail")
				}

				_, err = leaf.Verify(*rotationVerifyOptions)
				if err != nil {
					t.Fatalf("failed to verify the new leaf certificate using the rotation CA bundle: %v", err)
				}
			}
		})
	}
}

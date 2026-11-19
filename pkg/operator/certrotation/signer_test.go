package certrotation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/api/annotations"
	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/pki"
)

func TestEnsureSigningCertKeyPair(t *testing.T) {
	verifyActionsOnCreated := func(t *testing.T, actions []clienttesting.Action) {
		t.Helper()
		if len(actions) != 1 {
			t.Fatalf("Expected 1 action, got %s", spew.Sdump(actions))
		}

		action := actions[0]
		if !action.Matches("create", "secrets") {
			t.Fatalf("Expected secret create action, got %s", spew.Sdump(action))
		}
	}

	verifyActionsOnUpdated := func(t *testing.T, actions []clienttesting.Action) {
		t.Helper()
		if len(actions) != 1 {
			t.Fatalf("Expected 1 action, got %s", spew.Sdump(actions))
		}

		action := actions[0]
		if !action.Matches("update", "secrets") {
			t.Fatalf("Expected secret update action, got %s", spew.Sdump(action))
		}
	}

	verifyActionsEmpty := func(t *testing.T, actions []clienttesting.Action) {
		t.Helper()
		if len(actions) != 0 {
			t.Fatalf("Expected no action, got %s", spew.Sdump(actions))
		}
	}

	verifyControllerUpdatedSecret := func(t *testing.T, expected, actual bool) {
		t.Helper()
		if actual != expected {
			t.Errorf("Expected controller updated secret flag to be %v, got %v", expected, actual)
		}
	}

	verifySecret := func(t *testing.T, actual *corev1.Secret) {
		t.Helper()

		if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeSigner {
			t.Errorf("expected certificate type 'signer', got: %v", certType)
		}
		if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
			t.Error(actual.Data)
		}
		verifyKeyPair(t, actual.Data["tls.crt"], actual.Data["tls.key"])

		expectedAnnotationKeys := sets.New[string](
			"auth.openshift.io/certificate-not-after",
			"auth.openshift.io/certificate-not-before",
			"auth.openshift.io/certificate-issuer",
			"certificates.openshift.io/refresh-period",
			"openshift.io/owning-component",
		)
		if keys := sets.KeySet(actual.Annotations); !keys.Equal(expectedAnnotationKeys) {
			t.Errorf("Annotation keys don't match:\n%s", cmp.Diff(expectedAnnotationKeys, keys))
		}

		ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
		if !found {
			t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
		}
		if ownershipValue != "test" {
			t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
		}
		if len(actual.OwnerReferences) != 1 {
			t.Errorf("expected to have exactly one owner reference")
		}
		if actual.OwnerReferences[0].Name != "operator" {
			t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
		}
	}

	tests := []struct {
		name string

		initialSecret          *corev1.Secret
		RefreshOnlyWhenExpired bool

		verifyResult func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool)

		expectedError  string
		expectedEvents []*corev1.Event
	}{
		{
			name:                   "initial create",
			RefreshOnlyWhenExpired: false,
			verifyResult: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				actions := client.Actions()
				verifyActionsOnCreated(t, actions)
				verifyControllerUpdatedSecret(t, true, controllerUpdatedSecret)
				verifySecret(t, actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret))
			},
			expectedEvents: []*corev1.Event{
				{Reason: "SignerUpdateRequired", Message: `"signer" in "ns" requires a new signing cert/key pair: secret doesn't exist`},
				{Reason: "SecretCreated", Message: `Created Secret/signer -n ns because it was missing`},
			},
		},
		{
			name: "update no annotations",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer", ResourceVersion: "10"},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			RefreshOnlyWhenExpired: false,
			verifyResult: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				actions := client.Actions()
				verifyActionsOnUpdated(t, actions)
				verifyControllerUpdatedSecret(t, true, controllerUpdatedSecret)
				verifySecret(t, actions[0].(clienttesting.UpdateAction).GetObject().(*corev1.Secret))
			},
			expectedEvents: []*corev1.Event{
				{Reason: "SignerUpdateRequired", Message: `"signer" in "ns" requires a new signing cert/key pair: missing notAfter`},
				{Reason: "SecretUpdated", Message: `Updated Secret/signer -n ns because it changed`},
			},
		},
		{
			name: "update on missing notAfter annotation",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer", ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
						annotations.OpenShiftComponent:             "test",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			RefreshOnlyWhenExpired: false,
			verifyResult: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				actions := client.Actions()
				verifyActionsOnUpdated(t, actions)
				verifyControllerUpdatedSecret(t, true, controllerUpdatedSecret)
				verifySecret(t, actions[0].(clienttesting.UpdateAction).GetObject().(*corev1.Secret))
			},
			expectedEvents: []*corev1.Event{
				{Reason: "SignerUpdateRequired", Message: `"signer" in "ns" requires a new signing cert/key pair: missing notAfter`},
				{Reason: "SecretUpdated", Message: `Updated Secret/signer -n ns because it changed`},
			},
		},
		{
			name: "update on missing notBefore annotation",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer", ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after": "2108-09-08T22:47:31-07:00",
						annotations.OpenShiftComponent:            "test",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			RefreshOnlyWhenExpired: false,
			verifyResult: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				actions := client.Actions()
				verifyActionsOnUpdated(t, actions)
				verifyControllerUpdatedSecret(t, true, controllerUpdatedSecret)
				verifySecret(t, actions[0].(clienttesting.UpdateAction).GetObject().(*corev1.Secret))
			},
			expectedEvents: []*corev1.Event{
				{Reason: "SignerUpdateRequired", Message: `"signer" in "ns" requires a new signing cert/key pair: missing notBefore`},
				{Reason: "SecretUpdated", Message: `Updated Secret/signer -n ns because it changed`},
			},
		},
		{
			name: "update no work",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
						annotations.OpenShiftComponent:             "test",
					},
					OwnerReferences: []metav1.OwnerReference{{
						Name: "operator",
					}},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			RefreshOnlyWhenExpired: false,
			verifyResult: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				verifyActionsEmpty(t, client.Actions())
				verifyControllerUpdatedSecret(t, false, controllerUpdatedSecret)
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
		{
			name: "update with RefreshOnlyWhenExpired set",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "ns",
					Name:            "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			RefreshOnlyWhenExpired: true,
			verifyResult: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				verifyActionsEmpty(t, client.Actions())
				verifyControllerUpdatedSecret(t, false, controllerUpdatedSecret)
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

			client := kubefake.NewClientset()
			if test.initialSecret != nil {
				indexer.Add(test.initialSecret)
				client = kubefake.NewClientset(test.initialSecret)
			}

			recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))

			c := &RotatedSigningCASecret{
				Namespace:     "ns",
				Name:          "signer",
				Validity:      24 * time.Hour,
				Refresh:       12 * time.Hour,
				Client:        client.CoreV1(),
				Lister:        corev1listers.NewSecretLister(indexer),
				EventRecorder: recorder,
				AdditionalAnnotations: AdditionalAnnotations{
					JiraComponent: "test",
				},
				Owner: &metav1.OwnerReference{
					Name: "operator",
				},
				RefreshOnlyWhenExpired: test.RefreshOnlyWhenExpired,
			}

			_, updated, err := c.EnsureSigningCertKeyPair(t.Context())
			switch {
			case err != nil && len(test.expectedError) == 0:
				t.Error(err)
			case err != nil && !strings.Contains(err.Error(), test.expectedError):
				t.Error(err)
			case err == nil && len(test.expectedError) != 0:
				t.Errorf("missing %q", test.expectedError)
			}

			test.verifyResult(t, client, updated)

			if events := pruneEventFieldsForComparison(recorder.Events()); !cmp.Equal(events, test.expectedEvents) {
				t.Errorf("Events mismatch (-want +got):\n%s", cmp.Diff(test.expectedEvents, events))
			}
		})
	}
}

func pruneEventFieldsForComparison(events []*corev1.Event) []*corev1.Event {
	if len(events) == 0 {
		return nil
	}

	out := make([]*corev1.Event, len(events))
	for i, event := range events {
		out[i] = &corev1.Event{
			Reason:  event.Reason,
			Message: event.Message,
		}
	}
	return out
}

func verifyKeyPair(t testing.TB, certPEM, keyPEM []byte) {
	t.Helper()

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse cert: %v", err)
	}

	if !cert.IsCA {
		t.Error("Expected cert.IsCA = true")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse key: %v", err)
	}

	if err := key.Validate(); err != nil {
		t.Errorf("Failed to validate key: %v", err)
	}
}

func TestSetSigningCertKeyPairSecret_WithPKIConfigProvider(t *testing.T) {
	const certName = "openshift.io/test.signer"

	testCases := []struct {
		name string
		// policy is the PKI resource's certificates section; nil means no
		// PKI provider is wired.
		policy *configv1alpha1.PKICertificatePolicy
		want   configv1alpha1.PKIKeyConfig
	}{
		{
			name:   "no PKI configured uses legacy RSA-2048",
			policy: nil,
			want:   rsaKey(2048),
		},
		{
			name: "defaults apply without a CA override",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: rsaKey(3072)},
			},
			want: rsaKey(3072),
		},
		{
			name: "ECDSA-P256 CA override",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults:       configv1alpha1.PKIDefaultCertificateConfig{Key: rsaKey(2048)},
				CACertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP256)},
			},
			want: ecdsaKey(configv1alpha1.PKIECDSACurveP256),
		},
		{
			name: "ECDSA-P384 CA override",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults:       configv1alpha1.PKIDefaultCertificateConfig{Key: rsaKey(2048)},
				CACertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP384)},
			},
			want: ecdsaKey(configv1alpha1.PKIECDSACurveP384),
		},
		{
			name: "ECDSA-P521 CA override",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults:       configv1alpha1.PKIDefaultCertificateConfig{Key: rsaKey(2048)},
				CACertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP521)},
			},
			want: ecdsaKey(configv1alpha1.PKIECDSACurveP521),
		},
		{
			name: "RSA-2048 CA override",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults:       configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP256)},
				CACertificates: configv1alpha1.PKICertificateConfig{Key: rsaKey(2048)},
			},
			want: rsaKey(2048),
		},
		{
			name: "RSA-3072 CA override",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults:       configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP256)},
				CACertificates: configv1alpha1.PKICertificateConfig{Key: rsaKey(3072)},
			},
			want: rsaKey(3072),
		},
		{
			name: "RSA-4096 CA override",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults:       configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP256)},
				CACertificates: configv1alpha1.PKICertificateConfig{Key: rsaKey(4096)},
			},
			want: rsaKey(4096),
		},
		{
			name: "named ECDSA override wins over RSA CA override",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults:          configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP256)},
				CACertificates:    configv1alpha1.PKICertificateConfig{Key: rsaKey(3072)},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{namedCertificate(certName, ecdsaKey(configv1alpha1.PKIECDSACurveP521))},
			},
			want: ecdsaKey(configv1alpha1.PKIECDSACurveP521),
		},
		{
			name: "named RSA override wins over ECDSA CA override",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults:          configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP256)},
				CACertificates:    configv1alpha1.PKICertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP384)},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{namedCertificate(certName, rsaKey(4096))},
			},
			want: rsaKey(4096),
		},
		{
			name: "named override for another certificate is ignored",
			policy: &configv1alpha1.PKICertificatePolicy{
				Defaults:          configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP256)},
				CACertificates:    configv1alpha1.PKICertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP384)},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{namedCertificate("openshift.io/other.signer", rsaKey(2048))},
			},
			want: ecdsaKey(configv1alpha1.PKIECDSACurveP384),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "test-signer"},
			}

			c := RotatedSigningCASecret{
				Validity:        24 * time.Hour,
				CertificateName: certName,
			}
			if tc.policy != nil {
				c.PKIConfigProvider = pki.NewStaticConfigProvider(configv1alpha1.PKISpec{
					Certificates: *tc.policy,
				})
			}

			ca, err := c.setSigningCertKeyPairSecret(secret)
			if err != nil {
				t.Fatalf("setSigningCertKeyPairSecret() error = %v", err)
			}
			if ca == nil {
				t.Fatal("expected non-nil CA config")
			}
			if len(secret.Data["tls.crt"]) == 0 {
				t.Error("tls.crt is empty")
			}
			if len(secret.Data["tls.key"]) == 0 {
				t.Error("tls.key is empty")
			}

			cert := ca.Certs[0]
			if !cert.IsCA {
				t.Error("expected IsCA to be true")
			}
			assertPublicKeyMatches(t, cert.PublicKey, tc.want)
		})
	}
}

// errorConfigProvider is a pki.ConfigProvider that always returns an error.
type errorConfigProvider struct {
	err error
}

func (p *errorConfigProvider) Config() (configv1alpha1.PKISpec, error) {
	return configv1alpha1.PKISpec{}, p.err
}

func TestSetSigningCertKeyPairSecret_MissingPKIResource(t *testing.T) {
	t.Run("create path", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		client := kubefake.NewClientset()
		recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))

		c := &RotatedSigningCASecret{
			Namespace:       "ns",
			Name:            "signer",
			Validity:        24 * time.Hour,
			Refresh:         12 * time.Hour,
			Client:          client.CoreV1(),
			Lister:          corev1listers.NewSecretLister(indexer),
			EventRecorder:   recorder,
			CertificateName: "openshift.io/test.signer",
			// A wired provider whose resource is missing must fail the sync; it
			// must not fall back to legacy generation.
			PKIConfigProvider: &errorConfigProvider{
				err: apierrors.NewNotFound(schema.GroupResource{Group: "config.openshift.io", Resource: "pkis"}, "cluster"),
			},
		}

		_, _, err := c.EnsureSigningCertKeyPair(t.Context())
		if err == nil {
			t.Fatal("expected error for missing PKI resource")
		}
		if !apierrors.IsNotFound(err) {
			t.Errorf("expected apierrors.IsNotFound to match, got %v", err)
		}

		// No secret may be written: a fallback to legacy generation would have
		// created one.
		actions := client.Actions()
		if len(actions) != 0 {
			t.Errorf("expected no client actions, got %v", actions)
		}
	})

	t.Run("rotate path", func(t *testing.T) {
		// The bubble's fake clock lets the test move past the refresh time
		// deterministically instead of relying on wall-clock time passing.
		synctest.Test(t, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			client := kubefake.NewClientset()
			recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))

			c := &RotatedSigningCASecret{
				Namespace:       "ns",
				Name:            "signer",
				Validity:        24 * time.Hour,
				Refresh:         12 * time.Hour,
				Client:          client.CoreV1(),
				Lister:          corev1listers.NewSecretLister(indexer),
				EventRecorder:   recorder,
				CertificateName: "openshift.io/test.signer",
				PKIConfigProvider: pki.NewStaticConfigProvider(configv1alpha1.PKISpec{
					Certificates: testCertificatePolicy(),
				}),
			}

			if _, _, err := c.EnsureSigningCertKeyPair(t.Context()); err != nil {
				t.Fatalf("initial EnsureSigningCertKeyPair() error = %v", err)
			}
			createActions := len(client.Actions())
			if createActions != 1 {
				t.Fatalf("expected 1 create action after initial ensure, got %d", createActions)
			}

			// The fake client does not feed the lister's indexer; add the
			// created secret as a synced informer would, so the next sync
			// takes the rotation path rather than the creation path.
			created, err := client.CoreV1().Secrets("ns").Get(t.Context(), "signer", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := indexer.Add(created); err != nil {
				t.Fatal(err)
			}
			baselineActions := len(client.Actions())

			// Move past Refresh (12h) but not the 80% threshold (19.2h), so
			// rotation is due only because of the configured refresh.
			time.Sleep(13 * time.Hour)

			// Swap in a provider whose resource is missing: the rotation due
			// on this sync must fail without updating the existing valid
			// secret.
			c.PKIConfigProvider = &errorConfigProvider{
				err: apierrors.NewNotFound(schema.GroupResource{Group: "config.openshift.io", Resource: "pkis"}, "cluster"),
			}
			_, _, err = c.EnsureSigningCertKeyPair(t.Context())
			if err == nil {
				t.Fatal("expected error for missing PKI resource during rotation")
			}
			if !apierrors.IsNotFound(err) {
				t.Errorf("expected apierrors.IsNotFound to match, got %v", err)
			}
			if actions := client.Actions(); len(actions) != baselineActions {
				t.Errorf("expected no additional client actions during failed rotation, got %v", actions[baselineActions:])
			}

			// Guard against the sync silently taking the creation path.
			var sawRefresh bool
			for _, e := range recorder.Events() {
				if e.Reason == "SignerUpdateRequired" && strings.Contains(e.Message, "past its refresh time") {
					sawRefresh = true
				}
			}
			if !sawRefresh {
				t.Errorf("expected a SignerUpdateRequired event for the refresh time, got %v", recorder.Events())
			}
		})
	})
}

func TestEnsureSigningCertKeyPair_WithKeyConfig(t *testing.T) {
	policy := testCertificatePolicy()

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewClientset()
	recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))

	c := &RotatedSigningCASecret{
		Namespace:       "ns",
		Name:            "signer",
		Validity:        24 * time.Hour,
		Refresh:         12 * time.Hour,
		Client:          client.CoreV1(),
		Lister:          corev1listers.NewSecretLister(indexer),
		EventRecorder:   recorder,
		CertificateName: "openshift.io/test.signer",
		PKIConfigProvider: pki.NewStaticConfigProvider(configv1alpha1.PKISpec{
			Certificates: policy,
		}),
		Owner: &metav1.OwnerReference{Name: "operator"},
		AdditionalAnnotations: AdditionalAnnotations{
			JiraComponent: "test",
		},
	}

	ca, updated, err := c.EnsureSigningCertKeyPair(t.Context())
	if err != nil {
		t.Fatalf("EnsureSigningCertKeyPair() error = %v", err)
	}
	if !updated {
		t.Error("expected controller to report updated")
	}
	if ca == nil {
		t.Fatal("expected non-nil CA")
	}

	cert := ca.Config.Certs[0]
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA public key, got %v", cert.PublicKeyAlgorithm)
	}
	// testCertificatePolicy overrides CA certificates to ECDSA P-384;
	// assert the curve so the CA override is actually verified.
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", cert.PublicKey)
	}
	if publicKey.Curve != elliptic.P384() {
		t.Errorf("expected curve P-384, got %v", publicKey.Curve)
	}
	if !cert.IsCA {
		t.Error("expected IsCA to be true")
	}
}

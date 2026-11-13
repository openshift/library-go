package certrotation

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/api/annotations"
	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
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

func TestSetSigningCertKeyPairSecret_WithPKIProfile(t *testing.T) {
	testCases := []struct {
		name              string
		configurePKI      bool
		profileAlgorithm  string
		profileECDSACurve string
		wantAlg           x509.PublicKeyAlgorithm
	}{
		{
			name:         "no PKI configured uses legacy RSA-2048",
			configurePKI: false,
			wantAlg:      x509.RSA,
		},
		{
			name:              "ECDSA-P256 via profile",
			configurePKI:      true,
			profileAlgorithm:  "ECDSA",
			profileECDSACurve: "P256",
			wantAlg:           x509.ECDSA,
		},
		{
			name:              "ECDSA-P384 via profile",
			configurePKI:      true,
			profileAlgorithm:  "ECDSA",
			profileECDSACurve: "P384",
			wantAlg:           x509.ECDSA,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "test-signer"},
			}

			c := RotatedSigningCASecret{
				Validity:        24 * time.Hour,
				CertificateName: "test.signer",
			}
			if tc.configurePKI {
				profile := pki.DefaultPKIProfile()
				profile.SignerCertificates.Key.Algorithm = configv1alpha1.KeyAlgorithm(tc.profileAlgorithm)
				profile.SignerCertificates.Key.ECDSA.Curve = configv1alpha1.ECDSACurve(tc.profileECDSACurve)
				c.PKIProfileProvider = pki.NewStaticPKIProfileProvider(&profile)
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
			if cert.PublicKeyAlgorithm != tc.wantAlg {
				t.Errorf("expected %v public key, got %v", tc.wantAlg, cert.PublicKeyAlgorithm)
			}
		})
	}
}

func TestEnsureSigningCertKeyPair_WithKeyConfig(t *testing.T) {
	profile := pki.DefaultPKIProfile()

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewClientset()
	recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))

	c := &RotatedSigningCASecret{
		Namespace:          "ns",
		Name:               "signer",
		Validity:           24 * time.Hour,
		Refresh:            12 * time.Hour,
		Client:             client.CoreV1(),
		Lister:             corev1listers.NewSecretLister(indexer),
		EventRecorder:      recorder,
		CertificateName:    "test.signer",
		PKIProfileProvider: pki.NewStaticPKIProfileProvider(&profile),
		Owner:              &metav1.OwnerReference{Name: "operator"},
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
	if !cert.IsCA {
		t.Error("expected IsCA to be true")
	}
}

func TestEnsureSigningCertKeyPairRotatesWithFakeClock(t *testing.T) {
	newController := func(t *testing.T, fakeClock *clocktesting.FakeClock, indexer cache.Indexer, client *kubefake.Clientset) (*RotatedSigningCASecret, events.InMemoryRecorder) {
		t.Helper()
		recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(fakeClock.Now()))
		return &RotatedSigningCASecret{
			Namespace:     "ns",
			Name:          "signer",
			Validity:      24 * time.Hour,
			Refresh:       12 * time.Hour,
			Client:        client.CoreV1(),
			Lister:        corev1listers.NewSecretLister(indexer),
			EventRecorder: recorder,
			Clock:         fakeClock,
		}, recorder
	}

	// hasEvent reports whether any recorded event matches the reason and
	// contains the message substring.
	hasEvent := func(recorder events.InMemoryRecorder, reason, messageSubstr string) bool {
		for _, e := range recorder.Events() {
			if e.Reason == reason && strings.Contains(e.Message, messageSubstr) {
				return true
			}
		}
		return false
	}

	t.Run("rotate on 80 percent of validity", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		fakeClock := clocktesting.NewFakeClock(now)
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		client := kubefake.NewClientset()

		c, recorder := newController(t, fakeClock, indexer, client)
		if _, _, err := c.EnsureSigningCertKeyPair(t.Context()); err != nil {
			t.Fatal(err)
		}

		created, err := client.CoreV1().Secrets("ns").Get(t.Context(), "signer", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		indexer.Add(created)
		firstCert, err := crypto.GetCAFromBytes(created.Data["tls.crt"], created.Data["tls.key"])
		if err != nil {
			t.Fatal(err)
		}
		if !firstCert.Config.Certs[0].NotBefore.Equal(now.Add(-time.Second)) {
			t.Errorf("first NotBefore = %v, want %v (generation must use the fake clock)", firstCert.Config.Certs[0].NotBefore, now.Add(-time.Second))
		}

		// Advance past 80% of the 24h validity: rotation must trigger without real time passing.
		fakeClock.Step(20 * time.Hour)

		client.ClearActions()
		if _, _, err := c.EnsureSigningCertKeyPair(t.Context()); err != nil {
			t.Fatal(err)
		}

		actions := client.Actions()
		if len(actions) != 1 || !actions[0].Matches("update", "secrets") {
			t.Fatalf("expected one secret update action, got %s", spew.Sdump(actions))
		}
		updatedSecret := actions[0].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
		secondCert, err := crypto.GetCAFromBytes(updatedSecret.Data["tls.crt"], updatedSecret.Data["tls.key"])
		if err != nil {
			t.Fatal(err)
		}
		wantNotBefore := now.Add(20 * time.Hour).Add(-time.Second)
		if !secondCert.Config.Certs[0].NotBefore.Equal(wantNotBefore) {
			t.Errorf("rotated NotBefore = %v, want %v", secondCert.Config.Certs[0].NotBefore, wantNotBefore)
		}
		if bytes.Equal(firstCert.Config.Certs[0].Raw, secondCert.Config.Certs[0].Raw) {
			t.Error("expected a new signer certificate after advancing the clock")
		}
		// The 80% rule must be the trigger, not the Refresh rule (Refresh is
		// 12h and the step is 20h, so both thresholds are crossed).
		if !hasEvent(recorder, "SignerUpdateRequired", "past refresh time (80% of validity)") {
			t.Errorf("expected a SignerUpdateRequired event citing the 80%% rule, got %s", spew.Sdump(recorder.Events()))
		}
	})

	// Steady state must hold with the fake clock far from real time in both
	// directions: 30 days in the past catches rotation *decisions* reading
	// real time (real now is past the cert's NotAfter, so "already expired"
	// fires on every sync); 30 days in the future catches certificate
	// *generation* reading real time (the cert looks already expired on the
	// fake clock, so the controller re-rotates).
	offsetTestCases := []struct {
		name   string
		offset time.Duration
	}{
		{
			name:   "fake clock 30 days in the past",
			offset: -30 * 24 * time.Hour,
		},
		{
			name:   "fake clock 30 days in the future",
			offset: 30 * 24 * time.Hour,
		},
	}

	for _, tc := range offsetTestCases {
		t.Run("steady state, "+tc.name, func(t *testing.T) {
			fakeClock := clocktesting.NewFakeClock(time.Now().Add(tc.offset).Truncate(time.Second))
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			client := kubefake.NewClientset()

			c, _ := newController(t, fakeClock, indexer, client)
			if _, _, err := c.EnsureSigningCertKeyPair(t.Context()); err != nil {
				t.Fatal(err)
			}

			created, err := client.CoreV1().Secrets("ns").Get(t.Context(), "signer", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			indexer.Add(created)

			client.ClearActions()
			if _, _, err := c.EnsureSigningCertKeyPair(t.Context()); err != nil {
				t.Fatal(err)
			}
			if actions := client.Actions(); len(actions) != 0 {
				t.Fatalf("expected no client actions in steady state, got %s", spew.Sdump(actions))
			}
		})
	}
}

func TestEnsureSigningCertKeyPairPKIPathWithFakeClock(t *testing.T) {
	fixedTime := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Truncate(time.Second)
	fakeClock := clocktesting.NewFakeClock(fixedTime)

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewClientset()

	profile := pki.DefaultPKIProfile()
	c := &RotatedSigningCASecret{
		Namespace:          "ns",
		Name:               "signer",
		Validity:           24 * time.Hour,
		Refresh:            12 * time.Hour,
		CertificateName:    "test.signer",
		PKIProfileProvider: pki.NewStaticPKIProfileProvider(&profile),
		Client:             client.CoreV1(),
		Lister:             corev1listers.NewSecretLister(indexer),
		EventRecorder:      events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(fakeClock.Now())),
		Clock:              fakeClock,
	}

	signingCertKeyPair, _, err := c.EnsureSigningCertKeyPair(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !signingCertKeyPair.Config.Certs[0].NotBefore.Equal(fixedTime.Add(-time.Second)) {
		t.Errorf("NotBefore = %v, want %v (PKI path generation must use the fake clock)", signingCertKeyPair.Config.Certs[0].NotBefore, fixedTime.Add(-time.Second))
	}
}

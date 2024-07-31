package certrotation

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

func TestNeedNewTargetCertKeyPairForTime(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	elevenMinutesBeforeNow := time.Now().Add(-11 * time.Minute)
	elevenMinutesBeforeNowFn := func() time.Time { return elevenMinutesBeforeNow }
	nowCert, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: 200 * time.Minute}, nowFn)
	if err != nil {
		t.Fatal(err)
	}
	elevenMinutesBeforeNowCert, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: 200 * time.Minute}, elevenMinutesBeforeNowFn)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string

		annotations            map[string]string
		signerFn               func() (*crypto.CA, error)
		refresh                time.Duration
		refreshOnlyWhenExpired bool

		expected string
	}{
		{
			name: "from nothing",
			signerFn: func() (*crypto.CA, error) {
				return nowCert, nil
			},
			refresh:  50 * time.Minute,
			expected: "missing notAfter",
		},
		{
			name: "malformed",
			annotations: map[string]string{
				CertificateNotAfterAnnotation:  "malformed",
				CertificateNotBeforeAnnotation: now.Add(-45 * time.Minute).Format(time.RFC3339),
			},
			signerFn: func() (*crypto.CA, error) {
				return nowCert, nil
			},
			refresh:  50 * time.Minute,
			expected: `bad expiry: "malformed"`,
		},
		{
			name: "past midpoint and cert is ready",
			annotations: map[string]string{
				CertificateNotAfterAnnotation:  now.Add(45 * time.Minute).Format(time.RFC3339),
				CertificateNotBeforeAnnotation: now.Add(-45 * time.Minute).Format(time.RFC3339),
			},
			signerFn: func() (*crypto.CA, error) {
				return elevenMinutesBeforeNowCert, nil
			},
			refresh:  40 * time.Minute,
			expected: "past its refresh time",
		},
		{
			name: "past midpoint and cert is new",
			annotations: map[string]string{
				CertificateNotAfterAnnotation:  now.Add(45 * time.Minute).Format(time.RFC3339),
				CertificateNotBeforeAnnotation: now.Add(-45 * time.Minute).Format(time.RFC3339),
			},
			signerFn: func() (*crypto.CA, error) {
				return nowCert, nil
			},
			refresh:  40 * time.Minute,
			expected: "",
		},
		{
			name: "past refresh but not expired",
			annotations: map[string]string{
				CertificateNotAfterAnnotation:  now.Add(45 * time.Minute).Format(time.RFC3339),
				CertificateNotBeforeAnnotation: now.Add(-45 * time.Minute).Format(time.RFC3339),
			},
			signerFn: func() (*crypto.CA, error) {
				return nowCert, nil
			},
			refresh:                40 * time.Minute,
			refreshOnlyWhenExpired: true,
			expected:               "",
		},
		{
			name: "already expired",
			annotations: map[string]string{
				CertificateNotAfterAnnotation:  now.Add(-1 * time.Millisecond).Format(time.RFC3339),
				CertificateNotBeforeAnnotation: now.Add(-45 * time.Minute).Format(time.RFC3339),
			},
			signerFn: func() (*crypto.CA, error) {
				return nowCert, nil
			},
			refresh:                30 * time.Minute,
			refreshOnlyWhenExpired: true,
			expected:               "already expired",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer, err := test.signerFn()
			if err != nil {
				t.Fatal(err)
			}

			actual := needNewTargetCertKeyPairForTime(test.annotations, signer, test.refresh, test.refreshOnlyWhenExpired)
			if !strings.HasPrefix(actual, test.expected) {
				t.Errorf("expected %v, got %v", test.expected, actual)
			}
		})
	}
}

func TestEnsureTargetCertKeyPair(t *testing.T) {
	tests := []struct {
		name string

		initialSecretFn func() *corev1.Secret
		caFn            func() (*crypto.CA, error)

		verifyActions func(t *testing.T, updateOnly bool, client *kubefake.Clientset)
		expectedError string
	}{
		{
			name: "initial create",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialSecretFn: func() *corev1.Secret { return nil },
			verifyActions: func(t *testing.T, updateonly bool, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("create", "secrets") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
				if len(actual.Annotations) == 0 {
					t.Errorf("expected certificates to be annotated")
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
		{
			name: "update write",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialSecretFn: func() *corev1.Secret {
				caBundleSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "target-secret", ResourceVersion: "10"},
					Data:       map[string][]byte{},
					Type:       corev1.SecretTypeTLS,
				}
				return caBundleSecret
			},
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[1].Matches("update", "secrets") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if len(actual.Annotations) == 0 {
					t.Errorf("expected certificates to be annotated")
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				if actual.Annotations[CertificateHostnames] != "bar,foo" {
					t.Error(actual.Annotations[CertificateHostnames])
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
		{
			name: "update SecretTLSType secrets",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialSecretFn: func() *corev1.Secret {
				caBundleSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "target-secret", ResourceVersion: "10"},
					Data:       map[string][]byte{},
					Type:       "SecretTypeTLS",
				}
				return caBundleSecret
			},
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset) {
				lengthWant := 3
				if updateOnly {
					lengthWant = 2
				}
				actions := client.Actions()
				if len(actions) != lengthWant {
					t.Fatal(spew.Sdump(actions))
				}

				var idx int
				switch updateOnly {
				case true:
					idx = 1
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("update", "secrets") {
						t.Error(actions[1])
					}
				default:
					idx = 2
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("delete", "secrets") {
						t.Error(actions[1])
					}
					if !actions[2].Matches("create", "secrets") {
						t.Error(actions[2])
					}
				}

				actual := actions[idx].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if len(actual.Annotations) == 0 {
					t.Errorf("expected certificates to be annotated")
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if actual.Type != corev1.SecretTypeTLS {
					t.Errorf("expected secret type to be kubernetes.io/tls, got: %v", actual.Type)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				if actual.Annotations[CertificateHostnames] != "bar,foo" {
					t.Error(actual.Annotations[CertificateHostnames])
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
		{
			name: "recreate invalid secret type",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialSecretFn: func() *corev1.Secret {
				caBundleSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "target-secret", ResourceVersion: "10"},
					Type:       corev1.SecretTypeOpaque,
					Data:       map[string][]byte{"foo": {}, "bar": {}},
				}
				return caBundleSecret
			},
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset) {
				lengthWant := 3
				if updateOnly {
					lengthWant = 2
				}

				actions := client.Actions()
				if len(actions) != lengthWant {
					t.Fatal(spew.Sdump(actions))
				}

				var idx int
				switch updateOnly {
				case true:
					idx = 1
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("update", "secrets") {
						t.Error(actions[1])
					}
				default:
					idx = 2
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("delete", "secrets") {
						t.Error(actions[1])
					}
					if !actions[2].Matches("create", "secrets") {
						t.Error(actions[2])
					}
				}

				actual := actions[idx].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if len(actual.Annotations) == 0 {
					t.Errorf("expected certificates to be annotated")
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if actual.Type != corev1.SecretTypeTLS {
					t.Errorf("expected secret type to be kubernetes.io/tls, got: %v", actual.Type)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				if actual.Annotations[CertificateHostnames] != "bar,foo" {
					t.Error(actual.Annotations[CertificateHostnames])
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
	}

	for _, b := range []bool{true, false} {
		for _, test := range tests {
			t.Run(fmt.Sprintf("%s/update-only/%t", test.name, b), func(t *testing.T) {
				indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

				client := kubefake.NewSimpleClientset()
				if startingObj := test.initialSecretFn(); startingObj != nil {
					indexer.Add(startingObj)
					client = kubefake.NewSimpleClientset(startingObj)
				}

				c := &RotatedSelfSignedCertKeySecret{
					Namespace: "ns",
					Validity:  24 * time.Hour,
					Refresh:   12 * time.Hour,
					Name:      "target-secret",
					CertCreator: &ServingRotation{
						Hostnames: func() []string { return []string{"foo", "bar"} },
					},

					Client:        client.CoreV1(),
					Lister:        corev1listers.NewSecretLister(indexer),
					EventRecorder: events.NewInMemoryRecorder("test"),
					AdditionalAnnotations: AdditionalAnnotations{
						JiraComponent: "test",
					},
					Owner: &metav1.OwnerReference{
						Name: "operator",
					},
					UseSecretUpdateOnly: b,
				}

				newCA, err := test.caFn()
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.EnsureTargetCertKeyPair(context.TODO(), newCA, newCA.Config.Certs)
				switch {
				case err != nil && len(test.expectedError) == 0:
					t.Error(err)
				case err != nil && !strings.Contains(err.Error(), test.expectedError):
					t.Error(err)
				case err == nil && len(test.expectedError) != 0:
					t.Errorf("missing %q", test.expectedError)
				}

				test.verifyActions(t, b, client)
			})
		}
	}
}

func TestServerHostnameCheck(t *testing.T) {
	tests := []struct {
		name string

		existingHostnames string
		requiredHostnames []string

		expected string
	}{
		{
			name:              "nothing",
			existingHostnames: "",
			requiredHostnames: []string{"foo"},
			expected:          `"" are existing and not required, "foo" are required and not existing`,
		},
		{
			name:              "exists",
			existingHostnames: "foo",
			requiredHostnames: []string{"foo"},
			expected:          "",
		},
		{
			name:              "hasExtra",
			existingHostnames: "foo,bar",
			requiredHostnames: []string{"foo"},
			expected:          `"bar" are existing and not required, "" are required and not existing`,
		},
		{
			name:              "needsAnother",
			existingHostnames: "foo",
			requiredHostnames: []string{"foo", "bar"},
			expected:          `"" are existing and not required, "bar" are required and not existing`,
		},
		{
			name:              "both",
			existingHostnames: "foo,baz",
			requiredHostnames: []string{"foo", "bar"},
			expected:          `"baz" are existing and not required, "bar" are required and not existing`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := &ServingRotation{
				Hostnames: func() []string { return test.requiredHostnames },
			}
			actual := r.missingHostnames(map[string]string{CertificateHostnames: test.existingHostnames})
			if actual != test.expected {
				t.Fatal(actual)
			}
		})
	}
}

func TestEnsureTargetSignerCertKeyPair(t *testing.T) {
	tests := []struct {
		name string

		initialSecretFn func() *corev1.Secret
		caFn            func() (*crypto.CA, error)

		verifyActions func(t *testing.T, updateOnly bool, client *kubefake.Clientset)
		expectedError string
	}{
		{
			name: "initial create",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialSecretFn: func() *corev1.Secret { return nil },
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("create", "secrets") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}

				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeTarget {
					t.Errorf("expected certificate type 'target', got: %v", certType)
				}

				signingCertKeyPair, err := crypto.GetCAFromBytes(actual.Data["tls.crt"], actual.Data["tls.key"])
				if err != nil {
					t.Error(actual.Data)
				}
				if signingCertKeyPair.Config.Certs[0].Issuer.CommonName != "signer-tests" {
					t.Error(signingCertKeyPair.Config.Certs[0].Issuer.CommonName)

				}
				if signingCertKeyPair.Config.Certs[1].Subject.CommonName != "signer-tests" {
					t.Error(signingCertKeyPair.Config.Certs[0].Issuer.CommonName)
				}
			},
		},
		{
			name: "update write",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialSecretFn: func() *corev1.Secret {
				caBundleSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "target-secret"},
					Data:       map[string][]byte{},
					Type:       corev1.SecretTypeTLS,
				}
				return caBundleSecret
			},
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[1].Matches("update", "secrets") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeTarget {
					t.Errorf("expected certificate type 'target', got: %v", certType)
				}

				signingCertKeyPair, err := crypto.GetCAFromBytes(actual.Data["tls.crt"], actual.Data["tls.key"])
				if err != nil {
					t.Error(actual.Data)
				}
				if signingCertKeyPair.Config.Certs[0].Issuer.CommonName != "signer-tests" {
					t.Error(signingCertKeyPair.Config.Certs[0].Issuer.CommonName)

				}
				if signingCertKeyPair.Config.Certs[1].Subject.CommonName != "signer-tests" {
					t.Error(signingCertKeyPair.Config.Certs[0].Issuer.CommonName)
				}
			},
		},
	}

	for _, b := range []bool{true, false} {
		for _, test := range tests {
			t.Run(fmt.Sprintf("%s/update-only/%t", test.name, b), func(t *testing.T) {
				indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

				client := kubefake.NewSimpleClientset()
				if startingObj := test.initialSecretFn(); startingObj != nil {
					indexer.Add(startingObj)
					client = kubefake.NewSimpleClientset(startingObj)
				}

				c := &RotatedSelfSignedCertKeySecret{
					Namespace: "ns",
					Validity:  24 * time.Hour,
					Refresh:   12 * time.Hour,
					Name:      "target-secret",
					CertCreator: &SignerRotation{
						SignerName: "lower-signer",
					},

					Client:              client.CoreV1(),
					Lister:              corev1listers.NewSecretLister(indexer),
					EventRecorder:       events.NewInMemoryRecorder("test"),
					UseSecretUpdateOnly: b,
				}

				newCA, err := test.caFn()
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.EnsureTargetCertKeyPair(context.TODO(), newCA, newCA.Config.Certs)
				switch {
				case err != nil && len(test.expectedError) == 0:
					t.Error(err)
				case err != nil && !strings.Contains(err.Error(), test.expectedError):
					t.Error(err)
				case err == nil && len(test.expectedError) != 0:
					t.Errorf("missing %q", test.expectedError)
				}

				test.verifyActions(t, b, client)
			})
		}
	}
}

// A simplified test scenario for a race condition when multiple CertRotationControllers
// are used with the same SignerSecret (CA) and CABundleConfigMap.
//
// Let's assume there are two target controllers (firstCertController and secondCertController).
// The specific implementation details of these controllers are not defined in this test.
//
// During the recovery process, when the Signer is expired, the following sequence of events can occur:
//
// 1. firstCertController regenerates the signer (firstSignerSecret).
//
// 2. secondCertController regenerates the signer (secondSignerSecret) because it hasn't observed the change from step 1.
//
// 3. firstCertController regenerates the client cert and signs it with the firstSignerSecret.
//
// 4. secondCertController regenerates the client cert and signs it with the secondSignerSecret.
//
// At this point, we have client certs signed with two different signers (different keys) but with the same CommonName.
//
//  5. Since secondCertController persisted its signer last (the secondSignerSecret is stored in the shared secret), at some point,
//     the firstCertController gets triggered BUT it will NOT regenerate the client cert BECAUSE
//     the CommonName (from the firstSignerSecret) matches the one from secondSignerSecret.
func TestEnsureTargetCertKeyPairSignerCommonName(t *testing.T) {
	// firstSignerSecret would be generated by the firstCertController
	firstSignerSecret := &corev1.Secret{}
	require.NoError(t, setSigningCertKeyPairSecret(firstSignerSecret, time.Hour))

	// the secondSignerSecret would be generated by the secondCertController
	secondSignerSecret := &corev1.Secret{}
	require.NoError(t, setSigningCertKeyPairSecret(secondSignerSecret, time.Hour))

	firstSecretCommonName := firstSignerSecret.Annotations[CertificateIssuer]
	secondSecretCommonName := secondSignerSecret.Annotations[CertificateIssuer]
	require.Equal(t, firstSecretCommonName, secondSecretCommonName)

	firstSigner, err := crypto.GetCAFromBytes(firstSignerSecret.Data["tls.crt"], firstSignerSecret.Data["tls.key"])
	require.NoError(t, err)
	secondSigner, err := crypto.GetCAFromBytes(secondSignerSecret.Data["tls.crt"], secondSignerSecret.Data["tls.key"])
	require.NoError(t, err)

	fakeKubeClient := kubefake.NewSimpleClientset()
	coreV1Indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	// firstClientCertificate managed by firstCertController
	firstClientCertificate := RotatedSelfSignedCertKeySecret{
		Namespace: "ns",
		Name:      "first-client-secret",
		Validity:  24 * time.Hour,
		Refresh:   12 * time.Hour,
		CertCreator: &ClientRotation{
			UserInfo: &user.DefaultInfo{Name: "system:kube-controller-manager"},
		},

		Client:        fakeKubeClient.CoreV1(),
		Lister:        corev1listers.NewSecretLister(coreV1Indexer),
		EventRecorder: events.NewInMemoryRecorder("test"),
	}

	// normally, we would have secondClientCertificate managed by secondCertController,
	// but it is not needed to show the issue

	// normally, firstCertController would call EnsureTargetCertKeyPair
	firstClientCertResult, err := firstClientCertificate.EnsureTargetCertKeyPair(context.TODO(), firstSigner, []*x509.Certificate{firstSigner.Config.Certs[0]})
	require.NoError(t, err)
	coreV1Indexer.Add(firstClientCertResult)

	// since the secondCertController won, eventually secondSignerSecret should be used
	// to regenerate the firstClientCertificate but because the CommonName is exactly the same, but it isn't
	firstClientCertSecondResult, err := firstClientCertificate.EnsureTargetCertKeyPair(context.TODO(), secondSigner, []*x509.Certificate{secondSigner.Config.Certs[0]})
	require.NoError(t, err)

	// the firstClientCertSecondResult should be signed with the secondSignerSecret
	require.NotEqual(t, firstClientCertResult, firstClientCertSecondResult)
}

// TestCABundleWithMultipleSigners shows that a CABundle can miss a CAs
func TestCABundleWithMultipleSigners(t *testing.T) {
	firstSignerSecret := &corev1.Secret{}
	require.NoError(t, setSigningCertKeyPairSecret(firstSignerSecret, time.Hour))
	secondSignerSecret := &corev1.Secret{}
	require.NoError(t, setSigningCertKeyPairSecret(secondSignerSecret, time.Hour))

	firstSecretCommonName := firstSignerSecret.Annotations[CertificateIssuer]
	secondSecretCommonName := secondSignerSecret.Annotations[CertificateIssuer]
	require.Equal(t, firstSecretCommonName, secondSecretCommonName)

	firstSigner, err := crypto.GetCAFromBytes(firstSignerSecret.Data["tls.crt"], firstSignerSecret.Data["tls.key"])
	require.NoError(t, err)
	secondSigner, err := crypto.GetCAFromBytes(secondSignerSecret.Data["tls.crt"], secondSignerSecret.Data["tls.key"])
	require.NoError(t, err)

	fakeKubeClient := kubefake.NewSimpleClientset()
	coreV1Indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	target := CABundleConfigMap{
		Namespace:     "ns",
		Name:          "trust-bundle",
		Client:        fakeKubeClient.CoreV1(),
		Lister:        corev1listers.NewConfigMapLister(coreV1Indexer),
		EventRecorder: events.NewInMemoryRecorder("test"),
	}

	expectedCertificates := []*x509.Certificate{}

	res, err := target.EnsureConfigMapCABundle(context.TODO(), firstSigner)
	require.NoError(t, err)
	_, err = fakeKubeClient.CoreV1().ConfigMaps("ns").Get(context.Background(), "trust-bundle", metav1.GetOptions{})
	require.NoError(t, err)
	// by not adding the caBundleConfigMap
	// to the lister, we simulate the race condition
	// that causes overwriting of the CM and
	// dropping the firstSigner
	//
	// nevertheless, let's add the secondSigner to our expectedCertificates
	expectedCertificates = append(expectedCertificates, firstSigner.Config.Certs[0])
	require.Equal(t, expectedCertificates, res)

	res, err = target.EnsureConfigMapCABundle(context.TODO(), secondSigner)
	require.NoError(t, err)
	expectedCertificates = append(expectedCertificates, secondSigner.Config.Certs[0])
	sort.SliceStable(expectedCertificates, func(i, j int) bool {
		return bytes.Compare(expectedCertificates[i].Raw, expectedCertificates[j].Raw) < 0
	})
	require.Equal(t, expectedCertificates, res)
}

// TestCABundleWithMultipleSignersThree shows that a CABundle can miss a CAs
func TestCABundleWithMultipleSignersThree(t *testing.T) {
	firstSignerSecret := &corev1.Secret{}
	require.NoError(t, setSigningCertKeyPairSecret(firstSignerSecret, time.Hour))
	secondSignerSecret := &corev1.Secret{}
	require.NoError(t, setSigningCertKeyPairSecret(secondSignerSecret, time.Hour))
	thirdSignerSecret := &corev1.Secret{}
	require.NoError(t, setSigningCertKeyPairSecret(thirdSignerSecret, time.Hour))

	firstSecretCommonName := firstSignerSecret.Annotations[CertificateIssuer]
	secondSecretCommonName := secondSignerSecret.Annotations[CertificateIssuer]
	thirdSecretCommonName := thirdSignerSecret.Annotations[CertificateIssuer]
	require.Equal(t, firstSecretCommonName, secondSecretCommonName, thirdSecretCommonName)

	firstSigner, err := crypto.GetCAFromBytes(firstSignerSecret.Data["tls.crt"], firstSignerSecret.Data["tls.key"])
	require.NoError(t, err)
	secondSigner, err := crypto.GetCAFromBytes(secondSignerSecret.Data["tls.crt"], secondSignerSecret.Data["tls.key"])
	require.NoError(t, err)
	thirdSigner, err := crypto.GetCAFromBytes(thirdSignerSecret.Data["tls.crt"], thirdSignerSecret.Data["tls.key"])
	require.NoError(t, err)

	fakeKubeClient := kubefake.NewSimpleClientset()
	coreV1Indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	target := CABundleConfigMap{
		Namespace:     "ns",
		Name:          "trust-bundle",
		Client:        fakeKubeClient.CoreV1(),
		Lister:        corev1listers.NewConfigMapLister(coreV1Indexer),
		EventRecorder: events.NewInMemoryRecorder("test"),
	}

	expectedCertificates := []*x509.Certificate{firstSigner.Config.Certs[0]}
	res, err := target.EnsureConfigMapCABundle(context.TODO(), firstSigner)
	require.NoError(t, err)
	require.Equal(t, expectedCertificates, res)
	caBundleConfigMap, err := fakeKubeClient.CoreV1().ConfigMaps("ns").Get(context.Background(), "trust-bundle", metav1.GetOptions{})
	require.NoError(t, err)
	coreV1Indexer.Add(caBundleConfigMap)

	res, err = target.EnsureConfigMapCABundle(context.TODO(), secondSigner)
	require.NoError(t, err)
	// by not adding the raBundleConfigMap
	// to the lister, we simulate the race condition
	// that causes overwriting of the CM
	//
	// nevertheless, let's add the secondSigner to our expectedCertificates
	expectedCertificates = append(expectedCertificates, secondSigner.Config.Certs[0])
	sort.SliceStable(expectedCertificates, func(i, j int) bool {
		return bytes.Compare(expectedCertificates[i].Raw, expectedCertificates[j].Raw) < 0
	})
	require.Equal(t, expectedCertificates, res)

	res, err = target.EnsureConfigMapCABundle(context.TODO(), thirdSigner)
	require.NoError(t, err)
	expectedCertificates = append(expectedCertificates, thirdSigner.Config.Certs[0])
	sort.SliceStable(expectedCertificates, func(i, j int) bool {
		return bytes.Compare(expectedCertificates[i].Raw, expectedCertificates[j].Raw) < 0
	})
	require.Equal(t, expectedCertificates, res)
}

func TestRotatedSigningCASecretSameCommonName(t *testing.T) {
	fakeKubeClient := kubefake.NewSimpleClientset()
	coreV1Indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	target := RotatedSigningCASecret{
		Namespace:     "ns",
		Name:          "signer",
		Validity:      24 * time.Hour,
		Refresh:       12 * time.Hour,
		Client:        fakeKubeClient.CoreV1(),
		Lister:        corev1listers.NewSecretLister(coreV1Indexer),
		EventRecorder: events.NewInMemoryRecorder("test"),
	}

	firstSigner, signerUpdated, err := target.EnsureSigningCertKeyPair(context.TODO())
	require.NoError(t, err)
	require.True(t, signerUpdated)

	secondSigner, signerUpdated, err := target.EnsureSigningCertKeyPair(context.TODO())
	require.NoError(t, err)
	require.True(t, signerUpdated)

	firstSecretCommonName := firstSigner.Config.Certs[0].Subject.CommonName
	secondSecretCommonName := secondSigner.Config.Certs[0].Subject.CommonName
	require.NotEqual(t, firstSecretCommonName, secondSecretCommonName)
}

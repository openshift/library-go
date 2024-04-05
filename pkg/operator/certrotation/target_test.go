package certrotation

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

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
				lengthWant := 5
				if updateOnly {
					lengthWant = 4
				}
				actions := client.Actions()
				if len(actions) != lengthWant {
					t.Fatal(spew.Sdump(actions))
				}

				var idx int
				switch updateOnly {
				case true:
					idx = 3
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("update", "secrets") {
						t.Error(actions[1])
					}
					if !actions[2].Matches("get", "secrets") {
						t.Error(actions[2])
					}
					if !actions[3].Matches("update", "secrets") {
						t.Error(actions[3])
					}
				default:
					idx = 4
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("delete", "secrets") {
						t.Error(actions[1])
					}
					if !actions[2].Matches("create", "secrets") {
						t.Error(actions[2])
					}
					if !actions[3].Matches("get", "secrets") {
						t.Error(actions[3])
					}
					if !actions[4].Matches("update", "secrets") {
						t.Error(actions[4])
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
				lengthWant := 5
				if updateOnly {
					lengthWant = 4
				}

				actions := client.Actions()
				if len(actions) != lengthWant {
					t.Fatal(spew.Sdump(actions))
				}

				var idx int
				switch updateOnly {
				case true:
					idx = 3
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("update", "secrets") {
						t.Error(actions[1])
					}
					if !actions[2].Matches("get", "secrets") {
						t.Error(actions[2])
					}
					if !actions[3].Matches("update", "secrets") {
						t.Error(actions[3])
					}
				default:
					idx = 4
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("delete", "secrets") {
						t.Error(actions[1])
					}
					if !actions[2].Matches("create", "secrets") {
						t.Error(actions[2])
					}
					if !actions[3].Matches("get", "secrets") {
						t.Error(actions[3])
					}
					if !actions[4].Matches("update", "secrets") {
						t.Error(actions[4])
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

func FuzzEnsureTargetCertKeyPair(f *testing.F) {
	const (
		WorkerCount                 = 3
		SecretNamespace, SecretName = "ns", "test-target"
	)
	// represents a secret that was created before 4.7 and
	// hasn't been updated until now (upgrade to 4.15)
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       SecretNamespace,
			Name:            SecretName,
			ResourceVersion: "10",
		},
		Type: "SecretTypeTLS",
		Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
	}
	newCA, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
	if err != nil {
		f.Fatal(err)
	}
	certCreator := &SignerRotation{
		SignerName: "lower-signer",
	}
	additionalAnnotations := AdditionalAnnotations{JiraComponent: "test"}
	if err := setTargetCertKeyPairSecret(existing, 24*time.Hour, newCA, certCreator, additionalAnnotations); err != nil {
		f.Fatal(err)
	}
	// give it a second so we have a unique target name,
	// and also unique not-after, and not-before values
	<-time.After(2 * time.Second)

	for _, b := range []bool{true, false} {
		f.Add(int64(1), b)
	}

	f.Fuzz(func(t *testing.T, seed int64, useSecretUpdateOnly bool) {
		t.Logf("seed: %v, useSecretUpdateOnly: %v", seed, useSecretUpdateOnly)
		d := &dispatcher{
			t:        t,
			source:   rand.NewSource(seed),
			requests: make(chan request, WorkerCount),
		}
		go d.Run()
		defer d.Stop()

		existing = existing.DeepCopy()

		// get the original crt and key bytes to compare later
		tlsCertWant, ok := existing.Data["tls.crt"]
		if !ok || len(tlsCertWant) == 0 {
			t.Fatalf("missing data in 'tls.crt' key of Data: %#v", existing.Data)
		}
		tlsKeyWant, ok := existing.Data["tls.key"]
		if !ok || len(tlsKeyWant) == 0 {
			t.Fatalf("missing data in 'tls.key' key of Data: %#v", existing.Data)
		}

		secretWant := existing.DeepCopy()

		clientset := kubefake.NewSimpleClientset(existing)

		options := events.RecommendedClusterSingletonCorrelatorOptions()
		client := clientset.CoreV1().Secrets(SecretNamespace)

		var wg sync.WaitGroup
		for i := 1; i <= WorkerCount; i++ {
			controllerName := fmt.Sprintf("controller-%d", i)
			wg.Add(1)
			d.Join(controllerName)

			go func(controllerName string) {
				defer func() {
					d.Leave(controllerName)
					wg.Done()
				}()

				recorder := events.NewKubeRecorderWithOptions(clientset.CoreV1().Events(SecretNamespace), options, "operator", &corev1.ObjectReference{Name: controllerName, Namespace: SecretNamespace})
				wrapped := &secretwrapped{SecretInterface: client, name: controllerName, t: t, d: d}
				getter := &secretgetter{w: wrapped}
				ctrl := &RotatedSelfSignedCertKeySecret{
					Namespace:   SecretNamespace,
					Name:        SecretName,
					Validity:    24 * time.Hour,
					Refresh:     12 * time.Hour,
					Client:      getter,
					CertCreator: certCreator,
					Lister: &fakeSecretLister{
						who:        controllerName,
						dispatcher: d,
						tracker:    clientset.Tracker(),
					},
					AdditionalAnnotations: additionalAnnotations,
					Owner:                 &metav1.OwnerReference{Name: "operator"},
					EventRecorder:         recorder,
					UseSecretUpdateOnly:   useSecretUpdateOnly,
				}

				d.Sequence(controllerName, "begin")
				_, err := ctrl.EnsureTargetCertKeyPair(context.TODO(), newCA, newCA.Config.Certs)
				if err != nil {
					t.Logf("error from %s: %v", controllerName, err)
				}
			}(controllerName)
		}

		wg.Wait()
		t.Log("controllers done")
		// controllers are done, we don't expect the target to change
		secretGot, err := client.Get(context.TODO(), SecretName, metav1.GetOptions{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if tlsCertGot, ok := secretGot.Data["tls.crt"]; !ok || !bytes.Equal(tlsCertWant, tlsCertGot) {
			t.Errorf("the target cert has mutated unexpectedly")
		}
		if tlsKeyGot, ok := secretGot.Data["tls.key"]; !ok || !bytes.Equal(tlsKeyWant, tlsKeyGot) {
			t.Errorf("the target cert has mutated unexpectedly")
		}
		if got, exists := secretGot.Annotations["openshift.io/owning-component"]; !exists || got != "test" {
			t.Errorf("owner annotation is missing: %#v", secretGot.Annotations)
		}
		t.Logf("diff: %s", cmp.Diff(secretWant, secretGot))
	})
}

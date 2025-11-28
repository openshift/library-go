package certrotation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestEnsureSigningCertKeyPair(t *testing.T) {
	const (
		namespace  = "ns"
		secretName = "signer"
		validity   = 24 * time.Hour
		refresh    = 12 * time.Hour

		jiraComponent = "test"
		ownerName     = "operator"
	)

	now := time.Now().UTC()

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

	verifySecret := func(t *testing.T, actual *corev1.Secret, isUpdate bool) {
		t.Helper()

		if actual.Data == nil {
			t.Fatalf("Expected secret data to be set")
		}

		issuer := fmt.Sprintf("%s_%s@%d", namespace, secretName, now.Unix())
		notBefore := now.Add(-1 * time.Second).Truncate(time.Second)
		notAfter := now.Add(validity).Truncate(time.Second)

		verifyKeyPair(t, actual.Data["tls.crt"], actual.Data["tls.key"], issuer, notBefore, notAfter)
		actual.Data = nil

		if revision := actual.ObjectMeta.ResourceVersion; isUpdate != (len(revision) != 0) {
			t.Errorf("Expected resource version to be set: %v, got %q", isUpdate, revision)
		}
		actual.ObjectMeta.ResourceVersion = ""

		expected := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      secretName,
				Labels: map[string]string{
					"auth.openshift.io/managed-certificate-type": "signer",
				},
				Annotations: map[string]string{
					"auth.openshift.io/certificate-issuer":     issuer,
					"auth.openshift.io/certificate-not-before": notBefore.Format(time.RFC3339),
					"auth.openshift.io/certificate-not-after":  notAfter.Format(time.RFC3339),
					"certificates.openshift.io/refresh-period": refresh.String(),
					"openshift.io/owning-component":            jiraComponent,
				},
				OwnerReferences: []metav1.OwnerReference{
					{Name: ownerName},
				},
			},
			Type: corev1.SecretTypeTLS,
		}

		if !cmp.Equal(actual, &expected) {
			t.Errorf("Secret object mismatch (+want -got):\n%s", cmp.Diff(&expected, actual))
		}
	}

	tests := []struct {
		name string

		initialSecret          *corev1.Secret
		RefreshOnlyWhenExpired bool

		verifyResult  func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool)
		expectedError string
	}{
		{
			name:                   "initial create",
			RefreshOnlyWhenExpired: false,
			verifyResult: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				t.Helper()

				actions := client.Actions()
				verifyActionsOnCreated(t, actions)
				verifyControllerUpdatedSecret(t, true, controllerUpdatedSecret)

				verifySecret(t, actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret), false)
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
				t.Helper()

				actions := client.Actions()
				verifyActionsOnUpdated(t, actions)
				verifyControllerUpdatedSecret(t, true, controllerUpdatedSecret)

				verifySecret(t, actions[0].(clienttesting.UpdateAction).GetObject().(*corev1.Secret), true)
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

			c := &RotatedSigningCASecret{
				Namespace:     namespace,
				Name:          secretName,
				Validity:      validity,
				Refresh:       refresh,
				Client:        client.CoreV1(),
				Lister:        corev1listers.NewSecretLister(indexer),
				EventRecorder: events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now())),
				Clock:         clocktesting.NewFakeClock(now),
				AdditionalAnnotations: AdditionalAnnotations{
					JiraComponent: jiraComponent,
				},
				Owner: &metav1.OwnerReference{
					Name: ownerName,
				},
				RefreshOnlyWhenExpired: test.RefreshOnlyWhenExpired,
			}

			_, updated, err := c.EnsureSigningCertKeyPair(context.TODO())
			switch {
			case err != nil && len(test.expectedError) == 0:
				t.Error(err)
			case err != nil && !strings.Contains(err.Error(), test.expectedError):
				t.Error(err)
			case err == nil && len(test.expectedError) != 0:
				t.Errorf("missing %q", test.expectedError)
			}

			test.verifyResult(t, client, updated)
		})
	}
}

func verifyKeyPair(t testing.TB, certPEM, keyPEM []byte, issuer string, notBefore, notAfter time.Time) {
	t.Helper()

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse cert: %v", err)
	}

	if cert.Issuer.CommonName != issuer {
		t.Errorf("cert.Issuer.CommonName = %q, want %q", cert.Issuer.CommonName, issuer)
	}
	if cert.Subject.CommonName != issuer {
		t.Errorf("cert.Subject.CommonName = %q, want %q", cert.Subject.CommonName, issuer)
	}
	if !cert.IsCA {
		t.Error("Expected cert.IsCA = true")
	}

	if cert.NotBefore != notBefore {
		t.Errorf("cert.NotBefore = %v, want %v", cert.NotBefore, notBefore)
	}
	if cert.NotAfter != notAfter {
		t.Errorf("cert.NotAfter = %v, want %v", cert.NotAfter, notAfter)
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

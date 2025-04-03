package certrotation

import (
	"context"
	gcrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	"k8s.io/client-go/util/cert"

	"github.com/davecgh/go-spew/spew"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

func TestEnsureConfigMapCABundle(t *testing.T) {
	certs, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string

		initialConfigMapFn     func() *corev1.ConfigMap
		caFn                   func() (*crypto.CA, error)
		RefreshOnlyWhenExpired bool

		verifyActions func(t *testing.T, client *kubefake.Clientset)
		expectedError string
	}{
		{
			name: "initial create",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialConfigMapFn:     func() *corev1.ConfigMap { return nil },
			RefreshOnlyWhenExpired: false,
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("create", "configmaps") {
					t.Error(actions[0])
				}

				actual := actions[0].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeCABundle {
					t.Errorf("expected certificate type 'ca-bundle', got: %v", certType)
				}
				if len(actual.Data["ca-bundle.crt"]) == 0 {
					t.Error(actual.Data)
				}
			},
		},
		{
			name: "update keep both",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialConfigMapFn: func() *corev1.ConfigMap {
				caBundleConfigMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "trust-bundle", ResourceVersion: "10"},
					Data:       map[string]string{},
				}
				certs, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				caBytes, err := crypto.EncodeCertificates(certs.Config.Certs...)
				if err != nil {
					t.Fatal(err)
				}
				caBundleConfigMap.Data["ca-bundle.crt"] = string(caBytes)
				return caBundleConfigMap
			},
			RefreshOnlyWhenExpired: false,
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("update", "configmaps") {
					t.Error(actions[0])
				}

				actual := actions[0].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if len(actual.Data["ca-bundle.crt"]) == 0 {
					t.Error(actual.Data)
				}
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeCABundle {
					t.Errorf("expected certificate type 'ca-bundle', got: %v", certType)
				}
				result, err := cert.ParseCertsPEM([]byte(actual.Data["ca-bundle.crt"]))
				if err != nil {
					t.Fatal(err)
				}
				if len(result) != 2 {
					t.Error(len(result))
				}
			},
		},
		{
			name: "update remove old",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			RefreshOnlyWhenExpired: false,
			initialConfigMapFn: func() *corev1.ConfigMap {
				caBundleConfigMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "trust-bundle", ResourceVersion: "10"},
					Data:       map[string]string{},
				}
				certs, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				caBytes, err := crypto.EncodeCertificates(certs.Config.Certs[0], certs.Config.Certs[0])
				if err != nil {
					t.Fatal(err)
				}
				caBundleConfigMap.Data["ca-bundle.crt"] = string(caBytes)
				return caBundleConfigMap
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("update", "configmaps") {
					t.Error(actions[0])
				}

				actual := actions[0].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if len(actual.Data["ca-bundle.crt"]) == 0 {
					t.Error(actual.Data)
				}
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeCABundle {
					t.Errorf("expected certificate type 'ca-bundle', got: %v", certType)
				}
				result, err := cert.ParseCertsPEM([]byte(actual.Data["ca-bundle.crt"]))
				if err != nil {
					t.Fatal(err)
				}
				if len(result) != 2 {
					t.Error(len(result))
				}
			},
		},
		{
			name: "no update when RefreshOnlyWhenExpired set",
			caFn: func() (*crypto.CA, error) {
				return certs, nil
			},
			RefreshOnlyWhenExpired: true,
			initialConfigMapFn: func() *corev1.ConfigMap {
				caBundleConfigMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "trust-bundle", ResourceVersion: "10"},
					Data:       map[string]string{},
				}
				caBytes, err := crypto.EncodeCertificates(certs.Config.Certs[0])
				if err != nil {
					t.Fatal(err)
				}
				caBundleConfigMap.Data["ca-bundle.crt"] = string(caBytes)
				return caBundleConfigMap
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

			client := kubefake.NewSimpleClientset()
			if startingObj := test.initialConfigMapFn(); startingObj != nil {
				indexer.Add(startingObj)
				client = kubefake.NewSimpleClientset(startingObj)
			}

			c := &CABundleConfigMap{
				Namespace: "ns",
				Name:      "trust-bundle",

				Client:        client.CoreV1(),
				Lister:        corev1listers.NewConfigMapLister(indexer),
				EventRecorder: events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now())),
			}

			newCA, err := test.caFn()
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.EnsureConfigMapCABundle(context.TODO(), newCA, "signer-secret")
			switch {
			case err != nil && len(test.expectedError) == 0:
				t.Error(err)
			case err != nil && !strings.Contains(err.Error(), test.expectedError):
				t.Error(err)
			case err == nil && len(test.expectedError) != 0:
				t.Errorf("missing %q", test.expectedError)
			}

			test.verifyActions(t, client)
		})
	}
}

// NewCACertificate generates and signs new CA certificate and key.
func newTestCACertificate(subject pkix.Name, serialNumber int64, validity metav1.Duration, currentTime func() time.Time) (*crypto.CA, error) {
	caPublicKey, caPrivateKey, err := crypto.NewKeyPair()
	if err != nil {
		return nil, err
	}

	caCert := &x509.Certificate{
		Subject: subject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore:    currentTime().Add(-1 * time.Second),
		NotAfter:     currentTime().Add(validity.Duration),
		SerialNumber: big.NewInt(serialNumber),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := signCertificate(caCert, caPublicKey, caCert, caPrivateKey)
	if err != nil {
		return nil, err
	}

	return &crypto.CA{
		Config: &crypto.TLSCertificateConfig{
			Certs: []*x509.Certificate{cert},
			Key:   caPrivateKey,
		},
		SerialGenerator: &crypto.RandomSerialGenerator{},
	}, nil
}

func signCertificate(template *x509.Certificate, requestKey gcrypto.PublicKey, issuer *x509.Certificate, issuerKey gcrypto.PrivateKey) (*x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, requestKey, issuerKey)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, errors.New("Expected a single certificate")
	}
	return certs[0], nil
}

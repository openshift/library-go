package resourcesynccontroller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/openshift/library-go/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func generateCACert(cn string) (*x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func TestCombineCABundleConfigMaps(t *testing.T) {
	cert1, err := generateCACert("ca1")
	if err != nil {
		t.Error(err)
		return
	}
	ca1, err := crypto.EncodeCertificates(cert1)
	if err != nil {
		t.Error(err)
		return
	}

	cert2, err := generateCACert("ca2")
	if err != nil {
		t.Error(err)
		return
	}
	ca2, err := crypto.EncodeCertificates(cert2)
	if err != nil {
		t.Error(err)
		return
	}

	tt := []struct {
		name          string
		destination   ResourceLocation
		inputs        []ResourceLocation
		configmaps    []*corev1.ConfigMap
		expectedCA    *corev1.ConfigMap
		expectedError error
	}{
		{
			name: "continues with optional cm missing",
			destination: ResourceLocation{
				Namespace: "default",
				Name:      "bundle",
			},
			inputs: []ResourceLocation{
				{
					Namespace: "default",
					Name:      "cm1",
					Required:  true,
				},
				{
					Namespace: "default",
					Name:      "cm2",
					Required:  false,
				},
			},
			configmaps: []*corev1.ConfigMap{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
						Name:      "cm1",
					},
					Data: map[string]string{
						"ca-bundle.crt": string(ca1),
					},
				},
			},
			expectedCA: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "bundle",
				},
				Data: map[string]string{
					"ca-bundle.crt": func() string {
						bundle, err := crypto.EncodeCertificates(cert1)
						if err != nil {
							t.Fatal(err)
						}
						return string(bundle)
					}(),
				},
			},
			expectedError: nil,
		},
		{
			name: "fails if required cm isn't present",
			destination: ResourceLocation{
				Namespace: "default",
				Name:      "bundle",
			},
			inputs: []ResourceLocation{
				{
					Namespace: "default",
					Name:      "cm1",
					Required:  true,
				},
				{
					Namespace: "default",
					Name:      "cm2",
					Required:  false,
				},
			},
			configmaps: []*corev1.ConfigMap{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
						Name:      "cm2",
					},
					Data: map[string]string{
						"ca-bundle.crt": string(ca2),
					},
				},
			},
			expectedError: apierrors.NewNotFound(corev1.Resource("configmap"), "cm1"),
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			configMapIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			for _, cm := range tc.configmaps {
				err := configMapIndexer.Add(cm)
				if err != nil {
					t.Error(err)
				}
			}
			configmapLister := corev1listers.NewConfigMapLister(configMapIndexer)
			ca, err := CombineCABundleConfigMaps(tc.destination, configmapLister, tc.inputs...)
			if !reflect.DeepEqual(err, tc.expectedError) {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
				return
			}
			if err != nil {
				return
			}

			if ca.Namespace != tc.destination.Namespace {
				t.Errorf("expected namespace %q, got %q", tc.destination.Namespace, ca.Namespace)
			}

			if ca.Name != tc.destination.Name {
				t.Errorf("expected name %q, got %q", tc.destination.Name, ca.Name)
			}

			if !apiequality.Semantic.DeepEqual(ca, tc.expectedCA) {
				t.Errorf("expected CA %#v\n        got %v\ndiff: %s", tc.expectedError, err, cmp.Diff(tc.expectedError, err))
			}
		})
	}
}

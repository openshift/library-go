package pki

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openshift/library-go/pkg/crypto"
)

// fakePKILister implements configv1alpha1listers.PKILister for testing.
type fakePKILister struct {
	pki           *configv1alpha1.PKI
	err           error
	requestedName string
}

func (f *fakePKILister) List(_ labels.Selector) ([]*configv1alpha1.PKI, error) {
	panic("not implemented")
}

func (f *fakePKILister) Get(name string) (*configv1alpha1.PKI, error) {
	f.requestedName = name
	return f.pki, f.err
}

func TestStaticConfigProvider_ReturnsSpec(t *testing.T) {
	spec := configv1alpha1.PKISpec{
		Certificates: DefaultCertificatePolicy(),
	}
	provider := NewStaticConfigProvider(spec)

	got, err := provider.Config()
	if err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	if !reflect.DeepEqual(got, spec) {
		t.Errorf("Config() = %+v, want %+v", got, spec)
	}
}

func TestStaticConfigProvider_DeepCopiesSpec(t *testing.T) {
	spec := configv1alpha1.PKISpec{
		Certificates: configv1alpha1.PKICertificatePolicy{
			Defaults: configv1alpha1.PKIDefaultCertificateConfig{
				Key: configv1alpha1.PKIKeyConfig{
					Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
					ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP256},
				},
			},
			NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
				{Name: "openshift.io/test.ca"},
			},
		},
	}
	provider := NewStaticConfigProvider(spec)

	// Mutating the caller's value after construction must not affect the
	// provider.
	spec.Certificates.NamedCertificates[0].Name = "mutated"

	got, err := provider.Config()
	if err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	if got.Certificates.NamedCertificates[0].Name != "openshift.io/test.ca" {
		t.Errorf("NamedCertificates[0].Name = %q, want %q", got.Certificates.NamedCertificates[0].Name, "openshift.io/test.ca")
	}
}

func TestListerConfigProvider_ReturnsSpec(t *testing.T) {
	resource := &configv1alpha1.PKI{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1alpha1.PKISpec{
			Certificates: DefaultCertificatePolicy(),
		},
	}
	lister := &fakePKILister{pki: resource}
	provider := NewClusterConfigProvider(lister)

	got, err := provider.Config()
	if err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	if !reflect.DeepEqual(got, resource.Spec) {
		t.Errorf("Config() = %+v, want the spec from the lister resource", got)
	}
}

func TestListerConfigProvider_MissingResourceIsError(t *testing.T) {
	lister := &fakePKILister{
		err: apierrors.NewNotFound(schema.GroupResource{Group: "config.openshift.io", Resource: "pkis"}, "cluster"),
	}
	provider := NewClusterConfigProvider(lister)

	_, err := provider.Config()
	if err == nil {
		t.Fatal("expected error for missing PKI resource")
	}
	// The wrap must preserve apierrors.IsNotFound for callers that
	// distinguish a missing resource.
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected apierrors.IsNotFound to match, got %v", err)
	}
}

func TestListerConfigProvider_NilObjectIsError(t *testing.T) {
	lister := &fakePKILister{}
	provider := NewClusterConfigProvider(lister)

	_, err := provider.Config()
	if err == nil {
		t.Error("expected error when the lister returns a nil object")
	}
}

func TestListerConfigProvider_ListerErrorPropagates(t *testing.T) {
	lister := &fakePKILister{
		err: fmt.Errorf("connection refused"),
	}
	provider := NewClusterConfigProvider(lister)

	_, err := provider.Config()
	if err == nil {
		t.Fatal("expected error when lister fails")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "connection refused")
	}
}

func TestNewClusterConfigProvider_UsesClusterResourceName(t *testing.T) {
	lister := &fakePKILister{
		pki: &configv1alpha1.PKI{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
	}
	provider := NewClusterConfigProvider(lister)

	if _, err := provider.Config(); err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	if lister.requestedName != "cluster" {
		t.Errorf("requested resource name = %q, want %q", lister.requestedName, "cluster")
	}
}

func TestNewListerConfigProvider_UsesGivenResourceName(t *testing.T) {
	lister := &fakePKILister{
		pki: &configv1alpha1.PKI{ObjectMeta: metav1.ObjectMeta{Name: "other"}},
	}
	provider := NewListerConfigProvider(lister, "other")

	if _, err := provider.Config(); err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	if lister.requestedName != "other" {
		t.Errorf("requested resource name = %q, want %q", lister.requestedName, "other")
	}
}

func TestDeprecatedConstructorShims(t *testing.T) {
	lister := &fakePKILister{
		pki: &configv1alpha1.PKI{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
	}

	// Call the shims through variables so that running `go fix ./...` inside
	// this repo does not rewrite this test to call the new constructors
	// directly, which would stop it from exercising the shims.
	newClusterPKIProfileProvider := NewClusterPKIProfileProvider
	newListerPKIProfileProvider := NewListerPKIProfileProvider
	certificateConfig := CertificateConfig{}

	if _, err := newClusterPKIProfileProvider(lister).Config(); err != nil {
		t.Errorf("NewClusterPKIProfileProvider().Config() error = %v", err)
	}
	if lister.requestedName != "cluster" {
		t.Errorf("NewClusterPKIProfileProvider requested %q, want %q", lister.requestedName, "cluster")
	}

	if _, err := newListerPKIProfileProvider(lister, "other").Config(); err != nil {
		t.Errorf("NewListerPKIProfileProvider().Config() error = %v", err)
	}
	if lister.requestedName != "other" {
		t.Errorf("NewListerPKIProfileProvider requested %q, want %q", lister.requestedName, "other")
	}

	// The deprecated type alias must keep compiling and carry the resolved
	// key field.
	_ = certificateConfig.Key
}

func TestResolveCertificateConfig_DefaultCertificatePolicy_AllTypes(t *testing.T) {
	policy := DefaultCertificatePolicy()

	testCases := []struct {
		name     string
		certType CertificateType
		want     crypto.KeyPairGenerator
	}{
		{
			name:     "ca uses ECDSA P-384",
			certType: CertificateTypeCA,
			want:     crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			name:     "server falls back to ECDSA P-256",
			certType: CertificateTypeServer,
			want:     crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name:     "client falls back to ECDSA P-256",
			certType: CertificateTypeClient,
			want:     crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name:     "peer picks stronger of server and client",
			certType: CertificateTypePeer,
			want:     crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ResolveCertificateConfig(policy, tc.certType, "openshift.io/test")
			if err != nil {
				t.Fatalf("ResolveCertificateConfig() error = %v", err)
			}
			if cfg.Key != tc.want {
				t.Errorf("Key = %+v, want %+v", cfg.Key, tc.want)
			}
		})
	}
}

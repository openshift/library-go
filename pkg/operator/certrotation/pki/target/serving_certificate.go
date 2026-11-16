package target

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/clock"
)

var _ TargetCertCreator = (*ServingRotation)(nil)

type ServingRotation struct {
	hostnames              ServingHostnameFunc
	certificateExtensionFn []crypto.CertificateExtensionFunc
	hostnamesChanged       <-chan struct{}
	pkiProvider            pki.PKIProfileProvider
	certificateName        string
	clock                  clock.PassiveClock
}

type ServingRotationOption func(*ServingRotation)

func WithServingCertificateExtensionFuncs(fns ...crypto.CertificateExtensionFunc) ServingRotationOption {
	return func(sr *ServingRotation) {
		sr.certificateExtensionFn = fns
	}
}

func WithServingHostnamesChangedChannel(hostnamesChanged <-chan struct{}) ServingRotationOption {
	return func(sr *ServingRotation) {
		sr.hostnamesChanged = hostnamesChanged
	}
}

func NewServingRotation(certificateName string, pkiProvider pki.PKIProfileProvider, hostnames ServingHostnameFunc, options ...ServingRotationOption) *ServingRotation {
	rotation := &ServingRotation{
		certificateName: certificateName,
		pkiProvider:     pkiProvider,
		hostnames:       hostnames,
		clock:           clock.RealClock{},
	}

	for _, option := range options {
		option(rotation)
	}

	return rotation
}

func (r *ServingRotation) NewCertificate(signer *crypto.CA, validity time.Duration) (*crypto.TLSCertificateConfig, error) {
	hostnames := r.hostnames()
	if len(hostnames) == 0 {
		return nil, fmt.Errorf("no hostnames set")
	}

	cfg, err := pki.ResolveCertificateConfig(r.pkiProvider, pki.CertificateTypeClient, r.certificateName)
	if err != nil {
		return nil, fmt.Errorf("resolving PKI configuration: %w", err)
	}

	return signer.NewServerCertificate(sets.New(hostnames...), cfg.Key,
		crypto.WithLifetime(validity),
		crypto.WithExtensions(r.certificateExtensionFn...),
		crypto.WithNowFunc(r.clock.Now),
	)
}

func (r *ServingRotation) RecheckChannel() <-chan struct{} {
	return r.hostnamesChanged
}

func (r *ServingRotation) NeedNewTargetCertKeyPair(currentCertSecret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration) (bool, string, error) {
	updateRequired, reason, err := checkIfTargetUpdateRequired(currentCertSecret, signer, caBundleCerts, refresh, r.clock)
	if err != nil {
		return false, "", fmt.Errorf("checking if target update is required: %w", err)
	}

	if updateRequired {
		return true, reason, nil
	}

	return r.missingHostnames(currentCertSecret.Annotations)
}

func (r *ServingRotation) missingHostnames(annotations map[string]string) (bool, string, error) {
	return missingHostnames(annotations, r.hostnames())
}

func (r *ServingRotation) SetAnnotations(cert *crypto.TLSCertificateConfig, annotations map[string]string) {
	setHostnameAnnotations(cert, annotations)
}

func missingHostnames(annotations map[string]string, hostnames []string) (bool, string, error) {
	existingHostnames := sets.New(strings.Split(annotations[certrotation.CertificateHostnames], ",")...)
	requiredHostnames := sets.New(hostnames...)
	if !existingHostnames.Equal(requiredHostnames) {
		existingNotRequired := existingHostnames.Difference(requiredHostnames)
		requiredNotExisting := requiredHostnames.Difference(existingHostnames)
		return true, fmt.Sprintf("%q are existing and not required, %q are required and not existing", strings.Join(sets.List(existingNotRequired), ","), strings.Join(sets.List(requiredNotExisting), ",")), nil
	}
	return false, "", nil
}

func setHostnameAnnotations(cert *crypto.TLSCertificateConfig, annotations map[string]string) {
	hostnames := sets.Set[string]{}
	for _, ip := range cert.Certs[0].IPAddresses {
		hostnames.Insert(ip.String())
	}
	for _, dnsName := range cert.Certs[0].DNSNames {
		hostnames.Insert(dnsName)
	}
	// List does a sort so that we have a consistent representation
	annotations[certrotation.CertificateHostnames] = strings.Join(sets.List(hostnames), ",")
	return
}

type ServingHostnameFunc func() []string

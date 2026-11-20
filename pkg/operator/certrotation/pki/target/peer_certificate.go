package target

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/utils/clock"
)

var _ TargetCertCreator = (*PeerRotation)(nil)

// PeerRotation creates certificates used for both server and client authentication
// (e.g., etcd peer certificates). It uses CertificateTypePeer for PKI profile
// resolution, which selects the stronger of the serving and client key configurations.
//
// UserInfo is always required.
// NewPeerCertificate encodes UserInfo as the client identity in the certificate
// subject.
type PeerRotation struct {
	hostnames              ServingHostnameFunc
	userInfo               user.Info
	certificateExtensionFn []crypto.CertificateExtensionFunc
	hostnamesChanged       <-chan struct{}
	certificateName        string
	pkiProvider            pki.PKIProfileProvider
	clock                  clock.PassiveClock
}

type PeerRotationOption func(*PeerRotation)

func WithPeerCertificateExtensionFuncs(fns ...crypto.CertificateExtensionFunc) PeerRotationOption {
	return func(pr *PeerRotation) {
		pr.certificateExtensionFn = fns
	}
}

func WithPeerHostnamesChangedChannel(hostnamesChanged <-chan struct{}) PeerRotationOption {
	return func(pr *PeerRotation) {
		pr.hostnamesChanged = hostnamesChanged
	}
}

func NewPeerRotation(certificateName string, pkiProvider pki.PKIProfileProvider, hostnames ServingHostnameFunc, userInfo user.Info, options ...PeerRotationOption) *PeerRotation {
	rotation := &PeerRotation{
		certificateName: certificateName,
		pkiProvider:     pkiProvider,
		hostnames:       hostnames,
		userInfo:        userInfo,
		clock:           clock.RealClock{},
	}

	for _, option := range options {
		option(rotation)
	}

	return rotation
}

func (r *PeerRotation) NewCertificate(signer *crypto.CA, validity time.Duration) (*crypto.TLSCertificateConfig, error) {
	hostnames := r.hostnames()
	if len(hostnames) == 0 {
		return nil, fmt.Errorf("no hostnames set")
	}

	if r.userInfo == nil {
		return nil, fmt.Errorf("PeerRotation requires UserInfo")
	}

	cfg, err := pki.ResolveCertificateConfig(r.pkiProvider, pki.CertificateTypePeer, r.certificateName)
	if err != nil {
		return nil, fmt.Errorf("resolving PKI configuration: %w", err)
	}

	remainingSignerValidity := signer.Config.Certs[0].NotAfter.Sub(r.clock.Now())

	lifetime := min(remainingSignerValidity, validity)

	return signer.NewPeerCertificate(
		sets.New(hostnames...), r.userInfo, cfg.Key,
		crypto.WithLifetime(lifetime),
		crypto.WithExtensions(r.certificateExtensionFn...),
		crypto.WithNowFunc(r.clock.Now),
	)
}

func (r *PeerRotation) RecheckChannel() <-chan struct{} {
	return r.hostnamesChanged
}

func (r *PeerRotation) NeedNewTargetCertKeyPair(currentCertSecret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration) (bool, string, error) {
	updateRequired, reason, err := checkIfTargetUpdateRequired(currentCertSecret, signer, caBundleCerts, refresh, r.clock)
	if err != nil {
		return false, "", fmt.Errorf("checking if target update is required: %w", err)
	}

	if updateRequired {
		return true, reason, nil
	}

	return missingHostnames(currentCertSecret.Annotations, r.hostnames())
}

func (r *PeerRotation) SetAnnotations(cert *crypto.TLSCertificateConfig, annotations map[string]string) {
	setHostnameAnnotations(cert, annotations)
}

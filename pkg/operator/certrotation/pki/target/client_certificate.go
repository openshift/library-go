package target

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/utils/clock"
)

var _ TargetCertCreator = (*ClientRotation)(nil)

type ClientRotation struct {
	userInfo        user.Info
	pkiProvider     pki.PKIProfileProvider
	certificateName string
	clock           clock.PassiveClock
}

func NewClientRotation(certificateName string, pkiProvider pki.PKIProfileProvider, userInfo user.Info) *ClientRotation {
	return &ClientRotation{
		userInfo:        userInfo,
		pkiProvider:     pkiProvider,
		certificateName: certificateName,
		clock:           clock.RealClock{},
	}
}

func (r *ClientRotation) NewCertificate(signer *crypto.CA, validity time.Duration) (*crypto.TLSCertificateConfig, error) {
	cfg, err := pki.ResolveCertificateConfig(r.pkiProvider, pki.CertificateTypeClient, r.certificateName)
	if err != nil {
		return nil, fmt.Errorf("resolving PKI configuration: %w", err)
	}

	return signer.NewClientCertificate(r.userInfo, cfg.Key, crypto.WithLifetime(validity))
}

func (r *ClientRotation) NeedNewTargetCertKeyPair(currentCertSecret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration) (bool, string, error) {
	return checkIfTargetUpdateRequired(currentCertSecret, signer, caBundleCerts, refresh, r.clock)
}

func (r *ClientRotation) SetAnnotations(cert *crypto.TLSCertificateConfig, annotations map[string]string) {
	return
}

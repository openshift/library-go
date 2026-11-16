package target

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/clock"
)

var _ TargetCertCreator = (*SignerRotation)(nil)

type SignerRotation struct {
	signerName      string
	certificateName string
	pkiProvider     pki.PKIProfileProvider
	clock           clock.PassiveClock
}

func NewSignerRotation(certificateName string, pkiProvider pki.PKIProfileProvider, signerName string) *SignerRotation {
	return &SignerRotation{
		certificateName: certificateName,
		pkiProvider:     pkiProvider,
		signerName:      signerName,
		clock:           clock.RealClock{},
	}
}

func (r *SignerRotation) NewCertificate(signer *crypto.CA, validity time.Duration) (*crypto.TLSCertificateConfig, error) {
	signerName := fmt.Sprintf("%s_@%d", r.signerName, time.Now().Unix())

	cfg, err := pki.ResolveCertificateConfig(r.pkiProvider, pki.CertificateTypeSigner, r.certificateName)
	if err != nil {
		return nil, fmt.Errorf("resolving PKI configuration: %w", err)
	}

	remainingSignerValidity := signer.Config.Certs[0].NotAfter.Sub(r.clock.Now())

	lifetime := min(remainingSignerValidity, validity)

	return crypto.NewSigningCertificate(signerName, cfg.Key,
		crypto.WithSigner(signer),
		crypto.WithLifetime(lifetime),
		crypto.WithNowFunc(r.clock.Now),
	)
}

func (r *SignerRotation) NeedNewTargetCertKeyPair(currentCertSecret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration) (bool, string, error) {
	return checkIfTargetUpdateRequired(currentCertSecret, signer, caBundleCerts, refresh, r.clock)
}

func (r *SignerRotation) SetAnnotations(cert *crypto.TLSCertificateConfig, annotations map[string]string) {
	return
}

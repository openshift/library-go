package rotation

import (
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/clock"
)

func loadCertificateConfigFromSecret(secret *corev1.Secret) (*crypto.TLSCertificateConfig, error) {
	ca, err := crypto.GetCAFromBytes(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return nil, fmt.Errorf("loading certificate contents from secret data: %w", err)
	}

	return ca.Config, nil
}

type StandardRotator struct {
	refreshPeriod time.Duration
	clock         clock.PassiveClock
}

func NewStandardRotator(refreshPeriod time.Duration) *StandardRotator {
	return &StandardRotator{
		refreshPeriod: refreshPeriod,
		clock:         clock.RealClock{},
	}
}

func (sr *StandardRotator) NeedsRotation(s *corev1.Secret) (bool, string, error) {
	tlsCertCfg, err := loadCertificateConfigFromSecret(s)
	if err != nil {
		return false, "", err
	}

	// Typically, we only care about evaluating the first certificate in the chain
	// because that is either the leaf certificate being issued for a target certificate type
	// or the actual self-signed root CA signing certificate for self-signed signer certificates.
	cert := tlsCertCfg.Certs[0]

	if sr.clock.Now().After(cert.NotAfter) {
		return true, "expired", nil
	}

	refreshTime := cert.NotBefore.Add(sr.refreshPeriod)
	if sr.clock.Now().After(refreshTime) {
		return true, fmt.Sprintf("past refresh time of %v", refreshTime), nil
	}

	// no need to rotate
	return false, "", nil
}

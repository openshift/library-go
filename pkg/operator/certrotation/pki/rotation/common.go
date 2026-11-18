package rotation

import (
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation/pki/controller"
	corev1 "k8s.io/api/core/v1"
)

func loadCertificateConfigFromSecret(secret *corev1.Secret) (*crypto.TLSCertificateConfig, error) {
	ca, err := crypto.GetCAFromBytes(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return nil, fmt.Errorf("loading certificate contents from secret data: %w", err)
	}

	return ca.Config, nil
}

// TODO: Add key algorithm evaluation here once Ben's Matches() PR for crypto.KeyPairGenerator merges and can be rebased on.
func StandardRotationFn(refreshPeriod time.Duration) controller.RotationFn {
	return func(s *corev1.Secret) (bool, string, error) {
		tlsCertCfg, err := loadCertificateConfigFromSecret(s)
		if err != nil {
			return false, "", err
		}

		// Typically, we only care about evaluating the first certificate in the chain
		// because that is either the leaf certificate being issued for a target certificate type
		// or the actual self-signed root CA signing certificate for self-signed signer certificates.
		cert := tlsCertCfg.Certs[0]

		// TODO: sane way to make this a clock for testing?
		if time.Now().After(cert.NotAfter) {
			return true, "expired", nil
		}

		refreshTime := cert.NotBefore.Add(refreshPeriod)
		if time.Now().After(refreshTime) {
			return true, fmt.Sprintf("past refresh time of %v", refreshTime), nil
		}

		// no need to rotate
		return false, "", nil
	}
}

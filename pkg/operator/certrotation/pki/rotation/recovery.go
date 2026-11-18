package rotation

import (
	"time"

	"github.com/openshift/library-go/pkg/operator/certrotation/pki/controller"
	v1 "k8s.io/api/core/v1"
)

func RecoveryRotationFn() controller.RotationFn {
	return func(s *v1.Secret) (bool, string, error) {
		tlsCertCfg, err := loadCertificateConfigFromSecret(s)
		if err != nil {
			return false, "", err
		}

		cert := tlsCertCfg.Certs[0]

		if time.Now().After(cert.NotAfter) {
			return true, "expired", nil
		}

		return false, "", nil
	}
}

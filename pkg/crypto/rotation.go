package crypto

import (
	"crypto/x509"
	"time"
)

// FilterExpiredCerts checks are all certificates in the bundle valid, i.e. they have not expired.
// The function returns new bundle with only valid certificates or error if no valid certificate is found.
func FilterExpiredCerts(certs ...*x509.Certificate) []*x509.Certificate {
	return FilterExpiredCertsWithTime(time.Now(), certs...)
}

func FilterExpiredCertsWithTime(now time.Time, certs ...*x509.Certificate) []*x509.Certificate {
	var validCerts []*x509.Certificate
	for _, c := range certs {
		if c.NotAfter.After(now) {
			validCerts = append(validCerts, c)
		}
	}

	return validCerts
}

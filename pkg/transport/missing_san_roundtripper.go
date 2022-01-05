package transport

import (
	"net/http"

	"github.com/openshift/library-go/pkg/crypto"
)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (rt roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt(r)
}

type counter interface {
	Inc()
}

// NewMissingSANRoundTripper returns a round tripper that increases the given counter
// if the wrapped roundtripper returns an error indicating usage of legacy CN fields
// or if the wrapped roundtripper response leaf certificate includes no SAN field.
//
// The counter is compatible both with native Prometheus and k8s metrics types.
func NewMissingSANRoundTripper(rt http.RoundTripper, c counter) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (resp *http.Response, err error) {
		resp, err = rt.RoundTrip(req)
		if crypto.IsHostnameError(err) {
			c.Inc()
			return
		}

		if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
			return
		}

		// The first element is the leaf certificate.
		if !crypto.CertHasSAN(resp.TLS.PeerCertificates[0]) {
			c.Inc()
		}

		return
	})
}

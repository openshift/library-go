package certrotation

import (
	"crypto/x509"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/crypto"
)

// This file dispatches certificate issuance between the legacy and
// ConfigurablePKI code paths. LegacyPKI calls exactly the v1 legacy
// functions, including the legacy PeerCert CN constraint; ConfigurablePKI
// calls the option-style constructors with the resolved key generator. A nil
// key generator means legacy.

// issueSigner mints a self-signed signing CA. The subject CN format
// "<namespace>_<name>@<unix>" is preserved from v1.
func issueSigner(namespace, name string, validity time.Duration, keyGen crypto.KeyPairGenerator, now time.Time) (*crypto.TLSCertificateConfig, error) {
	signerName := fmt.Sprintf("%s_%s@%d", namespace, name, now.Unix())
	if keyGen == nil {
		return crypto.UnsafeMakeSelfSignedCAConfigForDurationAtTime(signerName, func() time.Time { return now }, validity)
	}
	return crypto.NewSigningCertificate(signerName, keyGen, crypto.WithLifetime(validity))
}

// issueTarget mints a target certificate from the given signer. Validity is
// clamped to the signer's remaining lifetime, as v1 did, so a target never
// outlives its issuer.
func issueTarget(target Target, hostnames []string, signer *crypto.CA, keyGen crypto.KeyPairGenerator, now time.Time) (*crypto.TLSCertificateConfig, error) {
	validity := target.Validity
	remainingSignerValidity := signer.Config.Certs[0].NotAfter.Sub(now)
	if remainingSignerValidity < validity {
		validity = remainingSignerValidity
	}

	switch cert := target.Cert.(type) {
	case ClientCert:
		if keyGen == nil {
			return signer.MakeClientCertificateForDuration(cert.User, validity)
		}
		return signer.NewClientCertificate(cert.User, keyGen, crypto.WithLifetime(validity))

	case ServingCert:
		if len(hostnames) == 0 {
			return nil, fmt.Errorf("target %s: no hostnames set", target.Name)
		}
		if keyGen == nil {
			return signer.MakeServerCertForDuration(sets.New(hostnames...), validity, cert.Extensions...)
		}
		return signer.NewServerCertificate(sets.New(hostnames...), keyGen,
			crypto.WithLifetime(validity),
			crypto.WithExtensions(cert.Extensions...),
		)

	case PeerCert:
		if len(hostnames) == 0 {
			return nil, fmt.Errorf("target %s: no hostnames set", target.Name)
		}
		if keyGen == nil {
			// Legacy path, exactly as v1's PeerRotation: a server cert
			// template whose CN is the sorted first hostname, extended with
			// both client and server auth key usages. The UserInfo.Name
			// constraint is checked at construction instead of at runtime.
			sortedHostnames := sets.List(sets.New(hostnames...))
			if cn := sortedHostnames[0]; cert.User.GetName() != cn {
				return nil, fmt.Errorf("target %s: legacy PeerCert uses sorted first hostname %q as CN; UserInfo.Name %q conflicts; set UserInfo.Name to match or use ConfigurablePKI", target.Name, cn, cert.User.GetName())
			}
			peerExtFn := func(c *x509.Certificate) error {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
				return nil
			}
			extensions := append(append([]crypto.CertificateExtensionFunc{}, cert.Extensions...), peerExtFn)
			return signer.MakeServerCertForDuration(sets.New(hostnames...), validity, extensions...)
		}
		return signer.NewPeerCertificate(sets.New(hostnames...), cert.User, keyGen,
			crypto.WithLifetime(validity),
			crypto.WithExtensions(cert.Extensions...),
		)

	case IntermediateSignerCert:
		// Subject CN format "<SignerName>_@<unix>" is preserved from v1's
		// SignerRotation.
		signerName := fmt.Sprintf("%s_@%d", cert.SignerName, now.Unix())
		if keyGen == nil {
			return crypto.MakeCAConfigForDuration(signerName, validity, signer)
		}
		return crypto.NewSigningCertificate(signerName, keyGen,
			crypto.WithSigner(signer),
			crypto.WithLifetime(validity),
		)

	default:
		return nil, fmt.Errorf("target %s: unknown certificate kind %T", target.Name, target.Cert)
	}
}

// checkLegacyPeerCertConstraint validates the legacy PeerCert CN constraint
// at construction time for LegacyPKI, instead of failing at issuance time as
// v1 did. It is a no-op for other certificate kinds and for ConfigurablePKI.
func checkLegacyPeerCertConstraint(rotation Rotation, pkiMode pkiMode) error {
	if pkiMode != pkiModeLegacy {
		return nil
	}
	for i := range rotation.Targets {
		peer, ok := rotation.Targets[i].Cert.(PeerCert)
		if !ok {
			continue
		}
		// Hostnames are not known at construction for dynamic sources; the
		// constraint is re-checked at issuance time in that case.
		if static, ok := peer.Hostnames.(staticHostnames); ok && len(static) > 0 {
			sortedHostnames := sets.List(sets.New(static...))
			if cn := sortedHostnames[0]; peer.User.GetName() != cn {
				return fmt.Errorf("target %s: legacy PeerCert uses sorted first hostname %q as CN; UserInfo.Name %q conflicts; set UserInfo.Name to match or use ConfigurablePKI", rotation.Targets[i].Name, cn, peer.User.GetName())
			}
		}
	}
	return nil
}

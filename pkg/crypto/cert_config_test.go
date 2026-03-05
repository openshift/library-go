package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

var allKeyPairGenerators = []KeyPairGenerator{
	RSAKeyPairGenerator{Bits: 2048},
	RSAKeyPairGenerator{Bits: 4096},
	ECDSAKeyPairGenerator{Curve: P256},
	ECDSAKeyPairGenerator{Curve: P384},
	ECDSAKeyPairGenerator{Curve: P521},
}

func keyGenName(g KeyPairGenerator) string {
	switch g := g.(type) {
	case RSAKeyPairGenerator:
		return fmt.Sprintf("RSA-%d", g.Bits)
	case ECDSAKeyPairGenerator:
		return "ECDSA-" + string(g.Curve)
	}
	return "unknown"
}

func TestKeyUsageForPublicKey(t *testing.T) {
	rsaGen := RSAKeyPairGenerator{Bits: 2048}
	rsaPub, _, err := rsaGen.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rsaUsage := KeyUsageForPublicKey(rsaPub)
	if rsaUsage != x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature {
		t.Errorf("RSA KeyUsage = %v, want KeyEncipherment|DigitalSignature", rsaUsage)
	}

	ecdsaGen := ECDSAKeyPairGenerator{Curve: P256}
	ecdsaPub, _, err := ecdsaGen.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ecdsaUsage := KeyUsageForPublicKey(ecdsaPub)
	if ecdsaUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("ECDSA KeyUsage = %v, want DigitalSignature only", ecdsaUsage)
	}
	if ecdsaUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("ECDSA KeyUsage should not include KeyEncipherment")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	testCases := []struct {
		name string
		gen  KeyPairGenerator
	}{
		{
			name: "RSA-2048",
			gen:  RSAKeyPairGenerator{Bits: 2048},
		},
		{
			name: "RSA-4096",
			gen:  RSAKeyPairGenerator{Bits: 4096},
		},
		{
			name: "ECDSA-P256",
			gen:  ECDSAKeyPairGenerator{Curve: P256},
		},
		{
			name: "ECDSA-P384",
			gen:  ECDSAKeyPairGenerator{Curve: P384},
		},
		{
			name: "ECDSA-P521",
			gen:  ECDSAKeyPairGenerator{Curve: P521},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, err := tc.gen.GenerateKeyPair()
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}
			if pub == nil || priv == nil {
				t.Fatal("GenerateKeyPair() returned nil key")
			}

			switch g := tc.gen.(type) {
			case RSAKeyPairGenerator:
				rsaPub, ok := pub.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("expected *rsa.PublicKey, got %T", pub)
				}
				if rsaPub.N.BitLen() != g.Bits {
					t.Errorf("RSA key size = %d, want %d", rsaPub.N.BitLen(), g.Bits)
				}
			case ECDSAKeyPairGenerator:
				ecPub, ok := pub.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
				}
				wantCurve := curveForName(g.Curve)
				if ecPub.Curve != wantCurve {
					t.Errorf("ECDSA curve = %v, want %v", ecPub.Curve.Params().Name, wantCurve.Params().Name)
				}
			}
		})
	}
}

func TestSubjectKeyIDFromPublicKey(t *testing.T) {
	for _, g := range allKeyPairGenerators {
		t.Run(keyGenName(g), func(t *testing.T) {
			pub, _, err := g.GenerateKeyPair()
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}
			skid, err := SubjectKeyIDFromPublicKey(pub)
			if err != nil {
				t.Fatalf("SubjectKeyIDFromPublicKey() error = %v", err)
			}
			// Truncated SHA-256 produces 20-byte (160-bit) subject key ID per RFC 7093
			if len(skid) != 20 {
				t.Errorf("SubjectKeyID length = %d, want 20", len(skid))
			}
		})
	}
}

func TestNewSigningCertificate(t *testing.T) {
	for _, g := range allKeyPairGenerators {
		t.Run(keyGenName(g), func(t *testing.T) {
			config, err := NewSigningCertificate("test-ca", g,
				WithLifetime(24*time.Hour),
			)
			if err != nil {
				t.Fatalf("NewSigningCertificate() error = %v", err)
			}
			if len(config.Certs) != 1 {
				t.Fatalf("expected 1 cert, got %d", len(config.Certs))
			}

			cert := config.Certs[0]
			if cert.Subject.CommonName != "test-ca" {
				t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "test-ca")
			}
			if !cert.IsCA {
				t.Error("expected IsCA to be true")
			}
			if len(cert.SubjectKeyId) == 0 {
				t.Error("SubjectKeyId is empty")
			}
			if len(cert.AuthorityKeyId) == 0 {
				t.Error("AuthorityKeyId is empty")
			}
			// Self-signed: SubjectKeyId == AuthorityKeyId
			if string(cert.SubjectKeyId) != string(cert.AuthorityKeyId) {
				t.Error("self-signed CA should have SubjectKeyId == AuthorityKeyId")
			}

			assertKeyType(t, config.Key, g)
		})
	}
}

func TestNewSigningCertificate_WithSubject(t *testing.T) {
	g := RSAKeyPairGenerator{Bits: 2048}
	config, err := NewSigningCertificate("ignored-name", g,
		WithSubject(x509pkixName("custom-cn", "custom-org")),
	)
	if err != nil {
		t.Fatalf("NewSigningCertificate() error = %v", err)
	}
	cert := config.Certs[0]
	if cert.Subject.CommonName != "custom-cn" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "custom-cn")
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "custom-org" {
		t.Errorf("Organization = %v, want [custom-org]", cert.Subject.Organization)
	}
}

func TestNewSigningCertificate_WithSigner(t *testing.T) {
	testCases := []struct {
		name   string
		rootKG KeyPairGenerator
		intKG  KeyPairGenerator
	}{
		{
			name:   "RSA root, RSA intermediate",
			rootKG: RSAKeyPairGenerator{Bits: 2048},
			intKG:  RSAKeyPairGenerator{Bits: 4096},
		},
		{
			name:   "RSA root, ECDSA intermediate",
			rootKG: RSAKeyPairGenerator{Bits: 4096},
			intKG:  ECDSAKeyPairGenerator{Curve: P256},
		},
		{
			name:   "ECDSA root, RSA intermediate",
			rootKG: ECDSAKeyPairGenerator{Curve: P384},
			intKG:  RSAKeyPairGenerator{Bits: 2048},
		},
		{
			name:   "ECDSA root, ECDSA intermediate",
			rootKG: ECDSAKeyPairGenerator{Curve: P256},
			intKG:  ECDSAKeyPairGenerator{Curve: P384},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rootConfig, err := NewSigningCertificate("root-ca", tc.rootKG)
			if err != nil {
				t.Fatalf("root NewSigningCertificate() error = %v", err)
			}
			rootCA := &CA{
				Config:          rootConfig,
				SerialGenerator: &RandomSerialGenerator{},
			}

			intConfig, err := NewSigningCertificate("intermediate-ca", tc.intKG,
				WithSigner(rootCA),
				WithLifetime(24*time.Hour),
			)
			if err != nil {
				t.Fatalf("intermediate NewSigningCertificate() error = %v", err)
			}

			intCert := intConfig.Certs[0]

			if !intCert.IsCA {
				t.Error("intermediate cert should be CA")
			}
			if intCert.Subject.CommonName != "intermediate-ca" {
				t.Errorf("CN = %q, want %q", intCert.Subject.CommonName, "intermediate-ca")
			}

			// AuthorityKeyId should match the root's SubjectKeyId
			if string(intCert.AuthorityKeyId) != string(rootConfig.Certs[0].SubjectKeyId) {
				t.Error("intermediate AuthorityKeyId should match root SubjectKeyId")
			}
			// SubjectKeyId should differ from root
			if string(intCert.SubjectKeyId) == string(rootConfig.Certs[0].SubjectKeyId) {
				t.Error("intermediate SubjectKeyId should differ from root")
			}

			// Cert chain should include both intermediate and root
			if len(intConfig.Certs) != 2 {
				t.Fatalf("expected 2 certs in chain, got %d", len(intConfig.Certs))
			}
			if intConfig.Certs[1].Subject.CommonName != "root-ca" {
				t.Errorf("chain[1] CN = %q, want %q", intConfig.Certs[1].Subject.CommonName, "root-ca")
			}

			// Verify the key type matches the intermediate's config
			assertKeyType(t, intConfig.Key, tc.intKG)
		})
	}
}

func TestNewServerCertificate(t *testing.T) {
	for _, caKG := range allKeyPairGenerators {
		for _, leafKG := range allKeyPairGenerators {
			name := keyGenName(caKG) + "-CA_" + keyGenName(leafKG) + "-leaf"
			t.Run(name, func(t *testing.T) {
				caConfig, err := NewSigningCertificate("test-ca", caKG)
				if err != nil {
					t.Fatalf("NewSigningCertificate() error = %v", err)
				}
				ca := &CA{
					Config:          caConfig,
					SerialGenerator: &RandomSerialGenerator{},
				}

				hostnames := sets.New("localhost", "127.0.0.1", "example.com")
				serverConfig, err := ca.NewServerCertificate(hostnames, leafKG,
					WithLifetime(1*time.Hour),
				)
				if err != nil {
					t.Fatalf("NewServerCertificate() error = %v", err)
				}

				cert := serverConfig.Certs[0]

				if cert.IsCA {
					t.Error("server cert should not be CA")
				}
				assertHasEKU(t, cert, x509.ExtKeyUsageServerAuth)
				assertKeyType(t, serverConfig.Key, leafKG)

				// Verify hostnames are in SANs
				if !slices.Contains(cert.DNSNames, "localhost") {
					t.Error("missing DNS SAN: localhost")
				}
				if !slices.Contains(cert.DNSNames, "example.com") {
					t.Error("missing DNS SAN: example.com")
				}

				// Verify chain: leaf signed by CA
				if string(cert.AuthorityKeyId) != string(caConfig.Certs[0].SubjectKeyId) {
					t.Error("leaf AuthorityKeyId should match CA SubjectKeyId")
				}
			})
		}
	}
}

func TestNewClientCertificate(t *testing.T) {
	for _, caKG := range allKeyPairGenerators {
		for _, leafKG := range allKeyPairGenerators {
			name := keyGenName(caKG) + "-CA_" + keyGenName(leafKG) + "-leaf"
			t.Run(name, func(t *testing.T) {
				caConfig, err := NewSigningCertificate("test-ca", caKG)
				if err != nil {
					t.Fatalf("NewSigningCertificate() error = %v", err)
				}
				ca := &CA{
					Config:          caConfig,
					SerialGenerator: &RandomSerialGenerator{},
				}

				u := &user.DefaultInfo{
					Name:   "system:test-user",
					Groups: []string{"system:masters"},
				}
				clientConfig, err := ca.NewClientCertificate(u, leafKG,
					WithLifetime(1*time.Hour),
				)
				if err != nil {
					t.Fatalf("NewClientCertificate() error = %v", err)
				}

				cert := clientConfig.Certs[0]

				if cert.IsCA {
					t.Error("client cert should not be CA")
				}
				assertHasEKU(t, cert, x509.ExtKeyUsageClientAuth)
				if cert.Subject.CommonName != "system:test-user" {
					t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "system:test-user")
				}
			})
		}
	}
}

func TestNewPeerCertificate(t *testing.T) {
	for _, g := range allKeyPairGenerators {
		t.Run(keyGenName(g), func(t *testing.T) {
			caConfig, err := NewSigningCertificate("test-ca", g)
			if err != nil {
				t.Fatalf("NewSigningCertificate() error = %v", err)
			}
			ca := &CA{
				Config:          caConfig,
				SerialGenerator: &RandomSerialGenerator{},
			}

			hostnames := sets.New("peer.example.com")
			u := &user.DefaultInfo{
				Name:   "system:peer",
				Groups: []string{"system:nodes"},
			}
			peerConfig, err := ca.NewPeerCertificate(hostnames, u, g,
				WithLifetime(1*time.Hour),
			)
			if err != nil {
				t.Fatalf("NewPeerCertificate() error = %v", err)
			}

			cert := peerConfig.Certs[0]

			// Peer cert should have both ServerAuth and ClientAuth
			assertHasEKU(t, cert, x509.ExtKeyUsageServerAuth)
			assertHasEKU(t, cert, x509.ExtKeyUsageClientAuth)

			// Should have hostnames in SANs
			if !slices.Contains(cert.DNSNames, "peer.example.com") {
				t.Error("missing DNS SAN: peer.example.com")
			}

			// Subject should come from user info
			if cert.Subject.CommonName != "system:peer" {
				t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "system:peer")
			}

			if cert.IsCA {
				t.Error("peer cert should not be CA")
			}
		})
	}
}

func TestNewServerCertificate_WithExtensions(t *testing.T) {
	g := RSAKeyPairGenerator{Bits: 2048}
	caConfig, err := NewSigningCertificate("test-ca", g)
	if err != nil {
		t.Fatalf("NewSigningCertificate() error = %v", err)
	}
	ca := &CA{
		Config:          caConfig,
		SerialGenerator: &RandomSerialGenerator{},
	}

	extensionCalled := false
	serverConfig, err := ca.NewServerCertificate(
		sets.New("localhost"),
		g,
		WithExtensions(func(cert *x509.Certificate) error {
			extensionCalled = true
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("NewServerCertificate() error = %v", err)
	}
	if !extensionCalled {
		t.Error("extension function was not called")
	}
	if serverConfig == nil {
		t.Error("server config is nil")
	}
}

// Helper functions

func assertKeyType(t *testing.T, key any, g KeyPairGenerator) {
	t.Helper()
	switch g := g.(type) {
	case RSAKeyPairGenerator:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", key)
			return
		}
		if rsaKey.N.BitLen() != g.Bits {
			t.Errorf("RSA key size = %d, want %d", rsaKey.N.BitLen(), g.Bits)
		}
	case ECDSAKeyPairGenerator:
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
			return
		}
		wantCurve := curveForName(g.Curve)
		if ecKey.Curve != wantCurve {
			t.Errorf("ECDSA curve = %v, want %v", ecKey.Curve.Params().Name, wantCurve.Params().Name)
		}
	}
}

func assertHasEKU(t *testing.T, cert *x509.Certificate, eku x509.ExtKeyUsage) {
	t.Helper()
	if !slices.Contains(cert.ExtKeyUsage, eku) {
		t.Errorf("certificate missing ExtKeyUsage %v", eku)
	}
}

func curveForName(c ECDSACurve) elliptic.Curve {
	switch c {
	case P256:
		return elliptic.P256()
	case P384:
		return elliptic.P384()
	case P521:
		return elliptic.P521()
	}
	return nil
}

func x509pkixName(cn, org string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{org}}
}

package crypto

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

var allKeySpecs = []KeySpec{
	{Algorithm: RSAKeyAlgorithm, RSABits: 2048},
	{Algorithm: RSAKeyAlgorithm, RSABits: 4096},
	{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256},
	{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384},
	{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P521},
}

var allKeyPairGenerators = func() []KeyPairGenerator {
	generators := make([]KeyPairGenerator, len(allKeySpecs))
	for i, spec := range allKeySpecs {
		generators[i] = mustGenerator(spec)
	}
	return generators
}()

func keyGenName(i int) string {
	return allKeySpecs[i].String()
}

func TestKeyUsageForPublicKey(t *testing.T) {
	rsaGen := mustGenerator(KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048})
	rsaPub, _, err := rsaGen.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rsaUsage := KeyUsageForPublicKey(rsaPub)
	if rsaUsage != x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature {
		t.Errorf("RSA KeyUsage = %v, want KeyEncipherment|DigitalSignature", rsaUsage)
	}

	ecdsaGen := mustGenerator(KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256})
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
		spec KeySpec
	}{
		{
			name: "RSA-2048",
			spec: KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048},
		},
		{
			name: "RSA-4096",
			spec: KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 4096},
		},
		{
			name: "ECDSA-P256",
			spec: KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256},
		},
		{
			name: "ECDSA-P384",
			spec: KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384},
		},
		{
			name: "ECDSA-P521",
			spec: KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P521},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, err := mustGenerator(tc.spec).GenerateKeyPair()
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}
			if pub == nil || priv == nil {
				t.Fatal("GenerateKeyPair() returned nil key")
			}

			if err := tc.spec.Matches(pub); err != nil {
				t.Errorf("generated key does not match spec: %v", err)
			}
		})
	}
}

func TestSubjectKeyIDFromPublicKey(t *testing.T) {
	for i, spec := range allKeySpecs {
		g := mustGenerator(spec)
		t.Run(keyGenName(i), func(t *testing.T) {
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
	for i, spec := range allKeySpecs {
		g := mustGenerator(spec)
		t.Run(keyGenName(i), func(t *testing.T) {
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

			assertKeyType(t, config.Key, spec)
		})
	}
}

func TestNewSigningCertificate_WithSubject(t *testing.T) {
	g := mustGenerator(KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048})
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
		name     string
		rootSpec KeySpec
		intSpec  KeySpec
	}{
		{
			name:     "RSA root, RSA intermediate",
			rootSpec: KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048},
			intSpec:  KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 4096},
		},
		{
			name:     "RSA root, ECDSA intermediate",
			rootSpec: KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 4096},
			intSpec:  KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256},
		},
		{
			name:     "ECDSA root, RSA intermediate",
			rootSpec: KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384},
			intSpec:  KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048},
		},
		{
			name:     "ECDSA root, ECDSA intermediate",
			rootSpec: KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256},
			intSpec:  KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rootConfig, err := NewSigningCertificate("root-ca", mustGenerator(tc.rootSpec))
			if err != nil {
				t.Fatalf("root NewSigningCertificate() error = %v", err)
			}
			rootCA := &CA{
				Config:          rootConfig,
				SerialGenerator: &RandomSerialGenerator{},
			}

			intConfig, err := NewSigningCertificate("intermediate-ca", mustGenerator(tc.intSpec),
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
			assertKeyType(t, intConfig.Key, tc.intSpec)
		})
	}
}

func TestNewServerCertificate(t *testing.T) {
	for caI, caSpec := range allKeySpecs {
		caKG := mustGenerator(caSpec)
		for leafI, leafSpec := range allKeySpecs {
			leafKG := mustGenerator(leafSpec)
			name := keyGenName(caI) + "-CA_" + keyGenName(leafI) + "-leaf"
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
				assertKeyType(t, serverConfig.Key, leafSpec)

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
	for caI, caSpec := range allKeySpecs {
		caKG := mustGenerator(caSpec)
		for leafI, leafSpec := range allKeySpecs {
			leafKG := mustGenerator(leafSpec)
			name := keyGenName(caI) + "-CA_" + keyGenName(leafI) + "-leaf"
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
	for i, spec := range allKeySpecs {
		g := mustGenerator(spec)
		t.Run(keyGenName(i), func(t *testing.T) {
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
	g := mustGenerator(KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048})
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

func assertKeyType(t *testing.T, key any, spec KeySpec) {
	t.Helper()
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Errorf("expected a crypto.Signer private key, got %T", key)
		return
	}
	if err := spec.Matches(signer.Public()); err != nil {
		t.Errorf("private key does not match spec: %v", err)
	}
}

func assertHasEKU(t *testing.T, cert *x509.Certificate, eku x509.ExtKeyUsage) {
	t.Helper()
	if !slices.Contains(cert.ExtKeyUsage, eku) {
		t.Errorf("certificate missing ExtKeyUsage %v", eku)
	}
}

func x509pkixName(cn, org string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{org}}
}

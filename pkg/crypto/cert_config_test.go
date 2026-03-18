package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

var allKeyConfigs = []KeyConfig{
	{Algorithm: RSAKeyAlgorithm, RSABits: 2048},
	{Algorithm: RSAKeyAlgorithm, RSABits: 4096},
	{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256},
	{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384},
	{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P521},
}

func keyConfigName(kc KeyConfig) string {
	switch kc.Algorithm {
	case RSAKeyAlgorithm:
		return "RSA-" + string(rune('0'+kc.RSABits/1000)) + "k"
	case ECDSAKeyAlgorithm:
		return "ECDSA-" + string(kc.ECDSACurve)
	}
	return "unknown"
}

func TestKeyConfig_SignatureAlgorithm(t *testing.T) {
	testCases := []struct {
		config  KeyConfig
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 2048}, x509.SHA256WithRSA, false},
		{KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 4096}, x509.SHA256WithRSA, false},
		{KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256}, x509.ECDSAWithSHA256, false},
		{KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384}, x509.ECDSAWithSHA384, false},
		{KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P521}, x509.ECDSAWithSHA512, false},
		{KeyConfig{Algorithm: "invalid"}, 0, true},
		{KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: "invalid"}, 0, true},
	}
	for _, tc := range testCases {
		got, err := tc.config.SignatureAlgorithm()
		if (err != nil) != tc.wantErr {
			t.Errorf("SignatureAlgorithm(%+v) error = %v, wantErr %v", tc.config, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("SignatureAlgorithm(%+v) = %v, want %v", tc.config, got, tc.want)
		}
	}
}

func TestKeyConfig_KeyUsage(t *testing.T) {
	rsaUsage := KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 2048}.KeyUsage()
	if rsaUsage != x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature {
		t.Errorf("RSA KeyUsage = %v, want KeyEncipherment|DigitalSignature", rsaUsage)
	}

	ecdsaUsage := KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256}.KeyUsage()
	if ecdsaUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("ECDSA KeyUsage = %v, want DigitalSignature only", ecdsaUsage)
	}
	if ecdsaUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("ECDSA KeyUsage should not include KeyEncipherment")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	testCases := []struct {
		name   string
		config KeyConfig
	}{
		{"RSA-2048", KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 2048}},
		{"RSA-4096", KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 4096}},
		{"ECDSA-P256", KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256}},
		{"ECDSA-P384", KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384}},
		{"ECDSA-P521", KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P521}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, err := GenerateKeyPair(tc.config)
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}
			if pub == nil || priv == nil {
				t.Fatal("GenerateKeyPair() returned nil key")
			}

			switch tc.config.Algorithm {
			case RSAKeyAlgorithm:
				rsaPub, ok := pub.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("expected *rsa.PublicKey, got %T", pub)
				}
				if rsaPub.N.BitLen() != tc.config.RSABits {
					t.Errorf("RSA key size = %d, want %d", rsaPub.N.BitLen(), tc.config.RSABits)
				}
			case ECDSAKeyAlgorithm:
				ecPub, ok := pub.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
				}
				wantCurve := curveForName(tc.config.ECDSACurve)
				if ecPub.Curve != wantCurve {
					t.Errorf("ECDSA curve = %v, want %v", ecPub.Curve.Params().Name, wantCurve.Params().Name)
				}
			}
		})
	}
}

func TestSubjectKeyIDFromPublicKey(t *testing.T) {
	for _, kc := range allKeyConfigs {
		t.Run(keyConfigName(kc), func(t *testing.T) {
			pub, _, err := GenerateKeyPair(kc)
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}
			skid, err := SubjectKeyIDFromPublicKey(pub)
			if err != nil {
				t.Fatalf("SubjectKeyIDFromPublicKey() error = %v", err)
			}
			// SHA-1 produces 20-byte hash
			if len(skid) != 20 {
				t.Errorf("SubjectKeyID length = %d, want 20", len(skid))
			}
		})
	}
}

func TestNewSigningCertificate(t *testing.T) {
	for _, kc := range allKeyConfigs {
		t.Run(keyConfigName(kc), func(t *testing.T) {
			config, err := NewSigningCertificate("test-ca", kc,
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

			// Self-signed: signature algorithm matches the cert's own key
			wantSigAlg, _ := kc.SignatureAlgorithm()
			if cert.SignatureAlgorithm != wantSigAlg {
				t.Errorf("SignatureAlgorithm = %v, want %v", cert.SignatureAlgorithm, wantSigAlg)
			}

			assertKeyType(t, config.Key, kc)
		})
	}
}

func TestNewSigningCertificate_WithSubject(t *testing.T) {
	kc := KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 2048}
	config, err := NewSigningCertificate("ignored-name", kc,
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
		rootKC KeyConfig
		intKC  KeyConfig
	}{
		{"RSA root, RSA intermediate", KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 2048}, KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 4096}},
		{"RSA root, ECDSA intermediate", KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 4096}, KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256}},
		{"ECDSA root, RSA intermediate", KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384}, KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 2048}},
		{"ECDSA root, ECDSA intermediate", KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256}, KeyConfig{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rootConfig, err := NewSigningCertificate("root-ca", tc.rootKC)
			if err != nil {
				t.Fatalf("root NewSigningCertificate() error = %v", err)
			}
			rootCA := &CA{
				Config:          rootConfig,
				SerialGenerator: &RandomSerialGenerator{},
			}

			intConfig, err := NewSigningCertificate("intermediate-ca", tc.intKC,
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
			assertKeyType(t, intConfig.Key, tc.intKC)

			// Signature algorithm should match the root's key (since root signed it)
			wantSigAlg, _ := tc.rootKC.SignatureAlgorithm()
			if intCert.SignatureAlgorithm != wantSigAlg {
				t.Errorf("SignatureAlgorithm = %v, want %v", intCert.SignatureAlgorithm, wantSigAlg)
			}
		})
	}
}

func TestNewServerCertificate(t *testing.T) {
	for _, caKC := range allKeyConfigs {
		for _, leafKC := range allKeyConfigs {
			name := keyConfigName(caKC) + "-CA_" + keyConfigName(leafKC) + "-leaf"
			t.Run(name, func(t *testing.T) {
				caConfig, err := NewSigningCertificate("test-ca", caKC)
				if err != nil {
					t.Fatalf("NewSigningCertificate() error = %v", err)
				}
				ca := &CA{
					Config:          caConfig,
					SerialGenerator: &RandomSerialGenerator{},
				}

				hostnames := sets.New("localhost", "127.0.0.1", "example.com")
				serverConfig, err := ca.NewServerCertificate(hostnames, leafKC,
					WithLifetime(1*time.Hour),
				)
				if err != nil {
					t.Fatalf("NewServerCertificate() error = %v", err)
				}

				cert := serverConfig.Certs[0]

				// Signature algorithm is determined by the CA's key, not the leaf's
				wantSigAlg, _ := caKC.SignatureAlgorithm()
				if cert.SignatureAlgorithm != wantSigAlg {
					t.Errorf("SignatureAlgorithm = %v, want %v", cert.SignatureAlgorithm, wantSigAlg)
				}
				if cert.IsCA {
					t.Error("server cert should not be CA")
				}
				assertHasEKU(t, cert, x509.ExtKeyUsageServerAuth)
				assertKeyType(t, serverConfig.Key, leafKC)

				// Verify hostnames are in SANs
				if !containsString(cert.DNSNames, "localhost") {
					t.Error("missing DNS SAN: localhost")
				}
				if !containsString(cert.DNSNames, "example.com") {
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
	for _, caKC := range allKeyConfigs {
		for _, leafKC := range allKeyConfigs {
			name := keyConfigName(caKC) + "-CA_" + keyConfigName(leafKC) + "-leaf"
			t.Run(name, func(t *testing.T) {
				caConfig, err := NewSigningCertificate("test-ca", caKC)
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
				clientConfig, err := ca.NewClientCertificate(u, leafKC,
					WithLifetime(1*time.Hour),
				)
				if err != nil {
					t.Fatalf("NewClientCertificate() error = %v", err)
				}

				cert := clientConfig.Certs[0]

				// Signature algorithm is determined by the CA's key, not the leaf's
				wantSigAlg, _ := caKC.SignatureAlgorithm()
				if cert.SignatureAlgorithm != wantSigAlg {
					t.Errorf("SignatureAlgorithm = %v, want %v", cert.SignatureAlgorithm, wantSigAlg)
				}
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
	for _, kc := range allKeyConfigs {
		t.Run(keyConfigName(kc), func(t *testing.T) {
			caConfig, err := NewSigningCertificate("test-ca", kc)
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
			peerConfig, err := ca.NewPeerCertificate(hostnames, u, kc,
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
			if !containsString(cert.DNSNames, "peer.example.com") {
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
	kc := KeyConfig{Algorithm: RSAKeyAlgorithm, RSABits: 2048}
	caConfig, err := NewSigningCertificate("test-ca", kc)
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
		kc,
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

func assertKeyType(t *testing.T, key interface{}, kc KeyConfig) {
	t.Helper()
	switch kc.Algorithm {
	case RSAKeyAlgorithm:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", key)
			return
		}
		if rsaKey.N.BitLen() != kc.RSABits {
			t.Errorf("RSA key size = %d, want %d", rsaKey.N.BitLen(), kc.RSABits)
		}
	case ECDSAKeyAlgorithm:
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
			return
		}
		wantCurve := curveForName(kc.ECDSACurve)
		if ecKey.Curve != wantCurve {
			t.Errorf("ECDSA curve = %v, want %v", ecKey.Curve.Params().Name, wantCurve.Params().Name)
		}
	}
}

func assertHasEKU(t *testing.T, cert *x509.Certificate, eku x509.ExtKeyUsage) {
	t.Helper()
	for _, e := range cert.ExtKeyUsage {
		if e == eku {
			return
		}
	}
	t.Errorf("certificate missing ExtKeyUsage %v", eku)
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
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

func x509pkixName(cn, org string) x509pkix {
	return x509pkix{CommonName: cn, Organization: []string{org}}
}

type x509pkix = pkix.Name

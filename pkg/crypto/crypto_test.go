package crypto

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"go/importer"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

const certificateLifetime = time.Hour * 24 * 365 * 2

func TestDefaultCipherSuite(t *testing.T) {
	// Ensure that conversion of the default cipher suite to names
	// completes without panic.
	_ = CipherSuitesToNamesOrDie(DefaultCiphers())
}

func TestConstantMaps(t *testing.T) {
	pkg, err := importer.Default().Import("crypto/tls")
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		return
	}
	discoveredVersions := map[string]bool{}
	discoveredCiphers := map[string]bool{}
	discoveredCiphersTLS13 := map[string]bool{}
	for _, declName := range pkg.Scope().Names() {
		if strings.HasPrefix(declName, "VersionTLS") {
			discoveredVersions[declName] = true
		}
		if strings.HasPrefix(declName, "TLS_RSA_") || strings.HasPrefix(declName, "TLS_ECDHE_") {
			discoveredCiphers[declName] = true
		}
		if strings.HasPrefix(declName, "TLS_AES_") || strings.HasPrefix(declName, "TLS_CHACHA20_") {
			discoveredCiphersTLS13[declName] = true
		}
	}

	for k := range discoveredCiphers {
		if _, ok := ciphers[k]; !ok {
			t.Errorf("discovered cipher tls.%s not in ciphers map", k)
		}
	}
	for k := range ciphers {
		if _, ok := discoveredCiphers[k]; !ok {
			t.Errorf("ciphers map has %s not in tls package", k)
		}
	}

	for k := range discoveredCiphersTLS13 {
		if _, ok := ciphersTLS13[k]; !ok {
			t.Errorf("discovered cipher tls.%s not in ciphers map", k)
		}
	}
	for k := range ciphersTLS13 {
		if _, ok := discoveredCiphersTLS13[k]; !ok {
			t.Errorf("ciphersTLS13 map has %s not in tls package", k)
		}
	}

	for k := range discoveredVersions {
		if _, ok := versions[k]; !ok {
			t.Errorf("discovered version tls.%s not in version map", k)
		}
	}
	for k := range versions {
		if _, ok := discoveredVersions[k]; !ok {
			t.Errorf("versions map has %s not in tls package", k)
		}
	}

	for k := range supportedVersions {
		if _, ok := discoveredVersions[k]; !ok {
			t.Errorf("supported versions map has %s not in tls package", k)
		}
	}

}

func TestCrypto(t *testing.T) {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	// Test CA
	fmt.Println("Building CA...")
	caKey, caCrt := buildCA(t)
	roots.AddCert(caCrt)

	// Test intermediate
	fmt.Println("Building intermediate 1...")
	intKey, intCrt := buildIntermediate(t, caKey, caCrt)
	verify(t, intCrt, x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}, true, 2)
	intermediates.AddCert(intCrt)

	// Test intermediate 2
	fmt.Println("Building intermediate 2...")
	intKey2, intCrt2 := buildIntermediate(t, intKey, intCrt)
	verify(t, intCrt2, x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}, true, 3)
	intermediates.AddCert(intCrt2)

	// Test server cert
	fmt.Println("Building server...")
	_, serverCrt := buildServer(t, intKey2, intCrt2)
	verify(t, serverCrt, x509.VerifyOptions{
		DNSName:       "localhost",
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, true, 4)
	verify(t, serverCrt, x509.VerifyOptions{
		DNSName:       "www.example.com",
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, true, 4)
	verify(t, serverCrt, x509.VerifyOptions{
		DNSName:       "127.0.0.1",
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, true, 4)
	verify(t, serverCrt, x509.VerifyOptions{
		DNSName:       "www.foo.com",
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, false, 4)

	// Test client cert
	fmt.Println("Building client...")
	_, clientCrt := buildClient(t, intKey2, intCrt2)
	verify(t, clientCrt, x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, true, 4)
}

// Can be used for CA or intermediate signing certs
func newSigningCertificateTemplate(subject pkix.Name, lifetime time.Duration, currentTime func() time.Time) *x509.Certificate {
	if lifetime <= 0 {
		lifetime = DefaultCACertificateLifetimeDuration
		fmt.Fprintf(os.Stderr, "Validity period of the certificate for %q is unset, resetting to %d years!\n", subject.CommonName, lifetime)
	}

	if lifetime > DefaultCACertificateLifetimeDuration {
		warnAboutCertificateLifeTime(subject.CommonName, DefaultCACertificateLifetimeDuration)
	}

	return newSigningCertificateTemplateForDuration(subject, lifetime, currentTime, nil, nil)
}

func buildCA(t *testing.T) (crypto.PrivateKey, *x509.Certificate) {
	caPublicKey, caPrivateKey, err := NewKeyPair()
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	caTemplate := newSigningCertificateTemplate(pkix.Name{CommonName: "CA"}, certificateLifetime, time.Now)
	caCrt, err := signCertificate(caTemplate, caPublicKey, caTemplate, caPrivateKey)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	return caPrivateKey, caCrt
}

func buildIntermediate(t *testing.T, signingKey crypto.PrivateKey, signingCrt *x509.Certificate) (crypto.PrivateKey, *x509.Certificate) {
	intermediatePublicKey, intermediatePrivateKey, err := NewKeyPair()
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	intermediateTemplate := newSigningCertificateTemplate(pkix.Name{CommonName: "Intermediate"}, certificateLifetime, time.Now)
	intermediateCrt, err := signCertificate(intermediateTemplate, intermediatePublicKey, signingCrt, signingKey)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if err := intermediateCrt.CheckSignatureFrom(signingCrt); err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	return intermediatePrivateKey, intermediateCrt
}

func buildServer(t *testing.T, signingKey crypto.PrivateKey, signingCrt *x509.Certificate) (crypto.PrivateKey, *x509.Certificate) {
	serverPublicKey, serverPrivateKey, err := NewKeyPair()
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	hosts := []string{"127.0.0.1", "localhost", "www.example.com"}
	serverTemplate := newServerCertificateTemplate(pkix.Name{CommonName: "Server"}, hosts, certificateLifetime, time.Now, nil, nil)
	serverCrt, err := signCertificate(serverTemplate, serverPublicKey, signingCrt, signingKey)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if err := serverCrt.CheckSignatureFrom(signingCrt); err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	return serverPrivateKey, serverCrt
}

func buildClient(t *testing.T, signingKey crypto.PrivateKey, signingCrt *x509.Certificate) (crypto.PrivateKey, *x509.Certificate) {
	clientPublicKey, clientPrivateKey, err := NewKeyPair()
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	clientTemplate := NewClientCertificateTemplate(pkix.Name{CommonName: "Client"}, certificateLifetime, time.Now)
	clientCrt, err := signCertificate(clientTemplate, clientPublicKey, signingCrt, signingKey)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if err := clientCrt.CheckSignatureFrom(signingCrt); err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	return clientPrivateKey, clientCrt
}

func verify(t *testing.T, cert *x509.Certificate, opts x509.VerifyOptions, success bool, chainLength int) {
	validChains, err := cert.Verify(opts)
	if success {
		if err != nil {
			t.Fatalf("Unexpected error: %#v", err)
		}
		if len(validChains) != 1 {
			t.Fatalf("Expected a valid chain")
		}
		if len(validChains[0]) != chainLength {
			t.Fatalf("Expected a valid chain of length %d, got %d", chainLength, len(validChains[0]))
		}
	} else if err == nil && len(validChains) > 0 {
		t.Fatalf("Expected failure, got success")
	}
}

func TestRandomSerialGenerator(t *testing.T) {
	generator := &RandomSerialGenerator{}

	hostnames := []string{"foo", "bar"}
	template := newServerCertificateTemplate(pkix.Name{CommonName: hostnames[0]}, hostnames, certificateLifetime, time.Now, nil, nil)
	if _, err := generator.Next(template); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidityPeriodOfClientCertificate(t *testing.T) {
	currentTime := time.Now()

	currentFakeTime := func() time.Time {
		return currentTime
	}

	tests := []struct {
		passedExpireDuration time.Duration
		realExpireDuration   time.Duration
	}{
		{
			passedExpireDuration: time.Hour,
			realExpireDuration:   time.Hour,
		},
		{
			passedExpireDuration: 0,
			realExpireDuration:   DefaultCertificateLifetimeDuration,
		},
		{
			passedExpireDuration: -time.Hour,
			realExpireDuration:   DefaultCertificateLifetimeDuration,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("passed=%v,real=%v", test.passedExpireDuration, test.realExpireDuration), func(t *testing.T) {
			cert := NewClientCertificateTemplate(pkix.Name{CommonName: "client"}, test.passedExpireDuration, currentFakeTime)
			expirationDate := cert.NotAfter
			expectedExpirationDate := currentTime.Add(test.realExpireDuration)
			if expectedExpirationDate != expirationDate {
				t.Errorf("expected that client certificate will expire at %v but found %v", expectedExpirationDate, expirationDate)
			}
		})
	}
}

func TestValidityPeriodOfServerCertificate(t *testing.T) {
	currentTime := time.Now()

	currentFakeTime := func() time.Time {
		return currentTime
	}

	tests := []struct {
		passedDuration time.Duration
		realDuration   time.Duration
	}{
		{
			passedDuration: time.Hour,
			realDuration:   time.Hour,
		},
		{
			passedDuration: 0,
			realDuration:   DefaultCertificateLifetimeDuration,
		},
		{
			passedDuration: -time.Hour,
			realDuration:   DefaultCertificateLifetimeDuration,
		},
	}

	for _, test := range tests {
		cert := newServerCertificateTemplate(
			pkix.Name{CommonName: "server"},
			[]string{"www.example.com"},
			test.passedDuration,
			currentFakeTime,
			nil,
			nil,
		)
		expirationDate := cert.NotAfter
		expectedExpirationDate := currentTime.Add(test.realDuration)
		if expectedExpirationDate != expirationDate {
			t.Errorf("expected that server certificate will expire at %v but found %v", expectedExpirationDate, expirationDate)
		}
	}
}

func TestValidityPeriodOfSigningCertificate(t *testing.T) {
	currentTime := time.Now()

	currentFakeTime := func() time.Time {
		return currentTime
	}

	tests := []struct {
		passedDuration time.Duration
		realDuration   time.Duration
	}{
		{
			passedDuration: time.Hour,
			realDuration:   time.Hour,
		},
		{
			passedDuration: 0,
			realDuration:   DefaultCACertificateLifetimeDuration,
		},
		{
			passedDuration: -time.Hour,
			realDuration:   DefaultCACertificateLifetimeDuration,
		},
	}

	for _, test := range tests {
		cert := newSigningCertificateTemplate(pkix.Name{CommonName: "CA"}, test.passedDuration, currentFakeTime)
		expirationDate := cert.NotAfter
		expectedExpirationDate := currentTime.Add(test.realDuration)
		if expectedExpirationDate != expirationDate {
			t.Errorf("expected that CA certificate will expire at %v but found %v", expectedExpirationDate, expirationDate)
		}
	}
}

func TestCertGeneration(t *testing.T) {
	testDir := t.TempDir()
	certfile := filepath.Join(testDir, "ca.crt")
	keyfile := filepath.Join(testDir, "ca.key")
	serialfile := filepath.Join(testDir, "serial.txt")

	// create a new CA
	ca, created, err := EnsureCA(certfile, keyfile, serialfile, "testca", 1)
	require.NoError(t, err)
	require.NotNil(t, ca)
	require.True(t, created)

	// ensure the new CA is still there but does not get recreated
	ca, created, err = EnsureCA(certfile, keyfile, serialfile, "testca", 1)
	require.NoError(t, err)
	require.NotNil(t, ca)
	require.False(t, created) // this should be false now

	require.Equal(t, "testca", ca.Config.Certs[0].Subject.CommonName)
	require.Equal(t, "testca", ca.Config.Certs[0].Issuer.CommonName)

	subCADir := filepath.Join(testDir, "subca")
	subCACertfile := filepath.Join(subCADir, "ca.crt")
	subCAKeyfile := filepath.Join(subCADir, "ca.key")
	subCASerialfile := filepath.Join(subCADir, "serial.txt")

	// create a new subCA
	subCA, created, err := ca.EnsureSubCA(subCACertfile, subCAKeyfile, subCASerialfile, "subca", 1)
	require.NoError(t, err)
	require.NotNil(t, subCA)
	require.True(t, created)

	// ensure the new subCA is still there but does not get recreated
	subCA, created, err = ca.EnsureSubCA(subCACertfile, subCAKeyfile, subCASerialfile, "subca", 1)
	require.NoError(t, err)
	require.NotNil(t, subCA)
	require.False(t, created)

	require.Equal(t, "subca", subCA.Config.Certs[0].Subject.CommonName)
	require.Equal(t, "testca", subCA.Config.Certs[0].Issuer.CommonName)
	require.Len(t, subCA.Config.Certs, 2, "expected the sub-CA cert bundle to contain subCA and signing CA certs")
	require.Equal(t, ca.Config.Certs[0].Raw, subCA.Config.Certs[1].Raw)
	require.Equal(t, ca.Config.Certs[0].SubjectKeyId, subCA.Config.Certs[0].AuthorityKeyId, "expected the sub-CA to be signed by the signer CA")

	serverCertDir := filepath.Join(subCADir, "server")
	serverCertFile := filepath.Join(serverCertDir, "server.crt")
	serverKeyFile := filepath.Join(serverCertDir, "server.key")
	hostnames := sets.New("myserver.local", "veryglobal.tho", "192.168.0.1")

	// create a new server cert signed by the sub-CA
	serverCert, created, err := subCA.EnsureServerCert(serverCertFile, serverKeyFile, hostnames, 1)
	require.NoError(t, err)
	require.NotNil(t, serverCert)
	require.True(t, created)

	// ensure the new server cert signed by the sub-CA exists and does not get recreated
	serverCert, created, err = subCA.EnsureServerCert(serverCertFile, serverKeyFile, hostnames, 1)
	require.NoError(t, err)
	require.NotNil(t, serverCert)
	require.False(t, created)

	require.Len(t, serverCert.Certs, 3)
	require.Equal(t, "192.168.0.1", serverCert.Certs[0].Subject.CommonName)
	require.Equal(t, "subca", serverCert.Certs[0].Issuer.CommonName)
	sortedDNSNames := sort.StringSlice(serverCert.Certs[0].DNSNames)
	sortedDNSNames.Sort()
	require.Equal(t, sets.List(hostnames), []string(sortedDNSNames))
	require.Equal(t, subCA.Config.Certs[0].SubjectKeyId, serverCert.Certs[0].AuthorityKeyId)

	clientCertDir := filepath.Join(testDir, "client")
	clientCertFile := filepath.Join(clientCertDir, "client.crt")
	clientKeyFile := filepath.Join(clientCertDir, "client.key")

	// create a new client cert signed by the root CA
	clientCert, created, err := ca.EnsureClientCertificate(clientCertFile, clientKeyFile, &user.DefaultInfo{Name: "testclient", Groups: []string{"testclients"}}, 1)
	require.NoError(t, err)
	require.NotNil(t, clientCert)
	require.True(t, created)

	// ensure the new client cert signed by the root CA exists and does not get recreated
	clientCert, created, err = ca.EnsureClientCertificate(clientCertFile, clientKeyFile, &user.DefaultInfo{Name: "testclient", Groups: []string{"testclients"}}, 1)
	require.NoError(t, err)
	require.NotNil(t, clientCert)
	require.False(t, created)

	require.Len(t, clientCert.Certs, 1) // we don't need to include the whole chain, unlike in server certs
	require.Equal(t, "testclient", clientCert.Certs[0].Subject.CommonName)
	require.Equal(t, []string{"testclients"}, clientCert.Certs[0].Subject.Organization)
	require.Equal(t, ca.Config.Certs[0].SubjectKeyId, clientCert.Certs[0].AuthorityKeyId)

	// ensure the new client cert signed by the root CA exists but gets regenerated because the Subject changes
	clientCert, created, err = ca.EnsureClientCertificate(clientCertFile, clientKeyFile, &user.DefaultInfo{Name: "testclient2", Groups: []string{"testclients"}}, 2)
	require.NoError(t, err)
	require.NotNil(t, clientCert)
	require.True(t, created)

	require.Len(t, clientCert.Certs, 1)
	require.Equal(t, "testclient2", clientCert.Certs[0].Subject.CommonName)
	require.Equal(t, []string{"testclients"}, clientCert.Certs[0].Subject.Organization)
	require.Equal(t, ca.Config.Certs[0].SubjectKeyId, clientCert.Certs[0].AuthorityKeyId)

	// ensure the new client cert signed by the root CA exists but gets regenerated because the groups change
	clientCert, created, err = ca.EnsureClientCertificate(clientCertFile, clientKeyFile, &user.DefaultInfo{Name: "testclient2", Groups: []string{"testclients", "newgroup"}}, 2)
	require.NoError(t, err)
	require.NotNil(t, clientCert)
	require.True(t, created)

	require.Len(t, clientCert.Certs, 1)
	require.Equal(t, "testclient2", clientCert.Certs[0].Subject.CommonName)
	require.ElementsMatch(t, []string{"testclients", "newgroup"}, clientCert.Certs[0].Subject.Organization)
	require.Equal(t, ca.Config.Certs[0].SubjectKeyId, clientCert.Certs[0].AuthorityKeyId)
}

func TestSubjectChanged(t *testing.T) {
	subject1 := pkix.Name{
		CommonName:   "testclient",
		Organization: []string{"testclients", "testclients2"},
		SerialNumber: "1234",
	}

	// ensure no change is detected for equal subjects
	require.False(t, subjectChanged(subject1, subject1))

	// ensure no change is detected for out of order organization//groups
	subject2 := pkix.Name{
		CommonName:   subject1.CommonName,
		Organization: []string{"testclients2", "testclients"},
		SerialNumber: subject1.SerialNumber,
	}
	require.False(t, subjectChanged(subject1, subject2))

	// ensure change is detected for different organization//groups
	subject2 = pkix.Name{
		CommonName:   subject1.CommonName,
		Organization: []string{"diff", "testclients"},
		SerialNumber: subject1.SerialNumber,
	}
	require.True(t, subjectChanged(subject1, subject2))

	// ensure change is detected for common name
	subject2 = pkix.Name{
		CommonName:   "changed",
		Organization: subject1.Organization,
		SerialNumber: subject1.SerialNumber,
	}
	require.True(t, subjectChanged(subject1, subject2))

	// ensure change is detected for different organization//groups
	subject2 = pkix.Name{
		CommonName:   subject1.CommonName,
		Organization: subject1.Organization,
		SerialNumber: "changed",
	}
	require.True(t, subjectChanged(subject1, subject2))
}

func TestServerCertRegeneration(t *testing.T) {
	testDir := t.TempDir()
	certfile := filepath.Join(testDir, "ca.crt")
	keyfile := filepath.Join(testDir, "ca.key")
	serialfile := filepath.Join(testDir, "serial.txt")

	ca, created, err := EnsureCA(certfile, keyfile, serialfile, "testca", 1)
	require.NoError(t, err)
	require.NotNil(t, ca)
	require.True(t, created)

	serverCertDir := filepath.Join(testDir, "server")
	serverCertFile := filepath.Join(serverCertDir, "server.crt")
	serverKeyFile := filepath.Join(serverCertDir, "server.key")
	hostnames := sets.New("myserver.local", "veryglobal.tho", "192.168.0.1")

	serverCert, created, err := ca.EnsureServerCert(serverCertFile, serverKeyFile, hostnames, 1)
	require.NoError(t, err)
	require.NotNil(t, serverCert)
	require.True(t, created)

	serverCert, created, err = ca.EnsureServerCert(serverCertFile, serverKeyFile, hostnames, 1)
	require.NoError(t, err)
	require.NotNil(t, serverCert)
	require.False(t, created)

	hostnames.Insert("secondname.local")
	serverCert, created, err = ca.EnsureServerCert(serverCertFile, serverKeyFile, hostnames, 1)
	require.NoError(t, err)
	require.NotNil(t, serverCert)
	require.True(t, created)

	hostnames.Delete("secondname.local")
	serverCert, created, err = ca.EnsureServerCert(serverCertFile, serverKeyFile, hostnames, 1)
	require.NoError(t, err)
	require.NotNil(t, serverCert)
	require.True(t, created)
}

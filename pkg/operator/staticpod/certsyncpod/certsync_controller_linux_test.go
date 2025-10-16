//go:build linux

package certsyncpod

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"github.com/openshift/library-go/pkg/operator/staticpod/internal/atomicdir"
	"github.com/openshift/library-go/pkg/operator/staticpod/internal/atomicdir/types"
)

// TestDynamicCertificates makes sure the receiving side of certificate synchronization works as expected.
// It reads and watches the certificates being synchronized in the same way as e.g. kube-apiserver,
// the very same libraries are being used.
func TestDynamicCertificates(t *testing.T) {
	const typeName = "secret"
	om := metav1.ObjectMeta{
		Namespace: "openshift-kube-apiserver",
		Name:      "s1",
	}

	// Generate all necessary keypairs.
	tlsCert, tlsKey := generateKeypair(t)
	tlsCertUpdated, tlsKeyUpdated := generateKeypair(t)

	// Write the keypair into a secret directory.
	secretDir := filepath.Join(t.TempDir(), "secrets", om.Name)
	stagingDir := filepath.Join(t.TempDir(), "staging", stagingDirUID, "secrets", om.Name)
	certFile := filepath.Join(secretDir, "tls.crt")
	keyFile := filepath.Join(secretDir, "tls.key")

	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatalf("Failed to create secret directory %q: %v", secretDir, err)
	}
	if err := os.WriteFile(certFile, tlsCert, 0600); err != nil {
		t.Fatalf("Failed to write TLS certificate into %q: %v", certFile, err)
	}
	if err := os.WriteFile(keyFile, tlsKey, 0600); err != nil {
		t.Fatalf("Failed to write TLS key into %q: %v", keyFile, err)
	}

	// Start the watcher.
	// This reads the keypair synchronously so the initial state is loaded here.
	dc, err := dynamiccertificates.NewDynamicServingContentFromFiles("localhost TLS", certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to init dynamic certificate: %v", err)
	}

	// Check the initial keypair is loaded.
	cert, key := dc.CurrentCertKeyContent()
	if !bytes.Equal(cert, tlsCert) || !bytes.Equal(key, tlsKey) {
		t.Fatal("Unexpected initial keypair loaded")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		dc.Run(ctx, 1)
	}()
	defer wg.Wait()
	defer cancel()

	// Poll until update detected.
	files := map[string]types.File{
		"tls.crt": {Content: tlsCertUpdated, Perm: 0600},
		"tls.key": {Content: tlsKeyUpdated, Perm: 0600},
	}
	err = wait.PollUntilContextCancel(ctx, 250*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		// Replace the secret directory.
		if err := atomicdir.Sync(secretDir, 0700, stagingDir, files); err != nil {
			t.Errorf("Failed to write files: %v", err)
			return false, err
		}

		// Check the loaded content matches.
		// This is most probably updated based on write in a previous Poll invocation.
		cert, key := dc.CurrentCertKeyContent()
		return bytes.Equal(cert, tlsCertUpdated) && bytes.Equal(key, tlsKeyUpdated), nil
	})
	if err != nil {
		t.Fatalf("Failed to wait for dynamic certificate: %v", err)
	}
}

// generateKeypair returns (cert, key).
func generateKeypair(t *testing.T) ([]byte, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate TLS key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(1 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("Failed to generate serial number for TLS keypair: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Example Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
	}

	publicKeyBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create TLS certificate: %v", err)
	}

	var certOut bytes.Buffer
	if err := pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: publicKeyBytes}); err != nil {
		t.Fatalf("Failed to write certificate PEM: %v", err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Unable to marshal private key: %v", err)
	}

	var keyOut bytes.Buffer
	if err := pem.Encode(&keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		t.Fatalf("Failed to write certificate PEM: %v", err)
	}

	return certOut.Bytes(), keyOut.Bytes()
}

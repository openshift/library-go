package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"

	"k8s.io/client-go/util/keyutil"
)

// Size for generated RSA key pairs
const keySize = 4096

// CheckRSAKeyPair returns an error if the provided public and private
// key bytes do not comprise a valid RSA key pair.
func CheckRSAKeyPair(pubKeyData, privKeyData []byte) error {
	privKey, err := keyutil.ParsePrivateKeyPEM(privKeyData)
	if err != nil {
		return err
	}
	rsaPrivateKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not of rsa type")
	}
	pubKeys, err := keyutil.ParsePublicKeysPEM(pubKeyData)
	if err != nil {
		return err
	}
	wantRSAPublicKey, ok := pubKeys[0].(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not of rsa type")
	}
	// The private key embeds the public key and the embedded key must
	// match the provided public key.
	if !reflect.DeepEqual(rsaPrivateKey.PublicKey, *wantRSAPublicKey) {
		return fmt.Errorf("key pair do not match")
	}
	return nil
}

// GenerateRSAKeyPair creates a new RSA key pair and returns the
// public and private keys as PEM-encoded bytes.
func GenerateRSAKeyPair() ([]byte, []byte, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	pubKeyPEM, err := publicKeyToPem(&rsaKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privKeyPEM, err := keyutil.MarshalPrivateKeyToPEM(rsaKey)
	if err != nil {
		return nil, nil, err
	}
	return pubKeyPEM, privKeyPEM, nil
}

// publicKeyToPem derives the RSA public key from its private key and
// returns it as PEM-encoded bytes.
func publicKeyToPem(key *rsa.PublicKey) ([]byte, error) {
	keyInBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	keyinPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: keyInBytes,
		},
	)
	return keyinPem, nil
}

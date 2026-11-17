package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ErrUnknownKeyAlgorithm reports a private key that is well-formed PEM of a
// recognized private key block family but whose key algorithm this build
// cannot identify. A future key algorithm (for example a post-quantum
// signature scheme supported by a newer build) parses as this error rather
// than as malformed data, so callers can distinguish "this binary cannot
// judge this key" from "this key is corrupt". Rotation logic uses the
// distinction to avoid fighting a newer binary that owns the artifact.
var ErrUnknownKeyAlgorithm = errors.New("private key algorithm not recognized by this build")

// privateKeyPEMBlockTypes that this build knows how to interpret.
const (
	pemBlockRSAPrivateKey = "RSA PRIVATE KEY"
	pemBlockECPrivateKey  = "EC PRIVATE KEY"
	pemBlockPKCS8         = "PRIVATE KEY"
)

// ParsePrivateKeyPEM parses a PEM-encoded private key from the raw bytes of a
// TLS secret's key data. Malformed input (missing PEM block, wrong block
// type, or undecodable key data) returns an error wrapping the parse failure.
// A well-formed private key PEM whose algorithm this build does not recognize
// returns an error wrapping ErrUnknownKeyAlgorithm.
//
// The returned key is one of *rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey.
func ParsePrivateKeyPEM(keyBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in key data")
	}

	switch block.Type {
	case pemBlockRSAPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing RSA private key: %w", err)
		}
		return key, nil
	case pemBlockECPrivateKey:
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing EC private key: %w", err)
		}
		return key, nil
	case pemBlockPKCS8:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing PKCS#8 private key: %w", err)
		}
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("%w: PKCS#8 key of type %T", ErrUnknownKeyAlgorithm, key)
		}
	default:
		if isPrivateKeyPEMBlockType(block.Type) {
			return nil, fmt.Errorf("%w: PEM block type %q", ErrUnknownKeyAlgorithm, block.Type)
		}
		return nil, fmt.Errorf("unexpected PEM block type %q, expected a private key", block.Type)
	}
}

// isPrivateKeyPEMBlockType reports whether the block type belongs to the
// private key family: it names a private key (RFC 7468 conventional suffix
// "PRIVATE KEY") without a stricter structure this build knows. Recognized
// algorithm-specific types are excluded by the caller's switch.
func isPrivateKeyPEMBlockType(blockType string) bool {
	if blockType == pemBlockRSAPrivateKey || blockType == pemBlockECPrivateKey || blockType == pemBlockPKCS8 {
		return false
	}
	return strings.HasSuffix(blockType, "PRIVATE KEY")
}

// KeyAlgorithmForPrivateKey identifies the key algorithm of a parsed private
// key. It returns ErrUnknownKeyAlgorithm for key types outside the set this
// build can generate, so key-drift comparison can treat them as "cannot
// judge" rather than as a mismatch.
func KeyAlgorithmForPrivateKey(key crypto.PrivateKey) (KeyAlgorithm, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return "RSA", nil
	case *ecdsa.PrivateKey:
		return "ECDSA", nil
	case ed25519.PrivateKey:
		return "Ed25519", nil
	default:
		return "", fmt.Errorf("%w: key of type %T", ErrUnknownKeyAlgorithm, key)
	}
}

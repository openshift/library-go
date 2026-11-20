package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// pkcs8PrivateKey is the outer structure of a PKCS#8 private key encoding.
// Parsing it independently of x509.ParsePKCS8PrivateKey lets
// ParsePrivateKeyPEM distinguish a well-formed key with an algorithm this
// build does not know (a future writer's certificate) from malformed data.
type pkcs8PrivateKey struct {
	Version    int
	Algorithm  pkixAlgorithmIdentifier
	PrivateKey []byte
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

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
			// New key algorithms ship as PKCS#8. When Go does not know the
			// algorithm OID, ParsePKCS8PrivateKey fails with a generic error;
			// parse the outer structure to tell a well-formed future key
			// from corrupt data.
			var outer pkcs8PrivateKey
			if _, outerErr := asn1.Unmarshal(block.Bytes, &outer); outerErr == nil && len(outer.PrivateKey) > 0 {
				return nil, fmt.Errorf("%w: PKCS#8 key with algorithm %s", ErrUnknownKeyAlgorithm, outer.Algorithm.Algorithm)
			}
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
	switch blockType {
	case "ENCRYPTED PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY":
		// Unusable in this context, but not a future algorithm either.
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

// KeyDescriptionForPrivateKey describes a parsed private key including its
// parameters: "RSA-2048", "ECDSA-P256", "Ed25519". Two keys drift apart when
// their descriptions differ, so a key-size or curve change in resolved
// configuration is detected, not just an algorithm-family change. Key types
// this build cannot inspect return ErrUnknownKeyAlgorithm.
func KeyDescriptionForPrivateKey(key crypto.PrivateKey) (string, error) {
	switch typedKey := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("RSA-%d", typedKey.N.BitLen()), nil
	case *ecdsa.PrivateKey:
		return fmt.Sprintf("ECDSA-%s", curveName(typedKey.Curve)), nil
	case ed25519.PrivateKey:
		return "Ed25519", nil
	default:
		return "", fmt.Errorf("%w: key of type %T", ErrUnknownKeyAlgorithm, key)
	}
}

// KeyDescriptionForGenerator describes a key pair generator in the same
// vocabulary as KeyDescriptionForPrivateKey, for drift comparison.
func KeyDescriptionForGenerator(gen KeyPairGenerator) string {
	switch g := gen.(type) {
	case RSAKeyPairGenerator:
		return fmt.Sprintf("RSA-%d", g.Bits)
	case ECDSAKeyPairGenerator:
		return fmt.Sprintf("ECDSA-%s", g.Curve)
	default:
		return ""
	}
}

func curveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P256"
	case elliptic.P384():
		return "P384"
	case elliptic.P521():
		return "P521"
	default:
		return fmt.Sprintf("%v", curve)
	}
}

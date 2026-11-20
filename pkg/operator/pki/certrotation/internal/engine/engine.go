// Package engine holds the pure decision core of certificate rotation:
// classify an artifact's state from parsed contents and inputs, then decide
// an action for a role. Everything here is free of clients and side effects,
// so every decision boundary is table-testable on an injected clock.
//
// Source of truth: classification reads the parsed resource contents (the
// certificate and key from tls.crt/tls.key, the bundle PEM from the
// configmap), never the rotation annotations. Annotations are write-only
// output for external readers. The single annotation consulted is the
// force-regeneration sentinel on the not-after annotation, an inbound
// command from oc that cannot be derived from contents.
package engine

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
)

// State is the classification of one artifact. Precedence is the order of
// the constants: Missing, then Invalid, then Expired, and so on down to
// Current. The first match wins the reason string.
type State string

const (
	// StateMissing: the object does not exist.
	StateMissing State = "Missing"

	// StateInvalid: the data is definitively malformed (unparseable PEM,
	// truncated key, mismatched cert and key) or the not-after annotation
	// carries the force-regeneration sentinel. A well-formed key whose
	// algorithm this build does not recognize is NOT Invalid; see
	// StateCurrent and the unknown-key rule.
	StateInvalid State = "Invalid"

	// StateExpired: now is past the certificate's NotAfter, parsed from
	// tls.crt.
	StateExpired State = "Expired"

	// StateDue: the artifact reached its scheduled rotation boundary:
	// past 80% of its validity, or past its refresh period measured from
	// the certificate's NotBefore. For targets, the refresh boundary only
	// applies once the current signer is at least Refresh/10 into its
	// life, so trust has propagated before leaves rotate.
	StateDue State = "Due"

	// StateStaleTrust (targets only): the leaf's issuer is not present in
	// the persisted CA bundle.
	StateStaleTrust State = "StaleTrust"

	// StateHostnameDrift (serving and peer targets only): the certificate's
	// SAN set differs from the desired hostnames.
	StateHostnameDrift State = "HostnameDrift"

	// StateKeyDrift: under ConfigurablePKI, the resolved key algorithm
	// differs from the key the artifact currently holds.
	StateKeyDrift State = "KeyDrift"

	// StateCurrent: nothing above matched. This includes well-formed keys
	// whose algorithm this build cannot recognize: the binary that can
	// judge them owns them.
	StateCurrent State = "Current"
)

// Action is what the reconciler should do with an artifact.
type Action string

const (
	ActionNone       Action = "none"
	ActionCreate     Action = "create"
	ActionRegenerate Action = "regenerate"
	ActionRepairMeta Action = "repair-metadata"
)

// SignerInputs carries everything classification needs about a signer
// artifact. ParsedCert and ParsedKey come from the persisted secret's
// tls.crt and tls.key; NotAfterAnnotation is read only to compare against
// the force-regeneration sentinel.
type SignerInputs struct {
	// Exists is false when the secret is absent.
	Exists bool
	// ParsedCert is the leaf certificate parsed from tls.crt. Nil when the
	// data is missing or malformed.
	ParsedCert *x509.Certificate
	// ParsedKey is the private key parsed from tls.key. Nil when missing or
	// malformed; KeyParseErr carries the parse result.
	ParsedKey   stdcrypto.PrivateKey
	KeyParseErr error
	// NotAfterAnnotation is the raw not-after annotation value, consulted
	// only for the force-regeneration sentinel.
	NotAfterAnnotation string
	// Refresh is the configured refresh period of the signer.
	Refresh time.Duration
	// ResolvedKeyAlgorithm is the key algorithm the PKI resolution would
	// issue now. Empty when PKI is legacy or resolution did not run.
	ResolvedKeyAlgorithm string
}

// ClassifySigner classifies the signer artifact.
func ClassifySigner(inputs SignerInputs, now time.Time) (State, string) {
	if !inputs.Exists {
		return StateMissing, "signer secret does not exist"
	}
	if reason, invalid := invalidData(inputs.ParsedCert, inputs.ParsedKey, inputs.KeyParseErr, inputs.NotAfterAnnotation); invalid {
		return StateInvalid, reason
	}
	if now.After(inputs.ParsedCert.NotAfter) {
		return StateExpired, fmt.Sprintf("signer expired at %s", inputs.ParsedCert.NotAfter.Format(time.RFC3339))
	}
	validity := inputs.ParsedCert.NotAfter.Sub(inputs.ParsedCert.NotBefore)
	if now.After(inputs.ParsedCert.NotAfter.Add(-validity / 5)) {
		return StateDue, "past 80% of signer validity"
	}
	if now.After(inputs.ParsedCert.NotBefore.Add(inputs.Refresh)) {
		return StateDue, fmt.Sprintf("past signer refresh period of %s", inputs.Refresh)
	}
	if inputs.ResolvedKeyAlgorithm != "" {
		if description, err := crypto.KeyDescriptionForPrivateKey(inputs.ParsedKey); err == nil && description != inputs.ResolvedKeyAlgorithm {
			return StateKeyDrift, fmt.Sprintf("signer key is %s, resolved key is %s", description, inputs.ResolvedKeyAlgorithm)
		}
	}
	return StateCurrent, ""
}

// TargetInputs carries everything classification needs about a target
// artifact, including the persisted signer and bundle the target is checked
// against.
type TargetInputs struct {
	Exists             bool
	ParsedCert         *x509.Certificate
	ParsedKey          stdcrypto.PrivateKey
	KeyParseErr        error
	NotAfterAnnotation string
	Refresh            time.Duration
	DesiredHostnames   []string
	// SignerNotBefore is the current signer certificate's NotBefore, for
	// the trust-propagation gate.
	SignerNotBefore time.Time
	// BundleCerts is the parsed content of the persisted CA bundle.
	BundleCerts []*x509.Certificate
	// ResolvedKeyAlgorithm is the key algorithm the PKI resolution would
	// issue now. Empty when PKI is legacy or resolution did not run.
	ResolvedKeyAlgorithm string
}

// ClassifyTarget classifies a target artifact.
func ClassifyTarget(inputs TargetInputs, now time.Time) (State, string) {
	if !inputs.Exists {
		return StateMissing, "target secret does not exist"
	}
	if reason, invalid := invalidData(inputs.ParsedCert, inputs.ParsedKey, inputs.KeyParseErr, inputs.NotAfterAnnotation); invalid {
		return StateInvalid, reason
	}
	if now.After(inputs.ParsedCert.NotAfter) {
		return StateExpired, fmt.Sprintf("target expired at %s", inputs.ParsedCert.NotAfter.Format(time.RFC3339))
	}
	validity := inputs.ParsedCert.NotAfter.Sub(inputs.ParsedCert.NotBefore)
	if now.After(inputs.ParsedCert.NotAfter.Add(-validity / 5)) {
		return StateDue, "past 80% of target validity"
	}
	// The refresh boundary only applies once the current signer has been
	// alive long enough for its trust to propagate. As in v1, the wait is
	// the target's own refresh period divided by ten.
	if now.After(inputs.ParsedCert.NotBefore.Add(inputs.Refresh)) &&
		now.After(inputs.SignerNotBefore.Add(inputs.Refresh/10)) {
		return StateDue, fmt.Sprintf("past target refresh period of %s and signer trust has propagated", inputs.Refresh)
	}
	if !issuerInBundle(inputs.ParsedCert, inputs.BundleCerts) {
		return StateStaleTrust, fmt.Sprintf("target issuer %q is not in the CA bundle", inputs.ParsedCert.Issuer.CommonName)
	}
	if hostnamesChanged(inputs.DesiredHostnames, inputs.ParsedCert) {
		return StateHostnameDrift, "target hostnames changed"
	}
	if inputs.ResolvedKeyAlgorithm != "" {
		if description, err := crypto.KeyDescriptionForPrivateKey(inputs.ParsedKey); err == nil && description != inputs.ResolvedKeyAlgorithm {
			return StateKeyDrift, fmt.Sprintf("target key is %s, resolved key is %s", description, inputs.ResolvedKeyAlgorithm)
		}
	}
	return StateCurrent, ""
}

// Decide maps a state and role to an action. This is the only place the
// writer and healer differ.
func Decide(state State, role Role) Action {
	switch role {
	case RoleWriter:
		switch state {
		case StateMissing:
			return ActionCreate
		case StateInvalid, StateExpired, StateDue, StateStaleTrust, StateHostnameDrift, StateKeyDrift:
			return ActionRegenerate
		case StateCurrent:
			return ActionNone
		}
	case RoleHealer:
		// The healer restores only unusable artifacts. It never rotates on
		// schedule, never chases drift, and never repairs metadata, so it
		// cannot fight the writer regardless of the writer's version.
		switch state {
		case StateMissing:
			return ActionCreate
		case StateInvalid, StateExpired:
			return ActionRegenerate
		case StateDue, StateStaleTrust, StateHostnameDrift, StateKeyDrift, StateCurrent:
			return ActionNone
		}
	}
	return ActionNone
}

// invalidData reports whether the artifact data is definitively unusable.
// A key parse failure caused by an unrecognized (but well-formed) key
// algorithm is deliberately not invalid: the binary that can judge that key
// owns the artifact, and acting on it would make an older healer fight a
// newer writer during upgrade skew.
func invalidData(cert *x509.Certificate, key stdcrypto.PrivateKey, keyParseErr error, notAfterAnnotation string) (string, bool) {
	if notAfterAnnotation == contract.ForceRegeneration {
		return "force-regeneration sentinel set on not-after annotation", true
	}
	if cert == nil {
		return "tls.crt is missing or unparseable", true
	}
	if keyParseErr != nil {
		if errors.Is(keyParseErr, crypto.ErrUnknownKeyAlgorithm) {
			// Unknown algorithm: not invalid, and not judgeable. Treated as
			// current for rotation purposes. The binary that can judge it
			// owns the artifact.
			return "", false
		}
		return fmt.Sprintf("tls.key is malformed: %v", keyParseErr), true
	}
	if key == nil {
		return "tls.key is missing", true
	}
	if !keyMatchesCert(cert, key) {
		return "tls.crt and tls.key do not match", true
	}
	return "", false
}

// keyMatchesCert reports whether the private key belongs to the certificate.
// A mismatched pair is unusable and must be regenerated.
func keyMatchesCert(cert *x509.Certificate, key stdcrypto.PrivateKey) bool {
	switch typedKey := key.(type) {
	case *rsa.PrivateKey:
		rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
		return ok && rsaPub.N.Cmp(typedKey.N) == 0 && rsaPub.E == typedKey.E
	case *ecdsa.PrivateKey:
		ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		return ok && ecdsaPub.X.Cmp(typedKey.X) == 0 && ecdsaPub.Y.Cmp(typedKey.Y) == 0 && ecdsaPub.Curve == typedKey.Curve
	case ed25519.PrivateKey:
		edPub, ok := cert.PublicKey.(ed25519.PublicKey)
		return ok && edPub.Equal(ed25519.PublicKey(typedKey.Public().(ed25519.PublicKey)))
	default:
		// Key types this build cannot inspect cannot be judged either way.
		return true
	}
}

// issuerInBundle reports whether the leaf's issuer is present in the bundle,
// matched by common name as v1 did.
func issuerInBundle(leaf *x509.Certificate, bundle []*x509.Certificate) bool {
	for _, ca := range bundle {
		if ca.Subject.CommonName == leaf.Issuer.CommonName {
			return true
		}
	}
	return false
}

// hostnamesChanged compares the desired hostname set against the
// certificate's SAN set, order-insensitively. Desired entries are
// canonicalized first: Go stores SANs in canonical form, so a desired
// non-canonical IPv6 literal (or mixed-case DNS name) must not compare
// unequal to its canonical self.
func hostnamesChanged(desired []string, cert *x509.Certificate) bool {
	certHostnames := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	for _, dns := range cert.DNSNames {
		certHostnames = append(certHostnames, strings.ToLower(dns))
	}
	for _, ip := range cert.IPAddresses {
		certHostnames = append(certHostnames, ip.String())
	}
	return contract.FormatHostnames(canonicalHostnames(desired)) != contract.FormatHostnames(certHostnames)
}

// canonicalHostnames renders each hostname in the form certificates carry:
// IPs through net.IP.String, DNS names lower-cased.
func canonicalHostnames(hostnames []string) []string {
	result := make([]string, 0, len(hostnames))
	for _, hostname := range hostnames {
		if ip := net.ParseIP(hostname); ip != nil {
			result = append(result, ip.String())
			continue
		}
		result = append(result, strings.ToLower(hostname))
	}
	return result
}

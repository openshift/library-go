package engine

import (
	stdcrypto "crypto"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
)

// errMalformedKey stands in for a definitively malformed key parse failure.
var errMalformedKey = errors.New("malformed key")

// testSigner mints a self-signed CA and returns it with its parsed leaf.
func testSigner(t *testing.T) (*crypto.CA, *x509.Certificate) {
	t.Helper()
	ca, err := crypto.MakeSelfSignedCAConfigForDuration("test-signer", 24*365*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, keyBytes, err := ca.GetPEMBytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := crypto.GetCAFromBytes(certBytes, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, ca.Certs[0]
}

// testLeaf mints a client cert signed by ca and returns its certificate
// and the matching private key.
func testLeaf(t *testing.T, ca *crypto.CA) (*x509.Certificate, stdcrypto.PrivateKey) {
	t.Helper()
	leaf, err := ca.MakeClientCertificateForDuration(testUser(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, keyBytes, err := leaf.GetPEMBytes()
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Certs[0], key
}

type testUserInfo struct{}

func (testUserInfo) GetName() string               { return "system:test" }
func (testUserInfo) GetUID() string                { return "" }
func (testUserInfo) GetGroups() []string           { return nil }
func (testUserInfo) GetExtra() map[string][]string { return nil }

func testUser() testUserInfo { return testUserInfo{} }

// signerInputsFrom builds SignerInputs from a parsed signer certificate.
func signerInputsFrom(cert *x509.Certificate, key stdcrypto.PrivateKey, exists bool) SignerInputs {
	inputs := SignerInputs{
		Exists:     exists,
		ParsedCert: cert,
		ParsedKey:  key,
		Refresh:    30 * 24 * time.Hour,
	}
	if cert != nil {
		inputs.NotAfterAnnotation = contract.FormatValidityTime(cert.NotAfter)
	}
	return inputs
}

func TestClassifySigner(t *testing.T) {
	signerCA, signerCert := testSigner(t)
	key := signerCA.Config.Key
	validity := signerCert.NotAfter.Sub(signerCert.NotBefore)

	testCases := []struct {
		name     string
		inputs   func() SignerInputs
		now      func() time.Time
		expected State
	}{
		{
			name: "missing when the secret does not exist",
			inputs: func() SignerInputs {
				return signerInputsFrom(nil, nil, false)
			},
			now:      func() time.Time { return signerCert.NotBefore },
			expected: StateMissing,
		},
		{
			name: "invalid when cert is nil",
			inputs: func() SignerInputs {
				inputs := signerInputsFrom(nil, key, true)
				return inputs
			},
			now:      func() time.Time { return signerCert.NotBefore },
			expected: StateInvalid,
		},
		{
			name: "invalid when key parse failed as malformed",
			inputs: func() SignerInputs {
				inputs := signerInputsFrom(signerCert, nil, true)
				inputs.KeyParseErr = errMalformedKey
				return inputs
			},
			now:      func() time.Time { return signerCert.NotBefore },
			expected: StateInvalid,
		},
		{
			name: "current when key algorithm is unknown",
			inputs: func() SignerInputs {
				inputs := signerInputsFrom(signerCert, nil, true)
				inputs.KeyParseErr = crypto.ErrUnknownKeyAlgorithm
				return inputs
			},
			now:      func() time.Time { return signerCert.NotBefore },
			expected: StateCurrent,
		},
		{
			name: "invalid on force-regeneration sentinel",
			inputs: func() SignerInputs {
				inputs := signerInputsFrom(signerCert, key, true)
				inputs.NotAfterAnnotation = contract.ForceRegeneration
				return inputs
			},
			now:      func() time.Time { return signerCert.NotBefore },
			expected: StateInvalid,
		},
		{
			name: "expired past not-after",
			inputs: func() SignerInputs {
				return signerInputsFrom(signerCert, key, true)
			},
			now:      func() time.Time { return signerCert.NotAfter.Add(time.Minute) },
			expected: StateExpired,
		},
		{
			name: "due past 80% of validity",
			inputs: func() SignerInputs {
				return signerInputsFrom(signerCert, key, true)
			},
			now: func() time.Time {
				return signerCert.NotAfter.Add(-validity / 5).Add(time.Minute)
			},
			expected: StateDue,
		},
		{
			name: "due past refresh period",
			inputs: func() SignerInputs {
				inputs := signerInputsFrom(signerCert, key, true)
				inputs.Refresh = time.Hour
				return inputs
			},
			now:      func() time.Time { return signerCert.NotBefore.Add(2 * time.Hour) },
			expected: StateDue,
		},
		{
			name: "current within all boundaries",
			inputs: func() SignerInputs {
				return signerInputsFrom(signerCert, key, true)
			},
			now:      func() time.Time { return signerCert.NotBefore.Add(time.Hour) },
			expected: StateCurrent,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := ClassifySigner(tc.inputs(), tc.now())
			if state != tc.expected {
				t.Errorf("expected state %s, got %s", tc.expected, state)
			}
		})
	}
	_ = signerCA
}

func TestClassifyTarget(t *testing.T) {
	signerCA, signerCert := testSigner(t)
	leaf, key := testLeaf(t, signerCA)
	validity := leaf.NotAfter.Sub(leaf.NotBefore)
	bundle := []*x509.Certificate{signerCert}

	baseInputs := func() TargetInputs {
		return TargetInputs{
			Exists:             true,
			ParsedCert:         leaf,
			ParsedKey:          key,
			Refresh:            12 * time.Hour,
			SignerNotBefore:    signerCert.NotBefore,
			BundleCerts:        bundle,
			NotAfterAnnotation: contract.FormatValidityTime(leaf.NotAfter),
		}
	}

	testCases := []struct {
		name     string
		mutate   func(inputs *TargetInputs)
		now      func() time.Time
		expected State
	}{
		{
			name:     "missing when the secret does not exist",
			mutate:   func(inputs *TargetInputs) { inputs.Exists = false },
			now:      func() time.Time { return leaf.NotBefore },
			expected: StateMissing,
		},
		{
			name:     "invalid on force-regeneration sentinel",
			mutate:   func(inputs *TargetInputs) { inputs.NotAfterAnnotation = contract.ForceRegeneration },
			now:      func() time.Time { return leaf.NotBefore },
			expected: StateInvalid,
		},
		{
			name:     "expired past not-after",
			mutate:   func(inputs *TargetInputs) {},
			now:      func() time.Time { return leaf.NotAfter.Add(time.Minute) },
			expected: StateExpired,
		},
		{
			name:   "due past 80% of validity",
			mutate: func(inputs *TargetInputs) {},
			now: func() time.Time {
				return leaf.NotAfter.Add(-validity / 5).Add(time.Minute)
			},
			expected: StateDue,
		},
		{
			name: "not due past target refresh while signer trust has not propagated",
			mutate: func(inputs *TargetInputs) {
				// A long refresh moves both the refresh boundary and the
				// trust gate (refresh/10) far out.
				inputs.Refresh = 130 * time.Hour
			},
			now: func() time.Time {
				// At 13h: refresh boundary (130h) not reached, 80% boundary
				// (19.2h of 24h validity) not reached, expiry not reached.
				return leaf.NotBefore.Add(13 * time.Hour)
			},
			expected: StateCurrent,
		},
		{
			name:   "not due when the trust gate has not opened",
			mutate: func(inputs *TargetInputs) {},
			now: func() time.Time {
				// Target refresh 12h: the refresh boundary passes at 12h,
				// but the trust gate (target refresh / 10 = 1.2h after the
				// signer's NotBefore) has not yet opened at 1h.
				return leaf.NotBefore.Add(1 * time.Hour)
			},
			expected: StateCurrent,
		},
		{
			name:   "due past target refresh once signer trust has propagated",
			mutate: func(inputs *TargetInputs) {},
			now: func() time.Time {
				// Past target refresh (12h) and past the trust gate
				// (target refresh / 10 = 1.2h), below the 80% boundary
				// (19.2h).
				return leaf.NotBefore.Add(13 * time.Hour)
			},
			expected: StateDue,
		},
		{
			name:     "stale trust when issuer not in bundle",
			mutate:   func(inputs *TargetInputs) { inputs.BundleCerts = nil },
			now:      func() time.Time { return leaf.NotBefore.Add(time.Hour) },
			expected: StateStaleTrust,
		},
		{
			name: "hostname drift when SAN set differs from desired",
			mutate: func(inputs *TargetInputs) {
				inputs.DesiredHostnames = []string{"other.host.example.com"}
			},
			now:      func() time.Time { return leaf.NotBefore.Add(time.Hour) },
			expected: StateHostnameDrift,
		},
		{
			name: "key drift when resolved algorithm differs",
			mutate: func(inputs *TargetInputs) {
				inputs.ResolvedKeyAlgorithm = "Ed25519"
			},
			now:      func() time.Time { return leaf.NotBefore.Add(time.Hour) },
			expected: StateKeyDrift,
		},
		{
			name:     "current within all boundaries",
			mutate:   func(inputs *TargetInputs) {},
			now:      func() time.Time { return leaf.NotBefore.Add(time.Hour) },
			expected: StateCurrent,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := baseInputs()
			tc.mutate(&inputs)
			state, _ := ClassifyTarget(inputs, tc.now())
			if state != tc.expected {
				t.Errorf("expected state %s, got %s", tc.expected, state)
			}
		})
	}
}

func TestDecide(t *testing.T) {
	testCases := []struct {
		name     string
		state    State
		role     Role
		expected Action
	}{
		{name: "writer creates missing", state: StateMissing, role: RoleWriter, expected: ActionCreate},
		{name: "healer creates missing", state: StateMissing, role: RoleHealer, expected: ActionCreate},
		{name: "writer regenerates invalid", state: StateInvalid, role: RoleWriter, expected: ActionRegenerate},
		{name: "healer regenerates invalid", state: StateInvalid, role: RoleHealer, expected: ActionRegenerate},
		{name: "writer regenerates expired", state: StateExpired, role: RoleWriter, expected: ActionRegenerate},
		{name: "healer regenerates expired", state: StateExpired, role: RoleHealer, expected: ActionRegenerate},
		{name: "writer regenerates due", state: StateDue, role: RoleWriter, expected: ActionRegenerate},
		{name: "healer ignores due", state: StateDue, role: RoleHealer, expected: ActionNone},
		{name: "writer regenerates stale trust", state: StateStaleTrust, role: RoleWriter, expected: ActionRegenerate},
		{name: "healer ignores stale trust", state: StateStaleTrust, role: RoleHealer, expected: ActionNone},
		{name: "writer regenerates hostname drift", state: StateHostnameDrift, role: RoleWriter, expected: ActionRegenerate},
		{name: "healer ignores hostname drift: unusable-only mandate", state: StateHostnameDrift, role: RoleHealer, expected: ActionNone},
		{name: "writer regenerates key drift", state: StateKeyDrift, role: RoleWriter, expected: ActionRegenerate},
		{name: "healer ignores key drift", state: StateKeyDrift, role: RoleHealer, expected: ActionNone},
		{name: "writer does nothing on current", state: StateCurrent, role: RoleWriter, expected: ActionNone},
		{name: "healer does nothing on current", state: StateCurrent, role: RoleHealer, expected: ActionNone},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := Decide(tc.state, tc.role)
			if actual != tc.expected {
				t.Errorf("expected action %s, got %s", tc.expected, actual)
			}
		})
	}
}

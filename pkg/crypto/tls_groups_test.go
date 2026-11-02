package crypto

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSGroupsToCurveIDs(t *testing.T) {
	for name, tc := range map[string]struct {
		groups      []string
		curves      []tls.CurveID
		unsupported []string
	}{
		"NIST groups exclude X25519 and preserve order": {
			groups: []string{"secp384r1", "secp256r1", "secp521r1"},
			curves: []tls.CurveID{tls.CurveP384, tls.CurveP256, tls.CurveP521},
		},
		"classical and hybrid X25519": {
			groups: []string{"X25519MLKEM768", "X25519"},
			curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		},
		"unknown groups are skipped and returned": {
			groups:      []string{"future-group", "secp256r1", "unknown-group"},
			curves:      []tls.CurveID{tls.CurveP256},
			unsupported: []string{"future-group", "unknown-group"},
		},
		"Go 1.26 groups are unsupported": {
			groups:      []string{"SecP256r1MLKEM768", "secp384r1", "SecP384r1MLKEM1024"},
			curves:      []tls.CurveID{tls.CurveP384},
			unsupported: []string{"SecP256r1MLKEM768", "SecP384r1MLKEM1024"},
		},
		"all unsupported groups": {
			groups:      []string{"unknown-group"},
			unsupported: []string{"unknown-group"},
		},
		"unset groups": {},
		"empty groups": {groups: []string{}},
	} {
		t.Run(name, func(t *testing.T) {
			curves, unsupported := TLSGroupsToCurveIDs(tc.groups)
			require.Equal(t, tc.curves, curves)
			require.Equal(t, tc.unsupported, unsupported)
		})
	}
}

func TestTLSGroupsToCurveIDsNamedStrings(t *testing.T) {
	type groupName string
	curves, unsupported := TLSGroupsToCurveIDs([]groupName{"secp256r1", "unknown-group"})
	require.Equal(t, []tls.CurveID{tls.CurveP256}, curves)
	require.Equal(t, []groupName{"unknown-group"}, unsupported)
}

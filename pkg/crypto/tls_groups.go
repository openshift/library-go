package crypto

import "crypto/tls"

// tlsGroupToCurveID contains the TLS groups supported by Go 1.25.
// SecP256r1MLKEM768 and SecP384r1MLKEM1024 require Go 1.26 and are
// intentionally left unsupported on this release branch.
var tlsGroupToCurveID = map[string]tls.CurveID{
	"X25519":         tls.X25519,
	"secp256r1":      tls.CurveP256,
	"secp384r1":      tls.CurveP384,
	"secp521r1":      tls.CurveP521,
	"X25519MLKEM768": tls.X25519MLKEM768,
}

// TLSGroupsToCurveIDs converts TLS group names to Go curve IDs, preserving
// their order. Unsupported groups are skipped and returned for callers to log.
// The type parameter accepts API group types without requiring an API update.
func TLSGroupsToCurveIDs[T ~string](groups []T) ([]tls.CurveID, []T) {
	var curves []tls.CurveID
	var unsupported []T
	for _, group := range groups {
		curve, ok := tlsGroupToCurveID[string(group)]
		if !ok {
			unsupported = append(unsupported, group)
			continue
		}
		curves = append(curves, curve)
	}
	return curves, unsupported
}

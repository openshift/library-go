package crypto

import (
	"crypto/fips140"

	configv1 "github.com/openshift/api/config/v1"
)

// fipsTLSGroups is the allowlist of TLSGroup values treated as FIPS-approved.
// Only the NIST P-curves qualify: their domain parameters are specified in
// NIST SP 800-186 and their use for ECDH key establishment in SP 800-56A.
//
// An allowlist is used rather than a blocklist because new groups are non-FIPS
// by default until they complete formal NIST validation (typically years), so
// any future group absent from this set is correctly excluded without requiring
// a library-go update.
//
// KNOWN DIVERGENCE (revisit as part of native Go FIPS adoption, HPSTRAT-723).
// Three sources disagree about the FIPS status of some groups, and this
// allowlist deliberately takes the strictest position:
//
//		group           openshift/api godoc     this allowlist   Go native FIPS (fips140=on)
//		X25519          "keep" (only            drops            REFUSES ("no supported
//		                 X25519MLKEM768 should                     elliptic curves for ECDHE")
//		                 be ignored in FIPS)
//		X25519MLKEM768  "ignore in FIPS"        drops            NEGOTIATES it
//
//	  - On plain X25519 this allowlist matches the runtime (both exclude it); the
//	    openshift/api godoc is the outdated one (corrected in OCPBUGS-109794).
//	  - On X25519MLKEM768 this allowlist is stricter than Go: Go's module will
//	    negotiate the hybrid, but we drop it because the hybrid embeds X25519 and
//	    the FIPS status of ML-KEM hybrids is still settling (SP 800-56C key
//	    derivation guidance).
//
// This set is intentionally strict (P-curves only) while operands run mixed
// crypto backends (OpenSSL FIPS + Go native): it is the safe intersection and
// never offers a curve an OpenSSL-backed operand would reject. It should be
// revisited once native Go FIPS is the backend — likely deferring to the
// module's approved set for Go operands and allowing the P-curve+ML-KEM hybrids
// (SecP256r1MLKEM768, SecP384r1MLKEM1024; both halves are NIST-approved), keeping
// an explicit filter only for non-Go / OpenSSL-backed operands. X25519MLKEM768
// stays excluded even then, because its classical half is the non-NIST curve.
// Tracked in CNTRLPLANE-4107 (under HPSTRAT-723).
var fipsTLSGroups = map[configv1.TLSGroup]struct{}{
	configv1.TLSGroupSecP256r1: {},
	configv1.TLSGroupSecP384r1: {},
	configv1.TLSGroupSecP521r1: {},
}

// IsFIPSEnabled reports whether the Go runtime is operating in FIPS 140 mode.
func IsFIPSEnabled() bool {
	return fips140.Enabled()
}

// FIPSApprovedTLSGroups returns the subset of groups that are FIPS-approved,
// preserving order and dropping the rest. It is the filter a component should
// apply to its configured TLS groups when running in FIPS mode:
//
//	groups := profileSpec.Groups
//	if crypto.IsFIPSEnabled() {
//		groups = crypto.FIPSApprovedTLSGroups(groups)
//	}
//
// This is a pure classification against the allowlist above; it does not itself
// check IsFIPSEnabled, so it stays unit-testable without a FIPS runtime and
// callers keep explicit control over when filtering applies.
func FIPSApprovedTLSGroups(groups []configv1.TLSGroup) []configv1.TLSGroup {
	approved := make([]configv1.TLSGroup, 0, len(groups))
	for _, g := range groups {
		if _, ok := fipsTLSGroups[g]; !ok {
			continue
		}
		approved = append(approved, g)
	}
	return approved
}

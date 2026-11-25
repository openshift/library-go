package crypto

import "cmp"

// SecurityLevel describes the cryptographic strength (in bits) of a key pair
// under both classical and quantum threat models.
//
// The zero value indicates an unknown or inapplicable security level. It
// compares as weaker than every other level.
type SecurityLevel struct {
	// ClassicalBits is the security strength in bits against classical
	// (non-quantum) attacks, as estimated by NIST SP 800-57.
	ClassicalBits int
	// QuantumBits is the security strength in bits against attacks by a
	// large-scale quantum computer. It is zero for algorithms without
	// post-quantum resistance.
	QuantumBits int
}

// IsQuantumSafe reports whether keys at this level resist quantum attacks.
func (s SecurityLevel) IsQuantumSafe() bool {
	return s.QuantumBits > 0
}

// Compare returns -1 if s is weaker than other, 0 if equal, and +1 if stronger.
//
// Post-quantum resistance takes precedence: levels are ordered primarily by
// QuantumBits, so any level with post-quantum resistance outranks any
// classical-only level. ClassicalBits breaks ties when QuantumBits are equal,
// and decides the order between two classical-only levels. Compare is suitable
// for use with slices.SortFunc.
func (s SecurityLevel) Compare(other SecurityLevel) int {
	return cmp.Or(
		cmp.Compare(s.QuantumBits, other.QuantumBits),
		cmp.Compare(s.ClassicalBits, other.ClassicalBits),
	)
}

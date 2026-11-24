package crypto

import "math"

// rsaSecurityBits returns the estimated maximum security strength of an RSA
// modulus of the given bit length, ES(nBits) from NIST SP 800-56B Rev. 2
// Appendix D: the GNFS-based estimate E rounded to the nearest multiple of
// eight.
func rsaSecurityBits(bits int) int {
	return int(math.Round(rsaStrengthEstimate(bits)/8) * 8)
}

// rsaStrengthEstimate returns E, the unrounded security strength estimate
// for an RSA modulus of nBits bits from NIST SP 800-56B Rev. 2 Appendix D:
//
//	E = (1.923 * cbrt(nBits*ln2) * cbrt(ln(nBits*ln2)^2) - 4.69) / ln2
func rsaStrengthEstimate(nBits int) float64 {
	x := float64(nBits) * math.Ln2
	return (1.923*math.Cbrt(x)*math.Cbrt(math.Pow(math.Log(x), 2)) - 4.69) / math.Ln2
}

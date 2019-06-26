package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

// RandomBitsString returns a random string with at least the requested bits of entropy.
// It uses RawURLEncoding to ensure we do not get / characters or trailing ='s.
// Callers should avoid using a value less than 256 unless they have a very good reason.
func RandomBitsString(bits int) string {
	size := (bits + 7) / 8

	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand should never fail
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Random256BitsString is a convenience function for calling RandomBitsString(256).
// Callers that need a random string should use this function unless they have a
// very good reason to need a different amount of entropy.
func Random256BitsString() string {
	// 32 bytes (256 bits) = 43 base64-encoded characters
	return RandomBitsString(256)
}

// Random512BitsString is a convenience function for calling RandomBitsString(512).
// Callers that need a random string should use this function unless they have a
// very good reason to need a different amount of entropy.
func Random512BitsString() string {
	// 32 bytes (256 bits) = 43 base64-encoded characters
	return RandomBitsString(512)
}

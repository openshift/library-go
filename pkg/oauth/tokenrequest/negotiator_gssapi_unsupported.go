//go:build !gssapi
// +build !gssapi

package tokenrequest

func GSSAPIEnabled() bool {
	return false
}

func NewGSSAPINegotiator(string) Negotiator {
	return newUnsupportedNegotiator("GSSAPI")
}

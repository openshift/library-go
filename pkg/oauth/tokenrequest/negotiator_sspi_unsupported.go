//go:build !windows
// +build !windows

package tokenrequest

import "io"

func SSPIEnabled() bool {
	return false
}

func NewSSPINegotiator(string, string, string, io.Reader, PasswordPrompter) Negotiator {
	return newUnsupportedNegotiator("SSPI")
}

package eventwatch

import (
	"strings"
)

// reasonMatch will test a string pattern, potentially containing globs, against a
// subject string. The result is a simple true/false, determining whether or
// not the glob pattern matched the subject text.
//
// Credit: https://github.com/ryanuber/go-glob
func reasonMatch(pattern, reason string) bool {
	if pattern == "" {
		return reason == pattern
	}

	// If the pattern _is_ a glob, it matches everything
	if pattern == "*" {
		return true
	}

	// If the pattern does not contain a glob, require strict match by default
	if !strings.Contains(pattern, "*") {
		return pattern == reason
	}

	parts := strings.Split(pattern, "*")

	if len(parts) == 1 {
		// No globs in pattern, so test for equality
		return reason == pattern
	}

	leadingGlob := strings.HasPrefix(pattern, "*")
	trailingGlob := strings.HasSuffix(pattern, "*")
	end := len(parts) - 1

	// Go over the leading parts and ensure they match.
	for i := range parts {
		idx := strings.Index(reason, parts[i])

		switch i {
		case 0:
			// Check the first section. Requires special handling.
			if !leadingGlob && idx != 0 {
				return false
			}
		default:
			// Check that the middle parts match.
			if idx < 0 {
				return false
			}
		}

		// Trim evaluated text from reason as we loop over the pattern.
		reason = reason[idx+len(parts[i]):]
	}

	// Reached the last section. Requires special handling.
	return trailingGlob || strings.HasSuffix(reason, parts[end])
}

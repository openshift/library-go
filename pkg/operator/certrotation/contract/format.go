package contract

import (
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
)

// FormatValidityTime renders a certificate validity timestamp for the
// not-before and not-after annotations. It matches the format the rotation
// code has always written: time.RFC3339 as produced by time.Time.Format.
func FormatValidityTime(t time.Time) string {
	return t.Format(time.RFC3339)
}

// ParseValidityTime parses a not-before or not-after annotation value. It
// errors on values that are not valid RFC3339 timestamps, including the
// ForceRegeneration sentinel; callers that accept the sentinel must compare
// against it before parsing.
func ParseValidityTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, value)
}

// FormatHostnames renders the hostname set of a serving or peer certificate
// for the hostnames annotation: the sorted, deduplicated, comma-joined set.
// This matches the format written by the rotation code since its origin.
func FormatHostnames(hostnames []string) string {
	return strings.Join(sets.List(sets.New(hostnames...)), ",")
}

// ParseHostnames parses a hostnames annotation value back into the sorted,
// deduplicated hostname set. An empty value yields nil.
func ParseHostnames(value string) []string {
	if value == "" {
		return nil
	}
	return sets.List(sets.New(strings.Split(value, ",")...))
}

// FormatRefreshPeriod renders a refresh period for the refresh-period
// annotation, in Go duration string format (for example "720h0m0s").
func FormatRefreshPeriod(refresh time.Duration) string {
	return refresh.String()
}

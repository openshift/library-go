// Package httptransport contains a builder that can be used to build an http.RoundTripper.
// Particularly the package supports registering dynamic CA bundle sources that are being watched
// and any change causes the RoundTripper to be rebuilt in the background and atomically replaced.
package httptransport

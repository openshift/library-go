// Package health probes a co-located KMSv2 plugin on a cadence and
// publishes a classified, timestamped HealthStatus through a StatusWriter.
// Used by operators and condition reporters that need plugin health
// without dialing the socket themselves.
package health

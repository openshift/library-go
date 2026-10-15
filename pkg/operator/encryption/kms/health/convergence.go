package health

import (
	operatorv1 "github.com/openshift/api/operator/v1"
)

// ConvergedRemoteKeyID returns the unanimous RemoteKeyID across reports when every
// report carries the same non-empty RemoteKeyID. An empty return value indicates
// no convergence (empty input, conflicting IDs, or any empty RemoteKeyID).
// Callers must filter reports to the relevant key ID and ensure the slice
// includes every expected node before treating a non-empty result as converged.
func ConvergedRemoteKeyID(reports []operatorv1.KMSPluginHealthReport) string {
	if len(reports) == 0 {
		return ""
	}
	remoteKeyID := reports[0].RemoteKeyID
	if remoteKeyID == "" {
		return ""
	}
	for _, report := range reports[1:] {
		if report.RemoteKeyID != remoteKeyID {
			return ""
		}
	}
	return remoteKeyID
}

// AllKeyIDsConverged reports whether every KeyID group has a unanimous non-empty
// RemoteKeyID. Empty input is treated as converged (nothing to assess). During
// KMS-to-KMS migration multiple KeyIDs report at once and may legitimately carry
// different RemoteKeyIDs; only disagreement within a KeyID group is non-converged.
func AllKeyIDsConverged(reports []operatorv1.KMSPluginHealthReport) bool {
	if len(reports) == 0 {
		return true
	}
	byKeyID := map[string][]operatorv1.KMSPluginHealthReport{}
	for _, report := range reports {
		byKeyID[report.KeyID] = append(byKeyID[report.KeyID], report)
	}
	for _, group := range byKeyID {
		if ConvergedRemoteKeyID(group) == "" {
			return false
		}
	}
	return true
}

// ReportsForKeyID returns health reports for the given encryption key ID (kms-{keyID}.sock).
// During KMS-to-KMS provider migration multiple plugins may report per node; callers use
// the current write key's keyID so backup/read-only keys are excluded from rotation logic.
func ReportsForKeyID(reports []operatorv1.KMSPluginHealthReport, keyID string) []operatorv1.KMSPluginHealthReport {
	filtered := make([]operatorv1.KMSPluginHealthReport, 0, len(reports))
	for _, report := range reports {
		if report.KeyID == keyID {
			filtered = append(filtered, report)
		}
	}
	return filtered
}

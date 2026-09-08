package health

import (
	operatorv1 "github.com/openshift/api/operator/v1"
)

// ConvergenceResult reports whether health reports agree on a single remote key ID.
type ConvergenceResult struct {
	Converged   bool
	RemoteKeyID string
}

// ConvergedRemoteKeyID returns Converged=true when every report in the slice carries
// the same RemoteKeyID. The caller is responsible for filtering reports and handling
// missing or empty entries.
func ConvergedRemoteKeyID(reports []operatorv1.KMSPluginHealthReport) ConvergenceResult {
	if len(reports) == 0 {
		return ConvergenceResult{}
	}
	remoteKeyID := reports[0].RemoteKeyID
	for _, report := range reports[1:] {
		if report.RemoteKeyID != remoteKeyID {
			return ConvergenceResult{}
		}
	}
	return ConvergenceResult{
		Converged:   true,
		RemoteKeyID: remoteKeyID,
	}
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

package health

import (
	operatorv1 "github.com/openshift/api/operator/v1"
)

// ConvergenceResult reports whether a set of KMS plugin health reports agree on
// the same remote key ID.
type ConvergenceResult struct {
	Converged   bool
	RemoteKeyID string
}

// ConvergedRemoteKeyID returns whether all reports in the slice report the same
// non-empty RemoteKeyID.
func ConvergedRemoteKeyID(reports []operatorv1.KMSPluginHealthReport) ConvergenceResult {
	if len(reports) == 0 {
		return ConvergenceResult{Converged: false}
	}

	var remoteKeyID string
	for _, report := range reports {
		if report.RemoteKeyID == "" {
			return ConvergenceResult{Converged: false}
		}
		if remoteKeyID == "" {
			remoteKeyID = report.RemoteKeyID
			continue
		}
		if report.RemoteKeyID != remoteKeyID {
			return ConvergenceResult{Converged: false}
		}
	}

	return ConvergenceResult{
		Converged:   true,
		RemoteKeyID: remoteKeyID,
	}
}

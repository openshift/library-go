package encryptionstatus

import (
	"context"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
)

// KMSEncryptionStatusClient reads and writes the KMSEncryptionStatus sub-field
// of an operator CR. Different controllers can own independent sub-fields by
// passing distinct fieldManager values per call, matching the
// OperatorClient.ApplyOperatorStatus pattern.
type KMSEncryptionStatusClient interface {
	GetKMSEncryptionStatus(ctx context.Context) (*operatorv1.KMSEncryptionStatus, error)

	// ApplyKMSEncryptionStatus uses Server-Side Apply. It is the right tool for
	// multi-writer fields such as HealthReports, where each health reporter owns
	// the entries for its own node via a distinct fieldManager.
	ApplyKMSEncryptionStatus(ctx context.Context, fieldManager string, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error

	// UpdateKMSEncryptionStatus uses a plain read-modify-write update. It is the
	// right tool for single-writer fields such as Preflight.ObservedConfigHash
	// (key controller) and Preflight.Result (preflight controller), where
	// set-and-persist semantics are needed without per-sync re-application.
	// A conflict (409) is returned as-is; controllers rely on their own
	// reconciliation loop to retry.
	UpdateKMSEncryptionStatus(ctx context.Context, mutate func(*operatorv1.KMSEncryptionStatus)) error
}

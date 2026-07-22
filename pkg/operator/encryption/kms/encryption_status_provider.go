package kms

import (
	"context"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
)

// EncryptionStatusProvider reads and writes the KMSEncryptionStatus sub-field
// of an operator CR. Get and Apply are safe for concurrent callers.
type EncryptionStatusProvider interface {
	GetKMSEncryptionStatus(ctx context.Context) (*operatorv1.KMSEncryptionStatus, error)

	// ApplyKMSEncryptionStatus uses Server-Side Apply. Each caller owns only
	// the fields it explicitly sets, identified by fieldManager.
	ApplyKMSEncryptionStatus(ctx context.Context, fieldManager string, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error

	// UpdateKMSEncryptionStatus reads the current status, applies the mutation,
	// and writes it back. A conflict (409) is returned as-is.
	//
	// Note: use this instead of ApplyKMSEncryptionStatus when the controller is
	// the sole owner of a field. Apply requires re-sending every owned field on
	// every sync, omitting one causes the server to remove it, which is
	// cumbersome for a controller that only writes a field once.
	UpdateKMSEncryptionStatus(ctx context.Context, mutate func(*operatorv1.KMSEncryptionStatus)) error
}

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
}

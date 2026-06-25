package health

import (
	"context"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"k8s.io/client-go/rest"
)

// NewEncryptionStatusWriterFunc builds the EncryptionStatusWriter for a target
// apiserver operator status CR. fieldManager sets the owner in the
// managedFields when doing SSA.
type NewEncryptionStatusWriterFunc func(restConfig *rest.Config, fieldManager string) (EncryptionStatusWriter, error)

// EncryptionStatusWriter is capable of applying the
// KMSEncryptionStatusApplyConfiguration at the correct place in the operator's
// status.
type EncryptionStatusWriter func(ctx context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error

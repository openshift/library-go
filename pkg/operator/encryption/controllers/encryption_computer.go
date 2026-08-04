package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/openshift/library-go/pkg/controller/factory"
)

// EncryptionComputer accepts a keyController and a stateController and
// allows computing their outputs without side effects.
type EncryptionComputer struct {
	keyController   *keyController
	stateController *stateController
}

func NewEncryptionComputer(keyCtrl *keyController, stateCtrl *stateController) *EncryptionComputer {
	return &EncryptionComputer{
		keyController:   keyCtrl,
		stateController: stateCtrl,
	}
}

// ComputeKeySecret returns the key secret that would be created by the
// key controller, or nil if no new key is needed.
func (e *EncryptionComputer) ComputeKeySecret(ctx context.Context, syncCtx factory.SyncContext) (*corev1.Secret, error) {
	return e.keyController.computeKeySecret(ctx, syncCtx)
}

// ComputeEncryptionConfigSecret returns the encryption config secret that
// would be applied by the state controller, or nil if no update is needed.
func (e *EncryptionComputer) ComputeEncryptionConfigSecret(ctx context.Context, queue workqueue.RateLimitingInterface) (*corev1.Secret, []eventWithReason, error) {
	return e.stateController.computeEncryptionConfigSecret(ctx, queue)
}

// ComputeEncryptionConfigSecretWithNewKey computes the key secret that
// would be created by the key controller and propagates it into the state
// controller's computation, returning the encryption config secret that
// would result if the new key had been created.
func (e *EncryptionComputer) ComputeEncryptionConfigSecretWithNewKey(ctx context.Context, syncCtx factory.SyncContext) (*corev1.Secret, []eventWithReason, error) {
	newKeySecret, err := e.keyController.computeKeySecret(ctx, syncCtx)
	if err != nil {
		return nil, nil, err
	}

	sc := e.stateController
	listKeySecretsFn := sc.listKeySecretsFn
	if newKeySecret != nil {
		listKeySecretsFn = func(ctx context.Context) ([]*corev1.Secret, error) {
			existing, err := sc.listKeySecretsFn(ctx)
			if err != nil {
				return nil, err
			}
			return append([]*corev1.Secret{newKeySecret}, existing...), nil
		}
	}

	return sc.computeEncryptionConfigSecretWithCustomListKeySecretFn(ctx, syncCtx.Queue(), listKeySecretsFn)
}

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

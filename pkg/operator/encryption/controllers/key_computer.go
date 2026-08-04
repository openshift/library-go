package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
)

// KeyComputer uses a keyController to compute what key secret would be
// needed without actually creating it.
type KeyComputer struct {
	controller *keyController
}

func newKeyComputer(controller *keyController) *KeyComputer {
	return &KeyComputer{controller: controller}
}

// ComputeKey returns the key secret that would be created by the key
// controller, or nil if no new key is needed.
func (k *KeyComputer) ComputeKey(ctx context.Context, syncCtx factory.SyncContext) (*corev1.Secret, error) {
	return k.controller.computeKeySecret(ctx, syncCtx)
}

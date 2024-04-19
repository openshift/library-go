package fake

import (
	"context"

	"github.com/openshift/library-go/pkg/secret"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type SecretMonitor struct {
	Err    error
	Secret *corev1.Secret
}

func (sm *SecretMonitor) AddSecretEventHandler(_ context.Context, _ string, _ string, _ cache.ResourceEventHandler) (secret.SecretEventHandlerRegistration, error) {
	return nil, sm.Err
}
func (sm *SecretMonitor) RemoveSecretEventHandler(_ secret.SecretEventHandlerRegistration) error {
	return sm.Err
}
func (sm *SecretMonitor) GetSecret(_ context.Context, _ secret.SecretEventHandlerRegistration) (*corev1.Secret, error) {
	return sm.Secret, sm.Err
}

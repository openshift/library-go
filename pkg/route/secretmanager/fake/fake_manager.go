package fake

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type SecretManager struct {
	Err        error
	Secret     *corev1.Secret
	IsPresent  bool
	SecretName string
}

func (m *SecretManager) RegisterRoute(ctx context.Context, namespace string, routeName string, secretName string, handler cache.ResourceEventHandlerFuncs) error {
	return m.Err
}
func (m *SecretManager) UnregisterRoute(namespace string, routeName string) error {
	return m.Err
}

func (m *SecretManager) GetSecret(ctx context.Context, namespace string, routeName string) (*corev1.Secret, error) {
	return m.Secret, m.Err
}

func (m *SecretManager) LookupRouteSecret(namespace string, routeName string) (string, bool) {
	return m.SecretName, m.IsPresent
}

func (m *SecretManager) Queue() workqueue.RateLimitingInterface {
	return nil
}

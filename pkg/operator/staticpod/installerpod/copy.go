package installerpod

import (
	"time"

	"github.com/golang/glog"
	"golang.org/x/net/context"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// getSecretWithRetry will get a secret from API server.
// It will retry on API server connection errors except not found error which is fatal for non-optional secrets.
// In case the secret is optional and we fail to get it, no error is returned and the secret returning is nil.
func (o *InstallOptions) getSecretWithRetry(ctx context.Context, secretNamePrefix string, isOptional bool) (*v1.Secret, error) {
	var resultSecret *v1.Secret = nil
	retryErr := wait.PollImmediateUntil(200*time.Millisecond, func() (bool, error) {
		secret, err := o.KubeClient.CoreV1().Secrets(o.Namespace).Get(o.nameFor(secretNamePrefix), metav1.GetOptions{})
		switch {
		case errors.IsNotFound(err):
			if isOptional {
				err = nil
			}
			return true, err
		case err != nil:
			glog.Warningf("Failed to get secret %s/%s: %v (will retry)", o.Namespace, o.nameFor(secretNamePrefix), err)
			return false, nil
		default:
			resultSecret = secret
			return true, nil
		}
	}, ctx.Done())
	return resultSecret, retryErr
}

// getConfigMapWithRetry will get a config map from API server.
// It will retry on API server connection errors except not found error which is fatal for non-optional secrets.
// In case the config is optional and we fail to get it, no error is returned and the config returning is nil.
func (o *InstallOptions) getConfigMapWithRetry(ctx context.Context, configNamePrefix string, isOptional bool) (*v1.ConfigMap, error) {
	var resultConfig *v1.ConfigMap = nil
	retryErr := wait.PollImmediateUntil(200*time.Millisecond, func() (bool, error) {
		config, err := o.KubeClient.CoreV1().ConfigMaps(o.Namespace).Get(o.nameFor(configNamePrefix), metav1.GetOptions{})
		switch {
		case errors.IsNotFound(err):
			if isOptional {
				err = nil
			}
			return true, err
		case err != nil:
			glog.Warningf("Failed to get configmap %s/%s: %v (will retry)", o.Namespace, o.nameFor(configNamePrefix), err)
			return false, nil
		default:
			resultConfig = config
			return true, nil
		}
	}, ctx.Done())
	return resultConfig, retryErr
}

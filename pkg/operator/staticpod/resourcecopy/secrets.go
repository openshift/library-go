package resourcecopy

import (
	"context"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/library-go/pkg/operator/resource/retry"
)

type HandleSecretFunc func(s *v1.Secret) error

// CopySecrets will copy all resources specified as an input from API server and then pass it to a handler function which will decide
// what we will do with the secrets.
// This function should be used when interacting with API server that can go up/down as it has built-in retry mechanism to handle
// connection errors.
// Each source can indicate whether the resource is optional or not. In case it is optional, the not found errors will be ignored.
// An error is returned when the context deadline is passed or the handler function return an error.
func CopySecrets(ctx context.Context, client corev1client.SecretsGetter, sourceSecrets []Source, handlerFn HandleSecretFunc) error {
	for _, source := range sourceSecrets {
		select {
		case <-ctx.Done():
			return wait.ErrWaitTimeout
		default:
		}
		var secret *v1.Secret
		err := retry.RetryOnConnectionErrors(ctx, func(ctx context.Context) (bool, error) {
			var clientErr error
			secret, clientErr = client.Secrets(source.Namespace()).Get(source.Name(), metav1.GetOptions{})
			if clientErr != nil {
				glog.Infof("Failed to get secret %s/%s: %v", source.Namespace(), source.Name(), clientErr)
				return false, clientErr
			}
			return true, nil
		})
		switch {
		case err == nil:
			glog.Infof("Copying secret %s/%s ...", source.Namespace(), source.Name())
			if err := handlerFn(secret); err != nil {
				return err
			}
		case errors.IsNotFound(err) && source.IsOptional():
			glog.Infof("Skipped non-existing optional secret %s/%s", source.Namespace(), source.Name())
			continue
		default:
			return err
		}
	}

	return nil

}

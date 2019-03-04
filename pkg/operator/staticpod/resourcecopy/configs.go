package resourcecopy

import (
	"context"

	"github.com/golang/glog"
	"github.com/openshift/library-go/pkg/operator/resource/retry"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

type HandleConfigMapFunc func(s *v1.ConfigMap) error

// CopyConfigMaps will copy all resources specified as an input from API server and then pass it to a handler function which will decide
// what we will do with the config maps.
// This function should be used when interacting with API server that can go up/down as it has built-in retry mechanism to handle
// connection errors.
// Each source can indicate whether the resource is optional or not. In case it is optional, the not found errors will be ignored.
// An error is returned when the context deadline is passed or the handler function return an error.
func CopyConfigMaps(ctx context.Context, client corev1client.ConfigMapsGetter, sourceConfigMaps []Source, handlerFn HandleConfigMapFunc) error {
	for _, source := range sourceConfigMaps {
		select {
		case <-ctx.Done():
			return wait.ErrWaitTimeout
		default:
		}
		var configMap *v1.ConfigMap
		err := retry.RetryOnConnectionErrors(ctx, func(ctx context.Context) (bool, error) {
			var clientErr error
			configMap, clientErr = client.ConfigMaps(source.Namespace()).Get(source.Name(), metav1.GetOptions{})
			if clientErr != nil {
				glog.Infof("Failed to get configMap %s/%s: %v", source.Namespace(), source.Name(), clientErr)
				return false, clientErr
			}
			return true, nil
		})
		switch {
		case err == nil:
			glog.Infof("Copying config map %s/%s ...", source.Namespace(), source.Name())
			if err := handlerFn(configMap); err != nil {
				return err
			}
		case errors.IsNotFound(err) && source.IsOptional():
			glog.Infof("Skipped non-existing optional configMap %s/%s", source.Namespace(), source.Name())
			continue
		default:
			return err
		}
	}

	return nil

}

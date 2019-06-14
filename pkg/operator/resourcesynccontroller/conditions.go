package resourcesynccontroller

import (
	"time"

	"github.com/openshift/library-go/pkg/operator/certrotation"

	corev1 "k8s.io/api/core/v1"
)

// SecretConditionFunc returns how long to wait before checking again. Zero means it is ready to sync now.  Negative means no opinion.
type SecretConditionFunc func(destination, source *corev1.Secret) time.Duration

type SecretSyncConditions []SecretConditionFunc

// WaitBeforeSecretSync suggests waiting for the minimum amount of time before syncing
func (c SecretSyncConditions) WaitBeforeSecretSync(destination, source *corev1.Secret) time.Duration {
	ret := time.Duration(0)

	for _, secretConditionFn := range c {
		curr := secretConditionFn(destination, source)
		if curr < 0 {
			continue
		}
		if curr < ret {
			ret = curr
		}
	}

	return ret
}

func WaitXMinutesAfterCertValid(waitTime time.Duration) SecretConditionFunc {
	return func(destination, source *corev1.Secret) time.Duration {
		// if there's nothing there, sync immediately
		if destination == nil {
			return 0
		}
		// if we're clearing it, sync immediately
		if source == nil {
			return 0
		}

		now := time.Now()

		// if we're already expired, sync immediately
		_, destinationNotAfter, unableToParse := certrotation.GetValidityFromAnnotations(destination.Annotations)
		if len(unableToParse) > 0 {
			return 0
		}
		if destinationNotAfter.Before(now) {
			return 0
		}

		sourceNotBefore, _, unableToParse := certrotation.GetValidityFromAnnotations(source.Annotations)
		if len(unableToParse) > 0 {
			return 0
		}
		// if it's after the time we should sync, go ahead and allow it
		syncAfter := sourceNotBefore.Add(waitTime)
		if syncAfter.After(now) {
			return 0
		}

		// try again after we're pretty darn sure that we will have waited long enough
		return now.Sub(syncAfter) + 1*time.Minute
	}
}

func IfTargetSecret(namespace, name string, delegate SecretConditionFunc) SecretConditionFunc {
	return func(destination, source *corev1.Secret) time.Duration {
		if destination == nil {
			return -1
		}
		if destination.Namespace == namespace && destination.Name == name {
			return delegate(destination, source)
		}

		return -1
	}
}

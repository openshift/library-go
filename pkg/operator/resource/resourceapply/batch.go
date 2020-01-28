package resourceapply

import (
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	batchclientv1beta1 "k8s.io/client-go/kubernetes/typed/batch/v1beta1"
	"k8s.io/klog"
)

func ApplyCronJob(client batchclientv1beta1.CronJobsGetter, recorder events.Recorder, required *batchv1beta1.CronJob) (*batchv1beta1.CronJob, bool, error) {
	existing, err := client.CronJobs(required.Namespace).Get(required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		actual, err := client.CronJobs(required.Namespace).Create(required)
		reportCreateEvent(recorder, required, err)
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}

	modified := resourcemerge.BoolPtr(false)
	existingCopy := existing.DeepCopy()

	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, required.ObjectMeta)
	if !*modified {
		return existingCopy, false, nil
	}

	if klog.V(4) {
		klog.Infof("CronJob %q changes: %v", required.Namespace+"/"+required.Name, JSONPatchNoError(existing, required))
	}

	actual, err := client.CronJobs(required.Namespace).Update(existingCopy)
	reportUpdateEvent(recorder, required, err)
	return actual, true, err
}

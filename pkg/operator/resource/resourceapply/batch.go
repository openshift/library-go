package resourceapply

import (
	"context"
	"fmt"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	batchclientv1 "k8s.io/client-go/kubernetes/typed/batch/v1"
)

// ApplyJob ensures the form of the specified job is present in the API. If it
// does not exist, it will be created. If it does exist, the existing job will be deleted,
// and a new Job will be created.
func ApplyJob(ctx context.Context, client batchclientv1.JobsGetter, recorder events.Recorder,
	requiredOriginal *batchv1.Job, expectedGeneration int64) (*batchv1.Job, bool, error) {

	required := requiredOriginal.DeepCopy()
	err := SetSpecHashAnnotation(&required.ObjectMeta, required.Spec)
	if err != nil {
		return nil, false, err
	}

	existing, err := client.Jobs(required.Namespace).Get(ctx, required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		actual, err := client.Jobs(required.Namespace).Create(ctx, required, metav1.CreateOptions{})
		resourcehelper.ReportCreateEvent(recorder, required, err)
		return actual, true, nil
	}
	if err != nil {
		return nil, false, err
	}

	modified := false
	existingCopy := existing.DeepCopy()
	resourcemerge.EnsureObjectMeta(&modified, &existingCopy.ObjectMeta, required.ObjectMeta)

	// there was no change to metadata, and the generation was right
	if !modified && existingCopy.ObjectMeta.Generation == expectedGeneration {
		return existingCopy, false, nil
	}

	// We do not update jobs, we always recreate them, since significant parts are immutable.
	// Delete here, recreate on next sync.
	err = client.Jobs(required.Namespace).Delete(ctx, required.Name, metav1.DeleteOptions{})
	if err != nil {
		return nil, false, err
	}
	resourcehelper.ReportDeleteEvent(recorder, required, nil)
	return nil, false, fmt.Errorf("job spec was modified, old job is deleted")
}

package resourceapply

import (
	"context"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"

	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	policyclientv1 "k8s.io/client-go/kubernetes/typed/policy/v1"
)

// ApplyPDB just creates the PDB associated.
func ApplyPDB(client policyclientv1.PodDisruptionBudgetsGetter, recorder events.Recorder, required *policyv1.PodDisruptionBudget) (*policyv1.PodDisruptionBudget, bool, error) {
	existing, err := client.PodDisruptionBudgets(required.Namespace).Get(context.TODO(), required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		requiredCopy := required.DeepCopy()
		actual, err := client.PodDisruptionBudgets(requiredCopy.Namespace).
			Create(context.TODO(), resourcemerge.WithCleanLabelsAndAnnotations(requiredCopy).(*policyv1.PodDisruptionBudget), metav1.CreateOptions{})
		reportCreateEvent(recorder, requiredCopy, err)
		return actual, true, err
	}

	modified := resourcemerge.BoolPtr(false)
	existingCopy := existing.DeepCopy()

	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, required.ObjectMeta)
	contentSame := equality.Semantic.DeepEqual(existingCopy.Spec, required.Spec)
	if !*modified && contentSame {
		return existingCopy, false, nil
	}
	existingCopy.Spec = *required.Spec.DeepCopy()
	if klog.V(4).Enabled() {
		klog.Infof("PDB %q changes: %v", required.Namespace+"/"+required.Name,
			JSONPatchNoError(existing, required))
	}
	actual, err := client.PodDisruptionBudgets(required.Namespace).Update(context.TODO(), existingCopy, metav1.UpdateOptions{})
	reportUpdateEvent(recorder, required, err)
	return actual, true, err
}

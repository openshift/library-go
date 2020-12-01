package resourceapply

import (
	"context"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionclientv1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

// ApplyValidatingWebhookConfiguration merges objectmeta, update webhooks.
func ApplyValidatingWebhookConfiguration(client admissionclientv1.ValidatingWebhookConfigurationsGetter, recorder events.Recorder,
	requiredOriginal *admissionv1.ValidatingWebhookConfiguration, expectedGeneration int64) (*admissionv1.ValidatingWebhookConfiguration, bool, error) {
	required := requiredOriginal.DeepCopy()
	err := SetSpecHashAnnotation(&required.ObjectMeta, required.Webhooks)
	if err != nil {
		return nil, false, err
	}

	existing, err := client.ValidatingWebhookConfigurations().Get(context.TODO(), required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		actual, err := client.ValidatingWebhookConfigurations().
			Create(context.TODO(), required, metav1.CreateOptions{})
		reportCreateEvent(recorder, required, err)
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}

	modified := resourcemerge.BoolPtr(false)
	existingCopy := existing.DeepCopy()

	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, required.ObjectMeta)
	if !*modified && existingCopy.ObjectMeta.Generation == expectedGeneration {
		return existingCopy, false, nil
	}

	if klog.V(4).Enabled() {
		klog.Infof("ValidatingWebhookConfiguration %q changes: %v", required.Name, JSONPatchNoError(existing, required))
	}

	existingCopy.Webhooks = required.Webhooks
	actual, err := client.ValidatingWebhookConfigurations().Update(context.TODO(), existingCopy, metav1.UpdateOptions{})
	reportUpdateEvent(recorder, required, err)
	return actual, true, err
}

// ApplyMutatingWebhookConfiguration merges objectmeta, update webhooks.
func ApplyMutatingWebhookConfiguration(client admissionclientv1.MutatingWebhookConfigurationsGetter, recorder events.Recorder,
	requiredOriginal *admissionv1.MutatingWebhookConfiguration, expectedGeneration int64) (*admissionv1.MutatingWebhookConfiguration, bool, error) {
	required := requiredOriginal.DeepCopy()
	err := SetSpecHashAnnotation(&required.ObjectMeta, required.Webhooks)
	if err != nil {
		return nil, false, err
	}

	existing, err := client.MutatingWebhookConfigurations().Get(context.TODO(), required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		actual, err := client.MutatingWebhookConfigurations().
			Create(context.TODO(), required, metav1.CreateOptions{})
		reportCreateEvent(recorder, required, err)
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}

	modified := resourcemerge.BoolPtr(false)
	existingCopy := existing.DeepCopy()

	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, required.ObjectMeta)
	if !*modified && existingCopy.ObjectMeta.Generation == expectedGeneration {
		return existingCopy, false, nil
	}

	if klog.V(4).Enabled() {
		klog.Infof("ValidatingWebhookConfiguration %q changes: %v", required.Name, JSONPatchNoError(existing, required))
	}

	existingCopy.Webhooks = required.Webhooks
	actual, err := client.MutatingWebhookConfigurations().Update(context.TODO(), existingCopy, metav1.UpdateOptions{})
	reportUpdateEvent(recorder, required, err)
	return actual, true, err
}

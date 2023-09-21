package resourceapply

import (
	"context"
	errorsstdlib "errors"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"

	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

var prometheusRuleGVR = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheusrules"}
var serviceMonitorGVR = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors"}

// ApplyPrometheusRule applies the PrometheusRule.
func ApplyPrometheusRule(ctx context.Context, client dynamic.Interface, recorder events.Recorder, required *unstructured.Unstructured) (*unstructured.Unstructured, bool, error) {
	return ApplyUnstructuredResourceImproved(ctx, client, recorder, required, noCache, prometheusRuleGVR)
}

// DeletePrometheusRule deletes the PrometheusRule.
func DeletePrometheusRule(ctx context.Context, client dynamic.Interface, recorder events.Recorder, required *unstructured.Unstructured) (*unstructured.Unstructured, bool, error) {
	return DeleteUnstructuredResource(ctx, client, recorder, required, prometheusRuleGVR)
}

// ApplyServiceMonitor applies the ServiceMonitor.
func ApplyServiceMonitor(ctx context.Context, client dynamic.Interface, recorder events.Recorder, required *unstructured.Unstructured) (*unstructured.Unstructured, bool, error) {
	return ApplyUnstructuredResourceImproved(ctx, client, recorder, required, noCache, serviceMonitorGVR)
}

// DeleteServiceMonitor deletes the ServiceMonitor.
func DeleteServiceMonitor(ctx context.Context, client dynamic.Interface, recorder events.Recorder, required *unstructured.Unstructured) (*unstructured.Unstructured, bool, error) {
	return DeleteUnstructuredResource(ctx, client, recorder, required, serviceMonitorGVR)
}

// ApplyUnstructuredResourceImproved can utilize the cache to reconcile the existing resource to the desired state.
func ApplyUnstructuredResourceImproved(ctx context.Context, client dynamic.Interface, recorder events.Recorder, required *unstructured.Unstructured, cache ResourceCache, resourceGVR schema.GroupVersionResource) (*unstructured.Unstructured, bool, error) {
	name := required.GetName()
	namespace := required.GetNamespace()

	// Create if resource does not exist, and update cache with new metadata.
	existing, err := client.Resource(resourceGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		requiredCopy := required.DeepCopy()
		want, err := client.Resource(resourceGVR).Namespace(namespace).Create(ctx, required, metav1.CreateOptions{})
		reportCreateEvent(recorder, requiredCopy, err)
		cache.UpdateCachedResourceMetadata(required, want)
		return want, true, err
	}
	if err != nil {
		return nil, false, err
	}

	// Return if the metadata hash or resource version matches.
	if cache.SafeToSkipApply(required, existing) {
		return existing, false, nil
	}

	// Ensure all expected metadata fields are set.
	existingCopy := existing.DeepCopy()
	existingObjectMeta, found, err := unstructured.NestedMap(existingCopy.Object, "metadata")
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, errorsstdlib.New(fmt.Sprintf("metadata not found in %s", existingCopy.GetName()))
	}
	requiredObjectMeta, found, err := unstructured.NestedMap(required.Object, "metadata")
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, errorsstdlib.New(fmt.Sprintf("metadata not found in %s", required.GetName()))
	}
	var existingObjectMetaTyped, requiredObjectMetaTyped metav1.ObjectMeta
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(existingObjectMeta, &existingObjectMetaTyped)
	if err != nil {
		return nil, false, err
	}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(requiredObjectMeta, &requiredObjectMetaTyped)
	if err != nil {
		return nil, false, err
	}
	modifiedPtr := resourcemerge.BoolPtr(false)
	resourcemerge.EnsureObjectMeta(modifiedPtr, &existingObjectMetaTyped, requiredObjectMetaTyped)
	if !*modifiedPtr {
		// Update cache even if certain fields are not modified, in order to maintain a consistent cache based on the
		// resource hash. The resource hash depends on the entire metadata, not just the fields that were checked above.
		cache.UpdateCachedResourceMetadata(required, existingCopy)
		return existingCopy, false, nil
	}

	// Ensure all expected spec fields are set.
	existingCopy, modified, err := ensureGenericSpec(required, existingCopy, noDefaulting, nil)
	if err != nil {
		return nil, false, err
	}
	if !modified {
		cache.UpdateCachedResourceMetadata(required, existingCopy)
		return existingCopy, false, nil
	}

	if klog.V(4).Enabled() {
		klog.Infof("%s %q changes: %v", resourceGVR.String(), namespace+"/"+name, JSONPatchNoError(existing, existingCopy))
	}

	// Perform update if resource exists but different from the desired one.
	actual, err := client.Resource(resourceGVR).Namespace(namespace).Update(ctx, existingCopy, metav1.UpdateOptions{})
	reportUpdateEvent(recorder, required, err)
	cache.UpdateCachedResourceMetadata(required, actual)
	return actual, true, err
}

// DeleteUnstructuredResource deletes the unstructured resource.
func DeleteUnstructuredResource(ctx context.Context, client dynamic.Interface, recorder events.Recorder, required *unstructured.Unstructured, resourceGVR schema.GroupVersionResource) (*unstructured.Unstructured, bool, error) {
	err := client.Resource(resourceGVR).Namespace(required.GetNamespace()).Delete(ctx, required.GetName(), metav1.DeleteOptions{})
	if err != nil && errors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	resourcehelper.ReportDeleteEvent(recorder, required, err)
	return nil, true, nil
}

func ensureGenericSpec(required, existing *unstructured.Unstructured, mimicDefaultingFn mimicDefaultingFunc, equalityChecker equalityChecker) (*unstructured.Unstructured, bool, error) {
	requiredCopy := required.DeepCopy()
	mimicDefaultingFn(requiredCopy)
	requiredSpec, _, err := unstructured.NestedMap(requiredCopy.UnstructuredContent(), "spec")
	if err != nil {
		return nil, false, err
	}
	existingSpec, _, err := unstructured.NestedMap(existing.UnstructuredContent(), "spec")
	if err != nil {
		return nil, false, err
	}

	if equalityChecker.DeepEqual(existingSpec, requiredSpec) {
		return existing, false, nil
	}

	existingCopy := existing.DeepCopy()
	if err := unstructured.SetNestedMap(existingCopy.UnstructuredContent(), requiredSpec, "spec"); err != nil {
		return nil, true, err
	}

	return existingCopy, true, nil
}

// mimicDefaultingFunc is used to set fields that are defaulted.  This allows for sparse manifests to apply correctly.
// For instance, if field .spec.foo is set to 10 if not set, then a function of this type could be used to set
// the field to 10 to match the comparison.  This is sometimes (often?) easier than updating the semantic equality.
// We often see this in places like RBAC and CRD.  Logically it can happen generically too.
type mimicDefaultingFunc func(obj *unstructured.Unstructured)

func noDefaulting(*unstructured.Unstructured) {}

// equalityChecker allows for custom equality comparisons.  This can be used to allow equality checks to skip certain
// operator managed fields.  This capability allows something like .spec.scale to be specified or changed by a component
// like HPA.  Use this capability sparingly.  Most places ought to just use `equality.Semantic`
type equalityChecker interface {
	DeepEqual(a1, a2 interface{}) bool
}

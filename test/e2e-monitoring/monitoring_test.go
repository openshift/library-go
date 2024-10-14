package e2e_monitoring

import (
	"context"
	clocktesting "k8s.io/utils/clock/testing"
	"os"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	noUpdate = iota
	metadataUpdate
	specAndMaybeMetadataUpdate
)

// didUpdate compares two unstructured resources and returns if the specified parts changed.
func didUpdate(old, new *unstructured.Unstructured) (int, error) {
	oldResourceVersion, _, err := unstructured.NestedString(old.Object, "metadata", "resourceVersion")
	if err != nil {
		return 0, err
	}
	newResourceVersion, _, err := unstructured.NestedString(new.Object, "metadata", "resourceVersion")
	if err != nil {
		return 0, err
	}
	oldGeneration, _, err := unstructured.NestedInt64(old.Object, "metadata", "generation")
	if err != nil {
		return 0, err
	}
	newGeneration, _, err := unstructured.NestedInt64(new.Object, "metadata", "generation")
	if err != nil {
		return 0, err
	}
	if oldResourceVersion != newResourceVersion {
		if oldGeneration != newGeneration {
			return specAndMaybeMetadataUpdate, nil
		}
		return metadataUpdate, nil
	}

	return noUpdate, nil
}

func TestResourceVersionApplication(t *testing.T) {
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	require.NoError(t, err)

	// Define the resource.
	duration := monv1.Duration("5m")
	resource := monv1.PrometheusRule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "monitoring.coreos.com/v1",
			Kind:       "PrometheusRule",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-prometheusrule",
			Namespace: "default",
		},
		Spec: monv1.PrometheusRuleSpec{
			Groups: []monv1.RuleGroup{
				{
					Name: "example",
					Rules: []monv1.Rule{
						{
							Alert: "Foo",
							Expr:  intstr.FromString("foo > 0"),
							For:   &duration,
							Labels: map[string]string{
								"bar": "baz",
							},
						},
					},
				},
			},
		},
	}
	gvr := schema.GroupVersionResource{
		Group:    resource.GroupVersionKind().Group,
		Version:  resource.GroupVersionKind().Version,
		Resource: "prometheusrules",
	}

	// Initialize pre-requisites.
	cache := resourceapply.NewResourceCache()
	recorder := events.NewInMemoryRecorder("TestResourceVersionApplication", clocktesting.NewFakePassiveClock(time.Now()))
	dynamicClient, err := dynamic.NewForConfig(config)
	require.NoError(t, err)

	// Create the resource.
	unstructuredResource := &unstructured.Unstructured{}
	unstructuredResourceMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&resource)
	require.NoError(t, err)
	unstructuredResource.SetUnstructuredContent(unstructuredResourceMap)
	oldUnstructuredResource := unstructuredResource.DeepCopy()
	gotUnstructuredResource, err := resourceapply.ApplyUnstructuredResourceImproved(
		context.TODO(),
		dynamicClient,
		recorder,
		unstructuredResource,
		cache,
		gvr,
		nil,
		nil,
	)
	if err != nil && !errors.IsAlreadyExists(err) {
		t.Fatalf("Failed to create resource: %v", err)
	}
	expectation, err := didUpdate(oldUnstructuredResource, gotUnstructuredResource)
	if err != nil {
		t.Fatalf("Failed to compare resources: %v", err)
	}
	require.True(t, expectation != noUpdate)

	// Update the resource version and the generation since we made a spec change.
	unstructuredResource.SetResourceVersion(gotUnstructuredResource.GetResourceVersion())
	unstructuredResource.SetGeneration(gotUnstructuredResource.GetGeneration())
	unstructuredResource.SetCreationTimestamp(gotUnstructuredResource.GetCreationTimestamp())
	unstructuredResource.SetUID(gotUnstructuredResource.GetUID())
	unstructuredResource.SetManagedFields(gotUnstructuredResource.GetManagedFields())
	require.Equal(t, unstructuredResource.UnstructuredContent(), gotUnstructuredResource.UnstructuredContent())

	// Compare the existing resource with the one we have.
	existingResourceUnstructured, err := dynamicClient.Resource(gvr).Namespace(resource.GetNamespace()).Get(context.TODO(), resource.GetName(), metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, unstructuredResource.UnstructuredContent(), existingResourceUnstructured.UnstructuredContent())

	// Update the resource with a change, without specifying a resource version.
	resource.Spec.Groups[0].Rules[0].Labels["bar"] = "qux"
	unstructuredResourceMap, err = runtime.DefaultUnstructuredConverter.ToUnstructured(&resource)
	require.NoError(t, err)
	unstructuredResource.SetUnstructuredContent(unstructuredResourceMap)
	oldUnstructuredResource = gotUnstructuredResource.DeepCopy()
	gotUnstructuredResource, err = resourceapply.ApplyUnstructuredResourceImproved(
		context.TODO(),
		dynamicClient,
		recorder,
		unstructuredResource,
		cache,
		gvr,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to update resource: %v", err)
	}
	expectation, err = didUpdate(oldUnstructuredResource, gotUnstructuredResource)
	if err != nil {
		t.Fatalf("Failed to compare resources: %v", err)
	}
	require.True(t, expectation == specAndMaybeMetadataUpdate)

	// Update the resource version and the generation since we made a spec change.
	unstructuredResource.SetResourceVersion(gotUnstructuredResource.GetResourceVersion())
	unstructuredResource.SetGeneration(gotUnstructuredResource.GetGeneration())
	unstructuredResource.SetCreationTimestamp(gotUnstructuredResource.GetCreationTimestamp())
	unstructuredResource.SetUID(gotUnstructuredResource.GetUID())
	unstructuredResource.SetManagedFields(gotUnstructuredResource.GetManagedFields())
	require.Equal(t, unstructuredResource.UnstructuredContent(), gotUnstructuredResource.UnstructuredContent())

	// Compare the existing resource with the one we have.
	existingResourceUnstructured, err = dynamicClient.Resource(gvr).Namespace(resource.GetNamespace()).Get(context.TODO(), resource.GetName(), metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, unstructuredResource.UnstructuredContent(), existingResourceUnstructured.UnstructuredContent())

	// Update the resource without any changes, without specifying a resource version.
	oldUnstructuredResource = gotUnstructuredResource.DeepCopy()
	gotUnstructuredResource, err = resourceapply.ApplyUnstructuredResourceImproved(
		context.TODO(),
		dynamicClient,
		recorder,
		unstructuredResource,
		cache,
		gvr,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to update resource: %v", err)
	}
	expectation, err = didUpdate(oldUnstructuredResource, gotUnstructuredResource)
	if err != nil {
		t.Fatalf("Failed to compare resources: %v", err)
	}
	require.True(t, expectation == noUpdate)

	// Do not update any fields as no change was made.
	require.Equal(t, unstructuredResource.UnstructuredContent(), gotUnstructuredResource.UnstructuredContent())

	// Compare the existing resource with the one we have.
	existingResourceUnstructured, err = dynamicClient.Resource(gvr).Namespace(resource.GetNamespace()).Get(context.TODO(), resource.GetName(), metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, unstructuredResource.UnstructuredContent(), existingResourceUnstructured.UnstructuredContent())

	// Delete the resource.
	err = dynamicClient.Resource(gvr).Namespace(resource.GetNamespace()).Delete(context.TODO(), resource.GetName(), metav1.DeleteOptions{})
	require.NoError(t, err)
}

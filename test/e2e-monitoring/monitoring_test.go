package e2e_monitoring

import (
	"context"
	clocktesting "k8s.io/utils/clock/testing"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/test/library"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
)

func TestResourceVersionApplication(t *testing.T) {
	config, err := library.NewClientConfigForTest()
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
	gotUnstructured, didUpdate, err := resourceapply.ApplyUnstructuredResourceImproved(
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
	require.True(t, didUpdate)

	// Update the resource version and the generation since we made a spec change.
	unstructuredResource.SetResourceVersion(gotUnstructured.GetResourceVersion())
	unstructuredResource.SetGeneration(gotUnstructured.GetGeneration())
	unstructuredResource.SetCreationTimestamp(gotUnstructured.GetCreationTimestamp())
	unstructuredResource.SetUID(gotUnstructured.GetUID())
	unstructuredResource.SetManagedFields(gotUnstructured.GetManagedFields())
	require.Equal(t, unstructuredResource.UnstructuredContent(), gotUnstructured.UnstructuredContent())

	// Compare the existing resource with the one we have.
	existingResourceUnstructured, err := dynamicClient.Resource(gvr).Namespace(resource.GetNamespace()).Get(context.TODO(), resource.GetName(), metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, unstructuredResource.UnstructuredContent(), existingResourceUnstructured.UnstructuredContent())

	// Update the resource with a change, without specifying a resource version.
	resource.Spec.Groups[0].Rules[0].Labels["bar"] = "qux"
	unstructuredResourceMap, err = runtime.DefaultUnstructuredConverter.ToUnstructured(&resource)
	require.NoError(t, err)
	unstructuredResource.SetUnstructuredContent(unstructuredResourceMap)
	gotUnstructured, didUpdate, err = resourceapply.ApplyUnstructuredResourceImproved(
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
	require.True(t, didUpdate)

	// Update the resource version and the generation since we made a spec change.
	unstructuredResource.SetResourceVersion(gotUnstructured.GetResourceVersion())
	unstructuredResource.SetGeneration(gotUnstructured.GetGeneration())
	unstructuredResource.SetCreationTimestamp(gotUnstructured.GetCreationTimestamp())
	unstructuredResource.SetUID(gotUnstructured.GetUID())
	unstructuredResource.SetManagedFields(gotUnstructured.GetManagedFields())
	require.Equal(t, unstructuredResource.UnstructuredContent(), gotUnstructured.UnstructuredContent())

	// Compare the existing resource with the one we have.
	existingResourceUnstructured, err = dynamicClient.Resource(gvr).Namespace(resource.GetNamespace()).Get(context.TODO(), resource.GetName(), metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, unstructuredResource.UnstructuredContent(), existingResourceUnstructured.UnstructuredContent())

	// Update the resource without any changes, without specifying a resource version.
	gotUnstructured, didUpdate, err = resourceapply.ApplyUnstructuredResourceImproved(
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
	require.False(t, didUpdate)

	// Do not update any fields as no change was made.
	require.Equal(t, unstructuredResource.UnstructuredContent(), gotUnstructured.UnstructuredContent())

	// Compare the existing resource with the one we have.
	existingResourceUnstructured, err = dynamicClient.Resource(gvr).Namespace(resource.GetNamespace()).Get(context.TODO(), resource.GetName(), metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, unstructuredResource.UnstructuredContent(), existingResourceUnstructured.UnstructuredContent())

	// Delete the resource.
	err = dynamicClient.Resource(gvr).Namespace(resource.GetNamespace()).Delete(context.TODO(), resource.GetName(), metav1.DeleteOptions{})
	require.NoError(t, err)
}

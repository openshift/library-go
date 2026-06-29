package encryption

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"

	routev1 "github.com/openshift/api/route/v1"
)

var routeGVR = schema.GroupVersionResource{Group: "route.openshift.io", Version: "v1", Resource: "routes"}

func CreateAndStoreRouteOfLife(ctx context.Context, t testing.TB, cs ClientSet, ns string) runtime.Object {
	t.Helper()
	t.Logf("Creating %q in %q namespace", "route-of-life", ns)

	route := RouteOfLife(t, ns)
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(route)
	require.NoError(t, err)

	created, err := cs.DynamicClient.Resource(routeGVR).Namespace(ns).Create(ctx, &unstructured.Unstructured{Object: obj}, metav1.CreateOptions{})
	require.NoError(t, err)

	var result routev1.Route
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(created.Object, &result)
	require.NoError(t, err)
	return &result
}

func RouteOfLife(_ testing.TB, ns string) runtime.Object {
	return &routev1.Route{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "route.openshift.io/v1",
			Kind:       "Route",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route-of-life",
			Namespace: ns,
		},
		Spec: routev1.RouteSpec{
			Host: "devcluster.openshift.io",
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromInt(2014),
			},
			To: routev1.RouteTargetReference{
				Name: "dummyroute",
			},
		},
	}
}

func GetRawRouteOfLife(t testing.TB, clientSet ClientSet, ns string) string {
	t.Helper()
	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	routeOfLifeKey := fmt.Sprintf("/openshift.io/routes/%s/%s", ns, "route-of-life")
	resp, err := clientSet.Etcd.Get(timeout, routeOfLifeKey)
	require.NoError(t, err)
	require.Len(t, resp.Kvs, 1, "expected exactly one key from etcd for route-of-life")

	return string(resp.Kvs[0].Value)
}

package encryption

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
)

var OASTargetGRs = []schema.GroupResource{
	{Group: "route.openshift.io", Resource: "routes"},
}

func AssertRouteOfLifeEncrypted(t testing.TB, clientSet ClientSet, resource runtime.Object) {
	t.Helper()
	routeOfLife, ok := resource.(*routev1.Route)
	if !ok {
		t.Fatalf("expected *routev1.Route, got %T", resource)
	}
	rawRouteValue := GetRawRouteOfLife(t, clientSet, routeOfLife.Namespace)
	if strings.Contains(rawRouteValue, routeOfLife.Spec.To.Name) {
		t.Errorf("route not encrypted, etcd value contains target name %q in plain text", routeOfLife.Spec.To.Name)
	}
}

func AssertRouteOfLifeNotEncrypted(t testing.TB, clientSet ClientSet, resource runtime.Object) {
	t.Helper()
	routeOfLife, ok := resource.(*routev1.Route)
	if !ok {
		t.Fatalf("expected *routev1.Route, got %T", resource)
	}
	rawRouteValue := GetRawRouteOfLife(t, clientSet, routeOfLife.Namespace)
	if !strings.Contains(rawRouteValue, routeOfLife.Spec.To.Name) {
		t.Errorf("route not decrypted, etcd value does not contain target name %q in plain text", routeOfLife.Spec.To.Name)
	}
}

func AssertRoutes(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
	t.Helper()
	assertRoutes(t, clientSet.Etcd, string(expectedMode))
	AssertLastMigratedKey(t, clientSet.Kube, OASTargetGRs, namespace, labelSelector)
}

func assertRoutes(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all Routes where encrypted/decrypted for %q mode", expectedMode)
	totalRoutes, err := VerifyResources(t, etcdClient, "/openshift.io/routes/", expectedMode, false)
	t.Logf("Verified %d Routes", totalRoutes)
	require.NoError(t, err)
}

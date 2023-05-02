package manager

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	routev1 "github.com/openshift/api/route/v1"
)

// Manager is the interface for registering and unregistering
// objects referenced by pods in the underlying cache and
// extracting those from that cache if needed.
type Manager interface {
	// Get object by its namespace and name.
	GetObject(namespace, name string) (runtime.Object, error)

	// WARNING: Register/UnregisterRoute functions should be efficient,
	// i.e. should not block on network operations.

	// RegisterRoute registers all objects referenced from a given Route.
	//
	// NOTE: All implementations of RegisterRoute should be idempotent.
	RegisterRoute(pod *routev1.Route)

	// UnregisterRoute unregisters objects referenced from a given route that are not
	// used by any other registered route.
	//
	// NOTE: All implementations of UnregisterRoute should be idempotent.
	UnregisterRoute(pod *routev1.Route)
}

// Store is the interface for a object cache that
// can be used by cacheBasedManager.
type Store interface {
	// AddReference adds a reference to the object to the store.
	// Note that multiple additions to the store has to be allowed
	// in the implementations and effectively treated as refcounted.
	AddReference(namespace, name string)
	// DeleteReference deletes reference to the object from the store.
	// Note that object should be deleted only when there was a
	// corresponding Delete call for each of Add calls (effectively
	// when refcount was reduced to zero).
	DeleteReference(namespace, name string)
	// Get an object from a store.
	Get(namespace, name string) (runtime.Object, error)
}

// fromApiserverCache modifies <opts> so that the GET request will
// be served from apiserver cache instead of from etcd.
func fromApiserverCache(opts *metav1.GetOptions) {
	opts.ResourceVersion = "0"
}

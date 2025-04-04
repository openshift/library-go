// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	operatorcontrolplanev1alpha1 "github.com/openshift/api/operatorcontrolplane/v1alpha1"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// PodNetworkConnectivityCheckLister helps list PodNetworkConnectivityChecks.
// All objects returned here must be treated as read-only.
type PodNetworkConnectivityCheckLister interface {
	// List lists all PodNetworkConnectivityChecks in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck, err error)
	// PodNetworkConnectivityChecks returns an object that can list and get PodNetworkConnectivityChecks.
	PodNetworkConnectivityChecks(namespace string) PodNetworkConnectivityCheckNamespaceLister
	PodNetworkConnectivityCheckListerExpansion
}

// podNetworkConnectivityCheckLister implements the PodNetworkConnectivityCheckLister interface.
type podNetworkConnectivityCheckLister struct {
	listers.ResourceIndexer[*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck]
}

// NewPodNetworkConnectivityCheckLister returns a new PodNetworkConnectivityCheckLister.
func NewPodNetworkConnectivityCheckLister(indexer cache.Indexer) PodNetworkConnectivityCheckLister {
	return &podNetworkConnectivityCheckLister{listers.New[*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck](indexer, operatorcontrolplanev1alpha1.Resource("podnetworkconnectivitycheck"))}
}

// PodNetworkConnectivityChecks returns an object that can list and get PodNetworkConnectivityChecks.
func (s *podNetworkConnectivityCheckLister) PodNetworkConnectivityChecks(namespace string) PodNetworkConnectivityCheckNamespaceLister {
	return podNetworkConnectivityCheckNamespaceLister{listers.NewNamespaced[*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck](s.ResourceIndexer, namespace)}
}

// PodNetworkConnectivityCheckNamespaceLister helps list and get PodNetworkConnectivityChecks.
// All objects returned here must be treated as read-only.
type PodNetworkConnectivityCheckNamespaceLister interface {
	// List lists all PodNetworkConnectivityChecks in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck, err error)
	// Get retrieves the PodNetworkConnectivityCheck from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck, error)
	PodNetworkConnectivityCheckNamespaceListerExpansion
}

// podNetworkConnectivityCheckNamespaceLister implements the PodNetworkConnectivityCheckNamespaceLister
// interface.
type podNetworkConnectivityCheckNamespaceLister struct {
	listers.ResourceIndexer[*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck]
}

package v1helpers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

var (
	emptyGetOptions  = metav1.GetOptions{}
	emptyListOptions = metav1.ListOptions{}
)

// combinedConfigMapGetter implements corev1client.ConfigMapsGetter using a client and a KubeInformersForNamespaces.
type combinedConfigMapGetter struct {
	client  corev1client.ConfigMapsGetter
	listers KubeInformersForNamespaces
}

// CachedConfigMapGetter returns a corev1client.ConfigMapsGetter that uses cached informers
// from KubeInformersForNamespaces for read operations. Write operations are delegated to the provided client.
func CachedConfigMapGetter(client corev1client.ConfigMapsGetter, listers KubeInformersForNamespaces) corev1client.ConfigMapsGetter {
	return &combinedConfigMapGetter{
		client:  client,
		listers: listers,
	}
}

// combinedConfigMapInterface implements corev1client.ConfigMapInterface using a client and a namespaced lister.
type combinedConfigMapInterface struct {
	corev1client.ConfigMapInterface
	lister    corev1listers.ConfigMapNamespaceLister
	namespace string
}

// ConfigMaps returns a combinedConfigMapInterface for the given namespace.
func (g combinedConfigMapGetter) ConfigMaps(namespace string) corev1client.ConfigMapInterface {
	return combinedConfigMapInterface{
		ConfigMapInterface: g.client.ConfigMaps(namespace),
		lister:             g.listers.InformersFor(namespace).Core().V1().ConfigMaps().Lister().ConfigMaps(namespace),
		namespace:          namespace,
	}
}

// Get retrieves a ConfigMap from the cache. GetOptions are not honored.
func (g combinedConfigMapInterface) Get(_ context.Context, name string, options metav1.GetOptions) (*corev1.ConfigMap, error) {
	if !equality.Semantic.DeepEqual(options, emptyGetOptions) {
		return nil, fmt.Errorf("GetOptions are not honored by cached client: %#v", options)
	}

	ret, err := g.lister.Get(name)
	if err != nil {
		return nil, err
	}
	return ret.DeepCopy(), nil
}

// List retrieves a list of ConfigMaps from the cache. ListOptions are not honored.
func (g combinedConfigMapInterface) List(_ context.Context, options metav1.ListOptions) (*corev1.ConfigMapList, error) {
	if !equality.Semantic.DeepEqual(options, emptyListOptions) {
		return nil, fmt.Errorf("ListOptions are not honored by cached client: %#v", options)
	}

	list, err := g.lister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	ret := &corev1.ConfigMapList{}
	for i := range list {
		ret.Items = append(ret.Items, *(list[i].DeepCopy()))
	}
	return ret, nil
}

// combinedSecretGetter implements corev1client.SecretsGetter using a client and a KubeInformersForNamespaces.
type combinedSecretGetter struct {
	client  corev1client.SecretsGetter
	listers KubeInformersForNamespaces
}

// CachedSecretGetter returns a corev1client.SecretsGetter that uses cached informers
// from KubeInformersForNamespaces for read operations. Write operations are delegated to the provided client.
func CachedSecretGetter(client corev1client.SecretsGetter, listers KubeInformersForNamespaces) corev1client.SecretsGetter {
	return &combinedSecretGetter{
		client:  client,
		listers: listers,
	}
}

// combinedSecretInterface implements corev1client.SecretInterface using a client and a namespaced lister.
type combinedSecretInterface struct {
	corev1client.SecretInterface
	lister    corev1listers.SecretNamespaceLister
	namespace string
}

// Secrets returns a combinedSecretInterface for the given namespace.
func (g combinedSecretGetter) Secrets(namespace string) corev1client.SecretInterface {
	return combinedSecretInterface{
		SecretInterface: g.client.Secrets(namespace),
		lister:          g.listers.InformersFor(namespace).Core().V1().Secrets().Lister().Secrets(namespace),
		namespace:       namespace,
	}
}

// Get retrieves a Secret from the cache. GetOptions are not honored.
func (g combinedSecretInterface) Get(_ context.Context, name string, options metav1.GetOptions) (*corev1.Secret, error) {
	if !equality.Semantic.DeepEqual(options, emptyGetOptions) {
		return nil, fmt.Errorf("GetOptions are not honored by cached client: %#v", options)
	}

	ret, err := g.lister.Get(name)
	if err != nil {
		return nil, err
	}
	return ret.DeepCopy(), nil
}

// List retrieves a list of Secrets from the cache. ListOptions are not honored.
func (g combinedSecretInterface) List(_ context.Context, options metav1.ListOptions) (*corev1.SecretList, error) {
	if !equality.Semantic.DeepEqual(options, emptyListOptions) {
		return nil, fmt.Errorf("ListOptions are not honored by cached client: %#v", options)
	}

	list, err := g.lister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	ret := &corev1.SecretList{}
	for i := range list {
		ret.Items = append(ret.Items, *(list[i].DeepCopy()))
	}
	return ret, nil
}

// namespacedConfigMapGetter implements corev1client.ConfigMapsGetter
// for a single, predefined namespace, using a shared informer for cached reads.
type namespacedConfigMapGetter struct {
	client          corev1client.ConfigMapsGetter
	informerFactory informers.SharedInformerFactory
	namespace       string // The specific namespace this getter is for
}

// NewNamespacedCachedConfigMapGetter returns a corev1client.ConfigMapsGetter that is scoped to a specific namespace.
// Read operations for the specified namespace will use the shared informer cache.
// Read operations for other namespaces (if any) and all write operations will be delegated to the provided client.
func NewNamespacedCachedConfigMapGetter(client corev1client.ConfigMapsGetter, informerFactory informers.SharedInformerFactory, namespace string) corev1client.ConfigMapsGetter {
	return &namespacedConfigMapGetter{
		client:          client,
		informerFactory: informerFactory,
		namespace:       namespace,
	}
}

// ConfigMaps returns a ConfigMapInterface. If the requested namespace matches the predefined namespace,
// it returns a cached interface. Otherwise, it returns the client's direct interface.
func (g *namespacedConfigMapGetter) ConfigMaps(namespace string) corev1client.ConfigMapInterface {
	// If the requested namespace matches the getter's predefined namespace, use the cached interface.
	if namespace == g.namespace {
		return combinedConfigMapInterface{
			ConfigMapInterface: g.client.ConfigMaps(namespace), // Delegate write operations
			lister:             g.informerFactory.Core().V1().ConfigMaps().Lister().ConfigMaps(namespace),
			namespace:          namespace,
		}
	}
	// For any other namespace, or if it's not the designated namespace, delegate to the uncached client.
	return g.client.ConfigMaps(namespace)
}

// namespacedSecretGetter implements corev1client.SecretsGetter
// for a single, predefined namespace, using a shared informer for cached reads.
type namespacedSecretGetter struct {
	client          corev1client.SecretsGetter
	informerFactory informers.SharedInformerFactory
	namespace       string // The specific namespace this getter is for
}

// NewNamespacedCachedSecretGetter returns a corev1client.SecretsGetter that is scoped to a specific namespace.
// Read operations for the specified namespace will use the shared informer cache.
// Read operations for other namespaces (if any) and all write operations will be delegated to the provided client.
func NewNamespacedCachedSecretGetter(client corev1client.SecretsGetter, informerFactory informers.SharedInformerFactory, namespace string) corev1client.SecretsGetter {
	return &namespacedSecretGetter{
		client:          client,
		informerFactory: informerFactory,
		namespace:       namespace,
	}
}

// Secrets returns a SecretInterface. If the requested namespace matches the predefined namespace,
// it returns a cached interface. Otherwise, it returns the client's direct interface.
func (g *namespacedSecretGetter) Secrets(namespace string) corev1client.SecretInterface {
	// If the requested namespace matches the getter's predefined namespace, use the cached interface.
	if namespace == g.namespace {
		return combinedSecretInterface{
			SecretInterface: g.client.Secrets(namespace), // Delegate write operations
			lister:          g.informerFactory.Core().V1().Secrets().Lister().Secrets(namespace),
			namespace:       namespace,
		}
	}
	// For any other namespace, or if it's not the designated namespace, delegate to the uncached client.
	return g.client.Secrets(namespace)
}

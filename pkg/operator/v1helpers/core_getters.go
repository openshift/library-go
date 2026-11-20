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

type combinedConfigMapGetter struct {
	client  corev1client.ConfigMapsGetter
	listers KubeInformersForNamespaces
}

func CachedConfigMapGetter(client corev1client.ConfigMapsGetter, listers KubeInformersForNamespaces) corev1client.ConfigMapsGetter {
	return &combinedConfigMapGetter{
		client:  client,
		listers: listers,
	}
}

type combinedConfigMapInterface struct {
	corev1client.ConfigMapInterface
	lister    corev1listers.ConfigMapNamespaceLister
	namespace string
}

func (g combinedConfigMapGetter) ConfigMaps(namespace string) corev1client.ConfigMapInterface {
	return combinedConfigMapInterface{
		ConfigMapInterface: g.client.ConfigMaps(namespace),
		lister:             g.listers.InformersFor(namespace).Core().V1().ConfigMaps().Lister().ConfigMaps(namespace),
		namespace:          namespace,
	}
}

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

type combinedSecretGetter struct {
	client  corev1client.SecretsGetter
	listers KubeInformersForNamespaces
}

func CachedSecretGetter(client corev1client.SecretsGetter, listers KubeInformersForNamespaces) corev1client.SecretsGetter {
	return &combinedSecretGetter{
		client:  client,
		listers: listers,
	}
}

type combinedSecretInterface struct {
	corev1client.SecretInterface
	lister    corev1listers.SecretNamespaceLister
	namespace string
}

func (g combinedSecretGetter) Secrets(namespace string) corev1client.SecretInterface {
	return combinedSecretInterface{
		SecretInterface: g.client.Secrets(namespace),
		lister:          g.listers.InformersFor(namespace).Core().V1().Secrets().Lister().Secrets(namespace),
		namespace:       namespace,
	}
}

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

// namespacedConfigMapGetter implements corev1client.ConfigMapsGetter for a single
// target namespace, backed by a namespace-scoped shared informer for cached reads.
// Reads in any other namespace, and all writes, are delegated to the live client.
type namespacedConfigMapGetter struct {
	client          corev1client.ConfigMapsGetter
	informerFactory informers.SharedInformerFactory
	namespace       string
}

// NewNamespacedCachedConfigMapGetter returns a corev1client.ConfigMapsGetter whose
// reads in the target namespace are served from the given informer factory's cache,
// while reads in any other namespace and all writes go to the live client. Unlike
// CachedConfigMapGetter it has no dependency on a cluster-scoped informer, so
// undecodable objects stored outside the target namespace cannot break it.
func NewNamespacedCachedConfigMapGetter(client corev1client.ConfigMapsGetter, informerFactory informers.SharedInformerFactory, namespace string) corev1client.ConfigMapsGetter {
	return &namespacedConfigMapGetter{
		client:          client,
		informerFactory: informerFactory,
		namespace:       namespace,
	}
}

func (g *namespacedConfigMapGetter) ConfigMaps(namespace string) corev1client.ConfigMapInterface {
	if namespace != g.namespace {
		return g.client.ConfigMaps(namespace)
	}
	return combinedConfigMapInterface{
		ConfigMapInterface: g.client.ConfigMaps(namespace),
		lister:             g.informerFactory.Core().V1().ConfigMaps().Lister().ConfigMaps(namespace),
		namespace:          namespace,
	}
}

// namespacedSecretGetter implements corev1client.SecretsGetter for a single target
// namespace, backed by a namespace-scoped shared informer for cached reads.
// Reads in any other namespace, and all writes, are delegated to the live client.
type namespacedSecretGetter struct {
	client          corev1client.SecretsGetter
	informerFactory informers.SharedInformerFactory
	namespace       string
}

// NewNamespacedCachedSecretGetter returns a corev1client.SecretsGetter whose reads
// in the target namespace are served from the given informer factory's cache, while
// reads in any other namespace and all writes go to the live client. Unlike
// CachedSecretGetter it has no dependency on a cluster-scoped informer, so
// undecodable objects stored outside the target namespace cannot break it.
func NewNamespacedCachedSecretGetter(client corev1client.SecretsGetter, informerFactory informers.SharedInformerFactory, namespace string) corev1client.SecretsGetter {
	return &namespacedSecretGetter{
		client:          client,
		informerFactory: informerFactory,
		namespace:       namespace,
	}
}

func (g *namespacedSecretGetter) Secrets(namespace string) corev1client.SecretInterface {
	if namespace != g.namespace {
		return g.client.Secrets(namespace)
	}
	return combinedSecretInterface{
		SecretInterface: g.client.Secrets(namespace),
		lister:          g.informerFactory.Core().V1().Secrets().Lister().Secrets(namespace),
		namespace:       namespace,
	}
}

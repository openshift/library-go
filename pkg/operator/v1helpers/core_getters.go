package v1helpers

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
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

func (g combinedConfigMapInterface) Get(name string, options metav1.GetOptions) (*corev1.ConfigMap, error) {
	if err := validateResourceVersion(options.ResourceVersion); err != nil {
		return nil, err
	}
	ret, err := g.lister.Get(name)
	if err != nil {
		return nil, err
	}
	return ret.DeepCopy(), nil
}
func (g combinedConfigMapInterface) List(opts metav1.ListOptions) (*corev1.ConfigMapList, error) {
	selector, err := listOptionsToSelector(opts)
	if err != nil {
		return nil, err
	}
	list, err := g.lister.List(selector)
	if err != nil {
		return nil, err
	}

	ret := &corev1.ConfigMapList{Items: make([]corev1.ConfigMap, len(list))}
	for i := range list {
		ret.Items[i] = *(list[i].DeepCopy())
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

func (g combinedSecretInterface) Get(name string, options metav1.GetOptions) (*corev1.Secret, error) {
	if err := validateResourceVersion(options.ResourceVersion); err != nil {
		return nil, err
	}
	ret, err := g.lister.Get(name)
	if err != nil {
		return nil, err
	}
	return ret.DeepCopy(), nil
}

func (g combinedSecretInterface) List(opts metav1.ListOptions) (*corev1.SecretList, error) {
	selector, err := listOptionsToSelector(opts)
	if err != nil {
		return nil, err
	}
	list, err := g.lister.List(selector)
	if err != nil {
		return nil, err
	}

	ret := &corev1.SecretList{Items: make([]corev1.Secret, len(list))}
	for i := range list {
		ret.Items[i] = *(list[i].DeepCopy())
	}
	return ret, nil
}

func listOptionsToSelector(options metav1.ListOptions) (labels.Selector, error) {
	if err := validateResourceVersion(options.ResourceVersion); err != nil {
		return nil, err
	}

	// make sure no unsupported fields are set (new fields to ListOptions are not silently ignored)
	optionsCopy := *(options.DeepCopy())
	optionsCopy.LabelSelector = ""           // setting label selector is supported and checked below
	optionsCopy.TypeMeta = metav1.TypeMeta{} // ignore type meta
	optionsCopy.TimeoutSeconds = nil         // ignore timeout
	optionsCopy.Limit = 0                    // ignore limit
	optionsCopy.ResourceVersion = ""         // we have already validated this above
	if optionsEmpty := (metav1.ListOptions{}); optionsCopy != optionsEmpty {
		return nil, fmt.Errorf("list options against cache has specified unsupported fields: %v", options)
	}

	return labels.Parse(options.LabelSelector)
}

func validateResourceVersion(resourceVersion string) error {
	switch resourceVersion {
	case "", "0":
		return nil
	default:
		return fmt.Errorf("options against cache with specified resource version %q are unsupported", resourceVersion)
	}
}

package secret

import (
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type listObjectFunc func(string, metav1.ListOptions) (runtime.Object, error)
type watchObjectFunc func(string, metav1.ListOptions) (watch.Interface, error)

type SecretEventHandlerRegistration interface {
	cache.ResourceEventHandlerRegistration

	GetKey() objectKey
}

type SecretMonitor interface {
	AddEventHandler(namespace, name string, handler cache.ResourceEventHandler) (SecretEventHandlerRegistration, error)

	RemoveEventHandler(SecretEventHandlerRegistration) error

	GetSecret(SecretEventHandlerRegistration) (*v1.Secret, error)
}

type sm struct {
	listObject  listObjectFunc
	watchObject watchObjectFunc

	monitors map[objectKey]*Object
}

func (s *sm) AddEventHandler(namespace, name string, handler cache.ResourceEventHandler) (SecretEventHandlerRegistration, error) {

	// name is a combination or routename_secretname
	key := objectKey{namespace: namespace, name: name}
	m, exists := s.monitors[key]

    // TODO refactor this later 
	secretName := strings.Split(name, "_")[1]
	if !exists {
		fieldSelector := fields.Set{"metadata.name": secretName}.AsSelector().String()
		listFunc := func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector

			klog.Info(fieldSelector)
			return s.listObject(namespace, options)
		}
		watchFunc := func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector

			klog.Info(fieldSelector)
			return s.watchObject(namespace, options)
		}

		store, informer := cache.NewInformer(
			&cache.ListWatch{ListFunc: listFunc, WatchFunc: watchFunc},
			&v1.Secret{},
			0, handler)

		m = NewObject(key, informer, store)

		go m.StartInformer()

		s.monitors[key] = m

		klog.Info("secret monitor key added", " item key ", key)
	}

	return m, nil
}

func (s *sm) RemoveEventHandler(handle SecretEventHandlerRegistration) error {
	key := handle.GetKey()
	item, ok := s.monitors[key]
	if ok {
		if item.Stop() {
			klog.Info("secret monitor stopped ", " item key ", key)
			delete(s.monitors, key)
		}
	} else {
		klog.Error("secret monitor handle not found")
		return fmt.Errorf("secret monitor handle not found: %s", key)
	}

	return nil
}

func (s *sm) GetSecret(handle SecretEventHandlerRegistration) (*v1.Secret, error) {

	key := handle.GetKey()

	if item, ok := s.monitors[key]; ok {

		secretName := strings.Split(key.name, "_")[1]
		sc, ok, err := item.store.GetByKey(item.Key(key.namespace, secretName))
		if err != nil {
			return nil, err
		}

		if ok {
			return sc.(*v1.Secret), nil
		}
	}

	return nil, fmt.Errorf("not found: %s", handle)

}

package linearizer

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
)

func NewFakeSecretLister(tracker clienttesting.ObjectTracker) *fakeSecretLister {
	return &fakeSecretLister{tracker: tracker}
}

type fakeSecretLister struct {
	tracker clienttesting.ObjectTracker
}

func (l *fakeSecretLister) List(selector labels.Selector) (ret []*corev1.Secret, err error) {
	return l.Secrets("").List(selector)
}

func (l *fakeSecretLister) Secrets(namespace string) corev1listers.SecretNamespaceLister {
	return &FakeNamespacedLister{
		ns:      namespace,
		gvr:     schema.GroupVersionResource{Version: "v1", Resource: "secrets"},
		gvk:     schema.GroupVersionKind{Version: "v1", Kind: "Secret"},
		tracker: l.tracker,
	}
}

type FakeNamespacedLister struct {
	tracker clienttesting.ObjectTracker
	gvr     schema.GroupVersionResource
	gvk     schema.GroupVersionKind
	ns      string
}

func (l *FakeNamespacedLister) List(selector labels.Selector) (ret []*corev1.Secret, err error) {
	obj, err := l.tracker.List(l.gvr, l.gvk, l.ns)

	var secrets []*corev1.Secret
	if l, ok := obj.(*corev1.SecretList); ok {
		for i := range l.Items {
			secrets = append(secrets, &l.Items[i])
		}
	}
	return secrets, err
}

func (l *FakeNamespacedLister) Get(name string) (*corev1.Secret, error) {
	obj, err := l.tracker.Get(l.gvr, l.ns, name)
	if secret, ok := obj.(*corev1.Secret); ok {
		return secret, err
	}
	return nil, err
}

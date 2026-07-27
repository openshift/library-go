package controllers

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// interceptingSecretsGetter wraps a real SecretsGetter.
// Reads fall through to the real cluster (augmented with intercepted writes so controllers
// see their own un-persisted objects). Writes are passed to shouldIntercept; if it returns
// true the secret is captured in memory, otherwise it is dropped without reaching the real API.
type interceptingSecretsGetter struct {
	real            corev1client.SecretsGetter
	shouldIntercept func(namespace, name string) bool
	written         map[string]*corev1.Secret // "namespace/name" → intercepted secret
}

func newInterceptingSecretsGetter(real corev1client.SecretsGetter, shouldIntercept func(namespace, name string) bool) *interceptingSecretsGetter {
	return &interceptingSecretsGetter{
		real:            real,
		shouldIntercept: shouldIntercept,
		written:         map[string]*corev1.Secret{},
	}
}

func (g *interceptingSecretsGetter) Secrets(ns string) corev1client.SecretInterface {
	return &interceptingSecretClient{
		SecretInterface: g.real.Secrets(ns), // real client; unimplemented methods fall through
		ns:              ns,
		written:         g.written,
		shouldIntercept: g.shouldIntercept,
	}
}

// findWritten returns the first intercepted secret matching pred, or an error if none matches.
func (g *interceptingSecretsGetter) findWritten(pred func(*corev1.Secret) bool) (*corev1.Secret, error) {
	for _, s := range g.written {
		if pred(s) {
			return s.DeepCopy(), nil
		}
	}
	return nil, fmt.Errorf("no intercepted secret matched")
}

// interceptingSecretClient implements corev1client.SecretInterface.
// Reads and unimplemented methods fall through to the embedded real client.
// Writes matching shouldIntercept are captured in written; others are dropped.
type interceptingSecretClient struct {
	corev1client.SecretInterface
	ns              string
	written         map[string]*corev1.Secret
	shouldIntercept func(namespace, name string) bool
}

func (c *interceptingSecretClient) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	if s, ok := c.written[c.ns+"/"+name]; ok {
		return s.DeepCopy(), nil
	}
	return c.SecretInterface.Get(ctx, name, opts)
}

func (c *interceptingSecretClient) List(ctx context.Context, opts metav1.ListOptions) (*corev1.SecretList, error) {
	list, err := c.SecretInterface.List(ctx, opts)
	if err != nil {
		return nil, err
	}
	selector, err := labels.Parse(opts.LabelSelector)
	if err != nil {
		return nil, err
	}
	// Append any intercepted secrets not yet in the cluster so the next controller
	// (StateController) sees the key secret created by KeyController.
	for key, s := range c.written {
		if !strings.HasPrefix(key, c.ns+"/") {
			continue
		}
		if selector.Matches(labels.Set(s.Labels)) {
			list.Items = append(list.Items, *s.DeepCopy())
		}
	}
	return list, nil
}

func (c *interceptingSecretClient) Create(_ context.Context, secret *corev1.Secret, _ metav1.CreateOptions) (*corev1.Secret, error) {
	return c.intercept(secret), nil
}

func (c *interceptingSecretClient) Update(_ context.Context, secret *corev1.Secret, _ metav1.UpdateOptions) (*corev1.Secret, error) {
	return c.intercept(secret), nil
}

func (c *interceptingSecretClient) intercept(secret *corev1.Secret) *corev1.Secret {
	cp := secret.DeepCopy()
	if cp.Namespace == "" {
		cp.Namespace = c.ns
	}
	if c.shouldIntercept(cp.Namespace, cp.Name) {
		c.written[cp.Namespace+"/"+cp.Name] = cp
	}
	return cp.DeepCopy()
}

package controllers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	applyconfigurationscorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// dryRunSecretsGetter wraps a live SecretsGetter for preflight dry-runs:
// reads hit the live API (plus an in-memory overlay of prior writes);
// Create/Update are recorded in memory and never reach the API.
type dryRunSecretsGetter struct {
	real    corev1client.SecretsGetter
	written map[string]map[string]*corev1.Secret // namespace → name → recorded secret
}

var _ corev1client.SecretsGetter = (*dryRunSecretsGetter)(nil)

func newDryRunSecretsGetter(real corev1client.SecretsGetter) (*dryRunSecretsGetter, error) {
	if real == nil {
		return nil, fmt.Errorf("dry-run secrets getter requires a non-nil SecretsGetter")
	}
	return &dryRunSecretsGetter{
		real:    real,
		written: map[string]map[string]*corev1.Secret{},
	}, nil
}

func (g *dryRunSecretsGetter) Secrets(ns string) corev1client.SecretInterface {
	return &dryRunSecretClient{
		parent: g,
		ns:     ns,
	}
}

// Recorded returns a deep copy of the secret recorded by Create/Update during this
// dry-run, if any. Live secrets that were only read are not returned. The bool
// return value indicates whether the secret was found in the overlay.
func (g *dryRunSecretsGetter) Recorded(namespace, name string) (*corev1.Secret, bool) {
	s, ok := g.written[namespace][name]
	if !ok {
		return nil, false
	}
	return s.DeepCopy(), true
}

// dryRunSecretClient implements corev1client.SecretInterface.
// Get/List read the live API and overlay prior writes; Create/Update record writes in memory.
// Other mutating methods and Watch return an error and never hit the live API.
type dryRunSecretClient struct {
	parent *dryRunSecretsGetter
	ns     string
}

var _ corev1client.SecretInterface = (*dryRunSecretClient)(nil)

func (c *dryRunSecretClient) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	if s, ok := c.parent.written[c.ns][name]; ok {
		return s.DeepCopy(), nil
	}
	return c.parent.real.Secrets(c.ns).Get(ctx, name, opts)
}

func (c *dryRunSecretClient) List(ctx context.Context, opts metav1.ListOptions) (*corev1.SecretList, error) {
	selector, err := labels.Parse(opts.LabelSelector)
	if err != nil {
		return nil, err
	}
	list, err := c.parent.real.Secrets(c.ns).List(ctx, opts)
	if err != nil {
		return nil, err
	}

	written := c.parent.written[c.ns]
	filtered := make([]corev1.Secret, 0, len(list.Items))
	seen := make(map[string]struct{}, len(list.Items))

	// Replace or drop live entries that have an overlay write.
	for i := range list.Items {
		name := list.Items[i].Name
		seen[name] = struct{}{}
		if s, ok := written[name]; ok {
			if !selector.Matches(labels.Set(s.Labels)) {
				continue
			}
			filtered = append(filtered, *s.DeepCopy())
			continue
		}
		filtered = append(filtered, list.Items[i])
	}

	// Insert overlay-only secrets that match the selector.
	for _, s := range written {
		if _, ok := seen[s.Name]; ok {
			continue
		}
		if !selector.Matches(labels.Set(s.Labels)) {
			continue
		}
		filtered = append(filtered, *s.DeepCopy())
	}
	list.Items = filtered
	return list, nil
}

func (c *dryRunSecretClient) Create(_ context.Context, secret *corev1.Secret, _ metav1.CreateOptions) (*corev1.Secret, error) {
	return c.record(secret), nil
}

func (c *dryRunSecretClient) Update(_ context.Context, secret *corev1.Secret, _ metav1.UpdateOptions) (*corev1.Secret, error) {
	return c.record(secret), nil
}

func (c *dryRunSecretClient) Delete(_ context.Context, _ string, _ metav1.DeleteOptions) error {
	return fmt.Errorf("dry-run secrets client does not support Delete")
}

func (c *dryRunSecretClient) DeleteCollection(_ context.Context, _ metav1.DeleteOptions, _ metav1.ListOptions) error {
	return fmt.Errorf("dry-run secrets client does not support DeleteCollection")
}

func (c *dryRunSecretClient) Watch(_ context.Context, _ metav1.ListOptions) (watch.Interface, error) {
	return nil, fmt.Errorf("dry-run secrets client does not support Watch")
}

func (c *dryRunSecretClient) Patch(_ context.Context, _ string, _ types.PatchType, _ []byte, _ metav1.PatchOptions, _ ...string) (*corev1.Secret, error) {
	return nil, fmt.Errorf("dry-run secrets client does not support Patch")
}

func (c *dryRunSecretClient) Apply(_ context.Context, _ *applyconfigurationscorev1.SecretApplyConfiguration, _ metav1.ApplyOptions) (*corev1.Secret, error) {
	return nil, fmt.Errorf("dry-run secrets client does not support Apply")
}

func (c *dryRunSecretClient) record(secret *corev1.Secret) *corev1.Secret {
	cp := secret.DeepCopy()
	// Scope to client namespace before storing, matching real client-go behavior.
	cp.Namespace = c.ns
	byName, ok := c.parent.written[c.ns]
	if !ok {
		byName = map[string]*corev1.Secret{}
		c.parent.written[c.ns] = byName
	}
	byName[cp.Name] = cp
	// Return a copy so caller mutations don't affect the stored version.
	return cp.DeepCopy()
}

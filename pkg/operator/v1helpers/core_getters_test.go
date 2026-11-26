package v1helpers

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

const (
	targetNamespace = "openshift-operator-namespace"
	foreignNs       = "other-namespace"
)

func newSecret(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data:       map[string][]byte{name: []byte("value")},
	}
}

func newConfigMap(namespace, name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data:       map[string]string{name: "value"},
	}
}

// startSecretAndConfigMapInformers starts the given factory and waits until the
// secret/configmap informers have synced their caches. The informers must be
// instantiated before Start, since Start only runs informers already created.
func startSecretAndConfigMapInformers(t *testing.T, informerFactory informers.SharedInformerFactory) {
	t.Helper()

	secretInformer := informerFactory.Core().V1().Secrets().Informer()
	configMapInformer := informerFactory.Core().V1().ConfigMaps().Informer()

	stopCh := make(chan struct{})
	t.Cleanup(func() { close(stopCh) })

	informerFactory.Start(stopCh)

	synced := func() bool {
		return secretInformer.HasSynced() && configMapInformer.HasSynced()
	}
	if synced() {
		return
	}
	if err := wait.PollUntilContextTimeout(context.Background(), 10*time.Millisecond, 5*time.Second, true,
		func(ctx context.Context) (bool, error) {
			return synced(), nil
		}); err != nil {
		t.Fatal("informer cache never synced")
	}
}

func TestNewNamespacedCachedSecretGetter(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		cacheObject []runtime.Object
		liveObjects []runtime.Object
		getName     string
		expectFound bool
		expectLive  bool
	}{
		{
			name:        "read in target namespace is served from the informer cache",
			namespace:   targetNamespace,
			cacheObject: []runtime.Object{newSecret(targetNamespace, "etcd-client")},
			getName:     "etcd-client",
			expectFound: true,
			expectLive:  false,
		},
		{
			name:        "target namespace cache miss falls back to the live client",
			namespace:   targetNamespace,
			liveObjects: []runtime.Object{newSecret(targetNamespace, "created-after-sync")},
			getName:     "created-after-sync",
			expectFound: true,
			expectLive:  true,
		},
		{
			name:        "target namespace cache and live miss returns NotFound",
			namespace:   targetNamespace,
			getName:     "missing",
			expectFound: false,
			expectLive:  true,
		},
		{
			name:        "read in a foreign namespace falls back to the live client",
			namespace:   foreignNs,
			liveObjects: []runtime.Object{newSecret(foreignNs, "unrelated")},
			getName:     "unrelated",
			expectFound: true,
			expectLive:  true,
		},
		{
			name:        "read in an unknown namespace does not panic and falls back to the live client",
			namespace:   "not-watched-anywhere",
			getName:     "anything",
			expectFound: false,
			expectLive:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			informerClient := fake.NewSimpleClientset(test.cacheObject...)
			liveClient := fake.NewSimpleClientset(test.liveObjects...)
			informerFactory := informers.NewSharedInformerFactoryWithOptions(informerClient, 0, informers.WithNamespace(targetNamespace))
			startSecretAndConfigMapInformers(t, informerFactory)

			liveCalls := 0
			liveClient.Fake.PrependReactor("get", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
				liveCalls++
				return false, nil, nil
			})

			getter := NewNamespacedCachedSecretGetter(liveClient.CoreV1(), informerFactory, targetNamespace)
			secret, err := getter.Secrets(test.namespace).Get(context.Background(), test.getName, metav1.GetOptions{})

			if test.expectFound && err != nil {
				t.Fatalf("expected secret to be found, got error: %v", err)
			}
			if !test.expectFound && !apierrors.IsNotFound(err) {
				t.Fatalf("expected NotFound error, got: %v", err)
			}
			if test.expectFound && secret.Name != test.getName {
				t.Fatalf("expected secret %q, got %q", test.getName, secret.Name)
			}
			if test.expectLive && liveCalls == 0 {
				t.Fatal("expected the read to hit the live client")
			}
			if !test.expectLive && liveCalls != 0 {
				t.Fatalf("expected the read to be served from the cache, but the live client was called %d times", liveCalls)
			}
		})
	}
}

func TestNewNamespacedCachedConfigMapGetter(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		cacheObject []runtime.Object
		liveObjects []runtime.Object
		getName     string
		expectFound bool
		expectLive  bool
	}{
		{
			name:        "read in target namespace is served from the informer cache",
			namespace:   targetNamespace,
			cacheObject: []runtime.Object{newConfigMap(targetNamespace, "config")},
			getName:     "config",
			expectFound: true,
			expectLive:  false,
		},
		{
			name:        "target namespace cache miss falls back to the live client",
			namespace:   targetNamespace,
			liveObjects: []runtime.Object{newConfigMap(targetNamespace, "created-after-sync")},
			getName:     "created-after-sync",
			expectFound: true,
			expectLive:  true,
		},
		{
			name:        "target namespace cache and live miss returns NotFound",
			namespace:   targetNamespace,
			getName:     "missing",
			expectFound: false,
			expectLive:  true,
		},
		{
			name:        "read in a foreign namespace falls back to the live client",
			namespace:   foreignNs,
			liveObjects: []runtime.Object{newConfigMap(foreignNs, "unrelated-config")},
			getName:     "unrelated-config",
			expectFound: true,
			expectLive:  true,
		},
		{
			name:        "read in an unknown namespace does not panic and falls back to the live client",
			namespace:   "not-watched-anywhere",
			getName:     "anything",
			expectFound: false,
			expectLive:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			informerClient := fake.NewSimpleClientset(test.cacheObject...)
			liveClient := fake.NewSimpleClientset(test.liveObjects...)
			informerFactory := informers.NewSharedInformerFactoryWithOptions(informerClient, 0, informers.WithNamespace(targetNamespace))
			startSecretAndConfigMapInformers(t, informerFactory)

			liveCalls := 0
			liveClient.Fake.PrependReactor("get", "configmaps", func(action clienttesting.Action) (bool, runtime.Object, error) {
				liveCalls++
				return false, nil, nil
			})

			getter := NewNamespacedCachedConfigMapGetter(liveClient.CoreV1(), informerFactory, targetNamespace)
			configMap, err := getter.ConfigMaps(test.namespace).Get(context.Background(), test.getName, metav1.GetOptions{})

			if test.expectFound && err != nil {
				t.Fatalf("expected configmap to be found, got error: %v", err)
			}
			if !test.expectFound && !apierrors.IsNotFound(err) {
				t.Fatalf("expected NotFound error, got: %v", err)
			}
			if test.expectFound && configMap.Name != test.getName {
				t.Fatalf("expected configmap %q, got %q", test.getName, configMap.Name)
			}
			if test.expectLive && liveCalls == 0 {
				t.Fatal("expected the read to hit the live client")
			}
			if !test.expectLive && liveCalls != 0 {
				t.Fatalf("expected the read to be served from the cache, but the live client was called %d times", liveCalls)
			}
		})
	}
}

func TestNamespacedCachedSecretGetterWritesGoThroughLiveClient(t *testing.T) {
	informerClient := fake.NewSimpleClientset()
	liveClient := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactoryWithOptions(informerClient, 0, informers.WithNamespace(targetNamespace))
	startSecretAndConfigMapInformers(t, informerFactory)

	getter := NewNamespacedCachedSecretGetter(liveClient.CoreV1(), informerFactory, targetNamespace)

	created, err := getter.Secrets(targetNamespace).Create(context.Background(), newSecret(targetNamespace, "created-secret"), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("expected create to succeed, got error: %v", err)
	}
	if created.Name != "created-secret" {
		t.Fatalf("expected created secret name created-secret, got %q", created.Name)
	}

	// the created secret must be visible to the live client immediately, without cache sync
	stored, err := liveClient.CoreV1().Secrets(targetNamespace).Get(context.Background(), "created-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected created secret to be stored via the live client, got error: %v", err)
	}
	if stored == nil || stored.Name != "created-secret" {
		t.Fatal("expected created secret to be stored via the live client")
	}

	if _, err := getter.Secrets(foreignNs).Create(context.Background(), newSecret(foreignNs, "foreign-secret"), metav1.CreateOptions{}); err != nil {
		t.Fatalf("expected create in foreign namespace to succeed via the live client, got error: %v", err)
	}
}

func TestNamespacedCachedGettersFallBackOnCacheMiss(t *testing.T) {
	// regression path for OCPBUGS-59625: an object that exists in etcd but is not
	// visible in the informer cache must still be found by a live read. A
	// foreign-namespace read must not depend on the target cache at all.
	// The getter's live path uses a separate client that the informer never watches,
	// so the objects seeded there are invisible to the cache by construction rather
	// than by scheduling luck.
	informerClient := fake.NewSimpleClientset(newSecret(targetNamespace, "cached-in"))
	informerFactory := informers.NewSharedInformerFactoryWithOptions(informerClient, 0, informers.WithNamespace(targetNamespace))
	startSecretAndConfigMapInformers(t, informerFactory)

	liveClient := fake.NewSimpleClientset(
		newSecret(targetNamespace, "created-after-sync"),
		newSecret(foreignNs, "foreign-in"),
	)
	getter := NewNamespacedCachedSecretGetter(liveClient.CoreV1(), informerFactory, targetNamespace)

	// positive control: the object synced before the informer started is served
	// from the cache
	cached, err := getter.Secrets(targetNamespace).Get(context.Background(), "cached-in", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected the synced secret to be served from the cache, got error: %v", err)
	}
	if cached.Name != "cached-in" {
		t.Fatalf("expected secret cached-in, got %q", cached.Name)
	}

	// an object that exists only in the live client is found after the cache miss
	var liveCalls int
	liveClient.Fake.PrependReactor("get", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		liveCalls++
		return false, nil, nil
	})
	live, err := getter.Secrets(targetNamespace).Get(context.Background(), "created-after-sync", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected the target-namespace cache miss to fall back to the live client, got error: %v", err)
	}
	if live.Name != "created-after-sync" {
		t.Fatalf("expected secret created-after-sync, got %q", live.Name)
	}
	if liveCalls != 1 {
		t.Fatalf("expected one live read after a cache miss, got %d", liveCalls)
	}

	// the foreign namespace read is served by the live client and is unaffected by
	// the target-namespace cache state
	foreign, err := getter.Secrets(foreignNs).Get(context.Background(), "foreign-in", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected foreign-namespace read to succeed via the live client, got error: %v", err)
	}
	if foreign.Name != "foreign-in" {
		t.Fatalf("expected secret foreign-in, got %q", foreign.Name)
	}
	if liveCalls != 2 {
		t.Fatalf("expected the foreign-namespace read to use the live client, got %d total live reads", liveCalls)
	}
}

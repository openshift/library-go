package secret

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

func newMonitor(ctx context.Context, fakeKubeClient *fake.Clientset, key ObjectKey) *singleItemMonitor {
	sharedInformer := fakeSecretInformer(ctx, fakeKubeClient, key.Namespace, key.Name)
	return newSingleItemMonitor(key, sharedInformer)
}

// fakeSecretInformer will list/watch only one secret inside a namespace
func fakeSecretInformer(ctx context.Context, fakeKubeClient *fake.Clientset, namespace, name string) cache.SharedInformer {
	fieldSelector := fields.OneTermEqualSelector("metadata.name", name).String()
	klog.Info(fieldSelector)
	return cache.NewSharedInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector = fieldSelector
				return fakeKubeClient.CoreV1().Secrets(namespace).List(ctx, options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector = fieldSelector
				return fakeKubeClient.CoreV1().Secrets(namespace).Watch(ctx, options)
			},
		},
		&corev1.Secret{},
		0,
	)
}

func fakeSecret(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		Type: corev1.SecretTypeOpaque,
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"test": {1, 2, 3, 4},
		},
	}
}

func TestStartInformer(t *testing.T) {
	scenarios := []struct {
		name      string
		isClosed  bool
		expectErr bool
	}{
		{
			name:      "pass closed channel into informer",
			isClosed:  true,
			expectErr: true,
		},
		{
			name:      "pass unclosed channel into informer",
			isClosed:  false,
			expectErr: false,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset()
			monitor := newMonitor(context.TODO(), fakeKubeClient, ObjectKey{})
			if s.isClosed {
				close(monitor.stopCh)
			}
			go monitor.StartInformer(context.TODO())

			select {
			// this case will execute if stopCh is closed
			case <-monitor.stopCh:
				if !s.expectErr {
					t.Error("informer is not running")
				}
			default:
				// wait for the informer to start
				if !cache.WaitForCacheSync(context.TODO().Done(), monitor.HasSynced) {
					t.Fatal("cache not synced yet")
				}
				t.Log("informer is running")
			}
		})
	}
}

func TestStopInformer(t *testing.T) {
	scenarios := []struct {
		name             string
		withStart        bool
		alreadyStopped   bool
		expectStopped    bool
		expectChanClosed bool
	}{
		{
			name:             "stop without starting informer",
			withStart:        false,
			expectStopped:    false,
			expectChanClosed: false,
		},
		{
			name:             "stopping already stopped informer",
			withStart:        true,
			alreadyStopped:   true,
			expectStopped:    false,
			expectChanClosed: true,
		},
		{
			name:             "correctly stopped informer",
			withStart:        true,
			alreadyStopped:   false,
			expectStopped:    true,
			expectChanClosed: true,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset()
			monitor := newMonitor(context.TODO(), fakeKubeClient, ObjectKey{})

			if s.withStart {
				go monitor.StartInformer(context.TODO())
				// wait for the informer to start
				if !cache.WaitForCacheSync(context.TODO().Done(), monitor.HasSynced) {
					t.Fatal("cache not synced yet")
				}
			}
			if s.alreadyStopped {
				monitor.StopInformer()
			}

			if got := monitor.StopInformer(); got != s.expectStopped {
				t.Errorf("expected informer stopped to be %t but got %t", s.expectStopped, got)
			}

			var chanClosed bool
			select {
			// this case will execute if stopCh is closed
			case <-monitor.stopCh:
				chanClosed = true
			default:
				chanClosed = false
			}

			if s.expectChanClosed != chanClosed {
				t.Errorf("expected stop channel closed to be %t but got %t", s.expectChanClosed, chanClosed)
			}
		})
	}
}

func TestStopWithContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	fakeKubeClient := fake.NewSimpleClientset()
	monitor := newMonitor(ctx, fakeKubeClient, ObjectKey{})
	stopCh := make(chan bool)

	go func() {
		monitor.StartInformer(ctx)
		close(stopCh)
	}()
	// wait for the informer to start
	if !cache.WaitForCacheSync(ctx.Done(), monitor.HasSynced) {
		t.Fatal("cache not synced yet")
	}

	// cancel the context to stop the informer
	cancel()
	<-stopCh

	// again stopping should deny
	if monitor.StopInformer() != false {
		t.Fatal("context cancellation did not work properly")
	}
}

func TestAddEventHandler(t *testing.T) {
	scenarios := []struct {
		name      string
		key       ObjectKey
		isStop    bool
		expectErr bool
	}{
		{
			name:      "add handler to stopped informer",
			isStop:    true,
			expectErr: true,
		},
		{
			name:      "correctly add handler to informer",
			key:       NewObjectKey("namespace", "name"),
			isStop:    false,
			expectErr: false,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset()
			monitor := newMonitor(context.TODO(), fakeKubeClient, s.key)

			go monitor.StartInformer(context.TODO())
			// wait for the informer to start
			if !cache.WaitForCacheSync(context.TODO().Done(), monitor.HasSynced) {
				t.Fatal("cache not synced yet")
			}

			if s.isStop {
				monitor.StopInformer()
			}

			handlerRegistration, gotErr := monitor.AddEventHandler(cache.ResourceEventHandlerFuncs{})
			if gotErr != nil && !s.expectErr {
				t.Fatalf("unexpected error %v", gotErr)
			}
			if gotErr == nil && s.expectErr {
				t.Fatalf("expecting an error, got nil")
			}

			if gotErr == nil {
				if !reflect.DeepEqual(handlerRegistration.GetKey(), s.key) {
					t.Fatalf("expected key %v got key %v", s.key, handlerRegistration.GetKey())
				}
			}
		})
	}

}

func TestRemoveEventHandler(t *testing.T) {
	scenarios := []struct {
		name         string
		isNilHandler bool
		isStop       bool
		expectErr    bool
	}{
		{
			name:      "remove handler from stopped informer",
			isStop:    true,
			expectErr: true,
		},
		{
			name:         "nil handler is provided",
			isNilHandler: true,
			expectErr:    true,
		},
		{
			name:         "correct handler is provided",
			isNilHandler: false,
			expectErr:    false,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset()
			monitor := newMonitor(context.TODO(), fakeKubeClient, ObjectKey{})
			go monitor.StartInformer(context.TODO())
			// wait for the informer to start
			if !cache.WaitForCacheSync(context.TODO().Done(), monitor.HasSynced) {
				t.Fatal("cache not synced yet")
			}

			handlerRegistration, _ := monitor.AddEventHandler(cache.ResourceEventHandlerFuncs{})
			if s.isNilHandler {
				handlerRegistration = nil
			}

			if s.isStop {
				monitor.StopInformer()
			}

			gotErr := monitor.RemoveEventHandler(handlerRegistration)
			if gotErr != nil && !s.expectErr {
				t.Errorf("unexpected error %v", gotErr)
			}
			if gotErr == nil && s.expectErr {
				t.Errorf("expecting an error, got nil")
			}
		})
	}
}

func TestGetItem(t *testing.T) {
	scenarios := []struct {
		name        string
		secret      *corev1.Secret
		objectKey   ObjectKey
		expectExist bool
	}{
		{
			name:        "looking for secret which is not present",
			secret:      fakeSecret("sandbox", "wrong-name"),
			objectKey:   NewObjectKey("sandbox", "correct-name"),
			expectExist: false,
		},
		{
			name:        "looking for correct secret",
			secret:      fakeSecret("sandbox", "correct-name"),
			objectKey:   NewObjectKey("sandbox", "correct-name"),
			expectExist: true,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(s.secret)

			monitor := newMonitor(context.TODO(), fakeKubeClient, s.objectKey)

			go monitor.StartInformer(context.TODO())
			// wait for the informer to start
			if !cache.WaitForCacheSync(context.TODO().Done(), monitor.HasSynced) {
				t.Fatal("cache not synced yet")
			}

			uncast, gotExist, err := monitor.GetItem()

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotExist != s.expectExist {
				t.Fatalf("item is expected to exist %t but got %t", s.expectExist, gotExist)
			}

			if s.expectExist {
				gotSecret, ok := uncast.(*corev1.Secret)
				if !ok {
					t.Fatalf("unable to cast the item: %v", uncast)
				}
				if !reflect.DeepEqual(s.secret, gotSecret) {
					t.Fatalf("expected to get item %v but got %v", s.secret, gotSecret)
				}
			}
		})
	}
}

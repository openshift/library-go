package secret

import (
	"context"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

func fakeMonitor(ctx context.Context, fakeKubeClient *fake.Clientset, key ObjectKey) *singleItemMonitor {
	sharedInformer := fakeSecretInformer(ctx, fakeKubeClient, key.Namespace, key.Name)
	return newSingleItemMonitor(key, sharedInformer)
}

// fakeSecretInformer will list/watch only one secret inside a namespace
func fakeSecretInformer(ctx context.Context, fakeKubeClient *fake.Clientset, namespace, name string) cache.SharedInformer {
	fieldSelector := fields.OneTermEqualSelector("metadata.name", name).String()
	klog.Info(fieldSelector)
	return cache.NewSharedInformer(&cache.ListWatch{
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
			monitor := fakeMonitor(context.TODO(), fakeKubeClient, ObjectKey{})
			if s.isClosed {
				close(monitor.stopCh)
			}
			go monitor.StartInformer(context.TODO())
			time.Sleep(10 * time.Millisecond)

			select {
			// this case will execute if stopCh is closed
			case <-monitor.stopCh:
				if !s.expectErr {
					t.Error("informer is not running")
				}
			default:
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
			monitor := fakeMonitor(context.TODO(), fakeKubeClient, ObjectKey{})

			if s.withStart {
				go monitor.StartInformer(context.TODO())
				time.Sleep(10 * time.Millisecond)
			}
			if s.alreadyStopped {
				monitor.StopInformer()
			}

			if monitor.StopInformer() != s.expectStopped {
				t.Error("unexpected result")
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
				t.Error("unexpected result on chan closure")
			}
		})
	}
}

func TestStopWithContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	fakeKubeClient := fake.NewSimpleClientset()
	monitor := fakeMonitor(ctx, fakeKubeClient, ObjectKey{})

	go monitor.StartInformer(ctx)
	time.Sleep(10 * time.Millisecond)

	// cancel the context to stop the informer
	cancel()
	time.Sleep(10 * time.Millisecond)

	// again stopping should deny
	if monitor.StopInformer() != false {
		t.Error("context cancellation did not work properly")
	}
}

func TestAddEventHandler(t *testing.T) {
	scenarios := []struct {
		name      string
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
			isStop:    false,
			expectErr: false,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset()
			key := NewObjectKey("namespace", "name")
			monitor := fakeMonitor(context.TODO(), fakeKubeClient, key)
			go monitor.StartInformer(context.TODO())
			time.Sleep(10 * time.Millisecond)

			if s.isStop {
				monitor.StopInformer()
			}

			handlerRegistration, gotErr := monitor.AddEventHandler(cache.ResourceEventHandlerFuncs{})
			if gotErr != nil && !s.expectErr {
				t.Errorf("unexpected error %v", gotErr)
			}
			if gotErr == nil && s.expectErr {
				t.Errorf("expecting an error, got nil")
			}

			if !s.isStop { // for handling nil pointer dereference
				if !reflect.DeepEqual(handlerRegistration.GetKey(), key) {
					t.Errorf("expected key %v got key %v", key, handlerRegistration.GetKey())
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
			monitor := fakeMonitor(context.TODO(), fakeKubeClient, ObjectKey{})
			go monitor.StartInformer(context.TODO())
			time.Sleep(10 * time.Millisecond)

			handlerRegistration, _ := monitor.AddEventHandler(cache.ResourceEventHandlerFuncs{})
			if s.isNilHandler {
				handlerRegistration = nil
			}

			if s.isStop {
				monitor.StopInformer()
			}

			// for handling nil pointer dereference
			defer func() {
				if err := recover(); err != nil && !s.expectErr {
					t.Errorf("unexpected error %v", err)
				}
			}()

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
	var (
		namespace = "sandbox"
		name      = "secretName"
		secret    = fakeSecret(namespace, name)
	)
	scenarios := []struct {
		name            string
		withSecret      bool
		expectExist     bool
		expectUncastErr bool
	}{
		{
			name:            "looking for secret which is not present",
			withSecret:      false,
			expectExist:     false,
			expectUncastErr: true,
		},
		{
			name:            "looking for correct secret",
			withSecret:      true,
			expectExist:     true,
			expectUncastErr: false,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			var fakeKubeClient *fake.Clientset
			if s.withSecret {
				fakeKubeClient = fake.NewSimpleClientset(secret)
			} else {
				fakeKubeClient = fake.NewSimpleClientset()
			}

			monitor := fakeMonitor(context.TODO(), fakeKubeClient, NewObjectKey(namespace, name))

			go monitor.StartInformer(context.TODO())
			if !cache.WaitForCacheSync(context.TODO().Done(), monitor.HasSynced) {
				t.Fatal("cache not synced yet")
			}

			uncast, exists, err := monitor.GetItem()

			if err != nil {
				t.Error(err)
			}
			if !exists && s.expectExist {
				t.Error("item does not exist")
			}
			if exists && !s.expectExist {
				t.Error("item should not exist")
			}

			ret, ok := uncast.(*corev1.Secret)
			if !ok && !s.expectUncastErr {
				t.Errorf("unable to uncast")
			}
			if ok && s.expectUncastErr {
				t.Errorf("should not be able to uncast")
			}
			if ret != nil && !reflect.DeepEqual(secret, ret) {
				t.Errorf("expected %v got %v", secret, ret)
			}
		})
	}
}

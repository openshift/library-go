package secret

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestAddSecretEventHandler(t *testing.T) {
	var (
		namespace  = "ns"
		secretName = "secret"
	)

	scenarios := []struct {
		name              string
		handler           cache.ResourceEventHandler
		numInvocation     int
		expectNumHandlers int32
		expectKey         ObjectKey
		expectErr         int
	}{
		{
			name:              "nil handler is provided",
			handler:           nil,
			numInvocation:     1,
			expectNumHandlers: 0,
			expectErr:         1,
		},
		{
			name:              "correct handler is provided",
			handler:           cache.ResourceEventHandlerFuncs{},
			numInvocation:     5,
			expectKey:         NewObjectKey(namespace, secretName),
			expectNumHandlers: 5,
			expectErr:         0,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset()
			fakeInformer := func() cache.SharedInformer {
				return fakeSecretInformer(context.TODO(), fakeKubeClient, namespace, secretName)
			}
			sm := secretMonitor{
				kubeClient: fakeKubeClient,
				monitors:   map[ObjectKey]*monitoredItem{},
			}

			gotErr := 0
			for i := 0; i < s.numInvocation; i++ {
				if _, err := sm.addSecretEventHandler(context.TODO(), namespace, secretName, s.handler, fakeInformer); err != nil {
					gotErr += 1
				}
			}
			if gotErr != s.expectErr {
				t.Errorf("expected %d errors, got %d errors", s.expectErr, gotErr)
			}

			if s.expectErr == 0 {
				if _, exist := sm.monitors[s.expectKey]; !exist {
					t.Fatal("monitor key should be added into map", s.expectKey)
				}
				if sm.monitors[s.expectKey].numHandlers.Load() != s.expectNumHandlers {
					t.Errorf("expected %d handlers, got %d handlers", s.expectNumHandlers, sm.monitors[s.expectKey].numHandlers.Load())
				}
			}
		})
	}
}

func TestRemoveSecretEventHandler(t *testing.T) {
	var (
		namespace  = "ns"
		secretName = "secret"
	)
	scenarios := []struct {
		name              string
		numAddition       int
		numRemoval        int
		isNilHandler      bool
		isKeyRemoved      bool
		expectKeyExist    bool
		expectNumHandlers int32
		expectErr         int
	}{
		{
			name:           "same number of addition and removal",
			numAddition:    5,
			numRemoval:     5,
			expectKeyExist: false,
			expectErr:      0,
		},
		{
			name:              "less number of removal than addition",
			numAddition:       5,
			numRemoval:        3,
			expectKeyExist:    true,
			expectNumHandlers: 2, // (numAddition-numRemoval)
			expectErr:         0,
		},
		{
			name:           "nil handler is provided",
			numAddition:    2,
			numRemoval:     3, // will append an extra nil handler
			isNilHandler:   true,
			expectKeyExist: false,
			expectErr:      1,
		},
		{
			name:           "secret monitor key already removed",
			numAddition:    2,
			numRemoval:     2,
			isKeyRemoved:   true,
			expectKeyExist: false,
			expectErr:      2, // should be equal to numRemoval
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset()
			fakeInformer := func() cache.SharedInformer {
				return fakeSecretInformer(context.TODO(), fakeKubeClient, namespace, secretName)
			}
			key := NewObjectKey(namespace, secretName)
			sm := secretMonitor{
				kubeClient: fakeKubeClient,
				monitors:   map[ObjectKey]*monitoredItem{},
			}

			handlers := []SecretEventHandlerRegistration{}
			for i := 0; i < s.numAddition; i++ {
				h, err := sm.addSecretEventHandler(context.TODO(), namespace, secretName, cache.ResourceEventHandlerFuncs{}, fakeInformer)
				if err != nil {
					t.Error(err)
				}
				handlers = append(handlers, h)
			}

			if s.isNilHandler {
				handlers = append(handlers, nil)
			}

			if s.isKeyRemoved {
				delete(sm.monitors, key)
			}

			gotErr := 0
			for i := 0; i < s.numRemoval; i++ {
				if err := sm.RemoveSecretEventHandler(handlers[i]); err != nil {
					t.Log(err)
					gotErr += 1
				}
			}
			if gotErr != s.expectErr {
				t.Errorf("expected %d errors, got %d errors", s.expectErr, gotErr)
			}

			m, exist := sm.monitors[key]
			if exist != s.expectKeyExist {
				t.Errorf("expected %t, got %t", s.expectKeyExist, exist)
			}
			// check numHandlers is key exists
			if exist {
				if m.numHandlers.Load() != s.expectNumHandlers {
					t.Errorf("expected %d handlers, got %d handlers", s.expectNumHandlers, m.numHandlers.Load())
				}
			}
		})
	}
}

func TestGetSecret(t *testing.T) {
	var (
		namespace  = "testNamespace"
		secretName = "testSecretName"
		secret     = fakeSecret(namespace, secretName)
	)

	scenarios := []struct {
		name                  string
		isNilHandler          bool
		isKeyRemoved          bool
		withSecret            bool
		expectSecretFromCache *corev1.Secret
		expectErr             bool
	}{
		{
			name:                  "secret exists in cluster but nil handler is provided",
			isNilHandler:          true,
			withSecret:            true,
			expectSecretFromCache: nil,
			expectErr:             true,
		},
		{
			name:                  "secret monitor key already removed",
			isKeyRemoved:          true,
			withSecret:            true,
			expectSecretFromCache: nil,
			expectErr:             true,
		},
		{
			// this case may occur when handler is not removed correctly
			// when secret gets deleted
			name:                  "secret does not exist in cluster and correct handler is provided",
			withSecret:            false,
			expectSecretFromCache: nil,
			expectErr:             true,
		},
		{
			name:                  "secret exists and correct handler is provided",
			withSecret:            true,
			expectSecretFromCache: secret,
			expectErr:             false,
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

			fakeInformer := func() cache.SharedInformer {
				return fakeSecretInformer(context.TODO(), fakeKubeClient, namespace, secretName)
			}
			key := NewObjectKey(namespace, secretName)
			sm := secretMonitor{
				kubeClient: fakeKubeClient,
				monitors:   map[ObjectKey]*monitoredItem{},
			}
			h, err := sm.addSecretEventHandler(context.TODO(), key.Namespace, key.Name, cache.ResourceEventHandlerFuncs{}, fakeInformer)
			if err != nil {
				t.Error(err)
			}

			if s.isNilHandler {
				h = nil
			}
			if s.isKeyRemoved {
				delete(sm.monitors, key)
			}

			gotSec, gotErr := sm.GetSecret(h)
			if gotErr != nil && !s.expectErr {
				t.Errorf("unexpected error %v", gotErr)
			}
			if gotErr == nil && s.expectErr {
				t.Errorf("expecting an error, got nil")
			}
			if !reflect.DeepEqual(s.expectSecretFromCache, gotSec) {
				t.Errorf("expected %v got %v", s.expectSecretFromCache, gotSec)
			}
		})
	}
}

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
	scenarios := []struct {
		name           string
		handler        cache.ResourceEventHandler
		inputKeys      []ObjectKey
		expectHandlers map[ObjectKey]int
		expectErr      int
	}{
		{
			name:    "nil handler is provided",
			handler: nil,
			inputKeys: []ObjectKey{
				{Namespace: "ns1", Name: "secret1"},
			},
			expectErr: 1,
		},
		{
			name:    "correct handler is provided",
			handler: cache.ResourceEventHandlerFuncs{},
			inputKeys: []ObjectKey{
				{Namespace: "ns1", Name: "secret1"},
				{Namespace: "ns1", Name: "secret1"},
				{Namespace: "ns2", Name: "secret2"},
				{Namespace: "ns2", Name: "secret2"},
				{Namespace: "ns3", Name: "secret3"},
			},
			expectHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 2,
				{Namespace: "ns2", Name: "secret2"}: 2,
				{Namespace: "ns3", Name: "secret3"}: 1,
			},
			expectErr: 0,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset()
			sm := secretMonitor{
				kubeClient: fakeKubeClient,
				monitors:   map[ObjectKey]*monitoredItem{},
			}

			gotErr := 0
			for _, k := range s.inputKeys {
				fakeInformer := fakeSecretInformer(context.TODO(), fakeKubeClient, k.Namespace, k.Name)
				if _, err := sm.addSecretEventHandler(context.TODO(), k.Namespace, k.Name, s.handler, fakeInformer); err != nil {
					gotErr += 1
				}
			}
			if gotErr != s.expectErr {
				t.Fatalf("expected %d errors, got %d errors", s.expectErr, gotErr)
			}

			for k, h := range s.expectHandlers {
				if _, exist := sm.monitors[k]; !exist {
					t.Fatalf("expected key not found: %v", k)
				}
				if sm.monitors[k].numHandlers != h {
					t.Errorf("expected %d handlers, got %d handlers", h, sm.monitors[k].numHandlers)
				}
			}
		})
	}
}

func TestRemoveSecretEventHandler(t *testing.T) {
	scenarios := []struct {
		name           string
		addHandlers    map[ObjectKey]int // to generate SecretEventHandlerRegistrations for keys and associated numHandlers
		alreadyRemoved []ObjectKey       // to delete keys if already removed
		removeHandlers map[ObjectKey]int // to call RemoveSecretEventHandler for keys and associated numHandlers
		expectHandlers map[ObjectKey]int // expected keys and associated numHandlers
		isNilHandler   bool              // to inject exception of nil HandlerRegistration
		expectErr      int
	}{
		{
			name: "same number of addition and removal",
			addHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 2,
				{Namespace: "ns2", Name: "secret2"}: 2,
				{Namespace: "ns3", Name: "secret3"}: 1,
			},
			removeHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 2,
				{Namespace: "ns2", Name: "secret2"}: 2,
				{Namespace: "ns3", Name: "secret3"}: 1,
			},
			expectHandlers: map[ObjectKey]int{},
			expectErr:      0,
		},
		{
			name: "less number of removal than addition",
			addHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 2,
				{Namespace: "ns2", Name: "secret2"}: 2,
				{Namespace: "ns3", Name: "secret3"}: 1,
			},
			removeHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 2,
				{Namespace: "ns2", Name: "secret2"}: 1,
			},
			expectHandlers: map[ObjectKey]int{
				{Namespace: "ns2", Name: "secret2"}: 1,
				{Namespace: "ns3", Name: "secret3"}: 1,
			},
			expectErr: 0,
		},
		{
			name: "nil handler is provided",
			addHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 1,
			},
			removeHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 1,
			},
			expectHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 1,
			},
			isNilHandler: true,
			expectErr:    1,
		},
		{
			name: "secret monitor key already removed",
			addHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 2,
				{Namespace: "ns2", Name: "secret2"}: 2,
				{Namespace: "ns3", Name: "secret3"}: 1,
			},
			alreadyRemoved: []ObjectKey{
				{Namespace: "ns1", Name: "secret1"},
			},
			removeHandlers: map[ObjectKey]int{
				{Namespace: "ns1", Name: "secret1"}: 2,
				{Namespace: "ns2", Name: "secret2"}: 2,
			},
			expectHandlers: map[ObjectKey]int{
				{Namespace: "ns3", Name: "secret3"}: 1,
			},
			expectErr: 2,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset()
			sm := secretMonitor{
				kubeClient: fakeKubeClient,
				monitors:   map[ObjectKey]*monitoredItem{},
			}

			// Generate SecretEventHandlerRegistrations
			handlersReg := map[ObjectKey][]SecretEventHandlerRegistration{}
			for k, numHandlers := range s.addHandlers {
				fakeInformer := fakeSecretInformer(context.TODO(), fakeKubeClient, k.Namespace, k.Name)
				for i := 0; i < numHandlers; i++ {
					h, err := sm.addSecretEventHandler(context.TODO(), k.Namespace, k.Name, cache.ResourceEventHandlerFuncs{}, fakeInformer)
					if err != nil {
						t.Error(err)
					}
					// store the handlersRegistration
					if s.isNilHandler {
						handlersReg[k] = append(handlersReg[k], nil)
					} else {
						handlersReg[k] = append(handlersReg[k], h)
					}
				}
			}

			// Delete keys if already removed
			for _, keyRemoved := range s.alreadyRemoved {
				delete(sm.monitors, keyRemoved)
			}

			// call RemoveSecretEventHandler
			gotErr := 0
			for k, numHandlers := range s.removeHandlers {
				regList := handlersReg[k]
				for i := 0; i < numHandlers; i++ {
					if err := sm.RemoveSecretEventHandler(regList[i]); err != nil {
						t.Log(err)
						gotErr += 1
					}
				}
			}
			if gotErr != s.expectErr {
				t.Fatalf("expected %d errors, got %d errors", s.expectErr, gotErr)
			}

			for k, numHandlers := range s.expectHandlers {
				if _, exist := sm.monitors[k]; !exist {
					t.Fatalf("expected key not found: %v", k)
				}
				if sm.monitors[k].numHandlers != numHandlers {
					t.Errorf("expected %d handlers, got %d handlers", numHandlers, sm.monitors[k].numHandlers)
				}
			}
		})
	}
}

func TestGetSecret(t *testing.T) {
	var (
		namespace  = "testNamespace"
		secretName = "testSecretName"
	)

	scenarios := []struct {
		name            string
		isNilHandlerReg bool
		isKeyRemoved    bool
		secret          corev1.Secret
		expectErr       bool
	}{
		{
			name:      "secret exists and correct handlerRegistration is provided",
			secret:    *fakeSecret(namespace, secretName),
			expectErr: false,
		},
		{
			name:            "nil handlerRegistration is provided",
			isNilHandlerReg: true,
			expectErr:       true,
		},
		{
			name:         "secret monitor key already removed",
			isKeyRemoved: true,
			expectErr:    true,
		},
		{
			name:      "secret does not exist and correct handlerRegistration is provided",
			expectErr: true,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset(&s.secret)
			fakeInformer := fakeSecretInformer(context.TODO(), kubeClient, namespace, secretName)
			key := NewObjectKey(namespace, secretName)
			sm := secretMonitor{
				kubeClient: kubeClient,
				monitors:   map[ObjectKey]*monitoredItem{},
			}
			h, err := sm.addSecretEventHandler(context.TODO(), key.Namespace, key.Name, cache.ResourceEventHandlerFuncs{}, fakeInformer)
			if err != nil {
				t.Error(err)
			}

			if s.isNilHandlerReg {
				h = nil
			}
			if s.isKeyRemoved {
				delete(sm.monitors, key)
			}

			gotSec, gotErr := sm.GetSecret(context.TODO(), h)
			if (gotErr != nil) != s.expectErr {
				t.Fatalf("expected errors to be %t, but got %t", s.expectErr, err != nil)
			}
			if !s.expectErr {
				if !reflect.DeepEqual(&s.secret, gotSec) {
					t.Errorf("expected %v got %v", s.secret, gotSec)
				}
			}
		})
	}
}

package secretmanager

import (
	"context"
	"fmt"
	"testing"

	"github.com/openshift/library-go/pkg/route/secret"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type routeSecret struct {
	routeName  string
	secretName string
}

type fakeSecretMonitor struct {
	err error
}

func (sm *fakeSecretMonitor) AddSecretEventHandler(_ context.Context, _ string, _ string, _ cache.ResourceEventHandler) (secret.SecretEventHandlerRegistration, error) {
	return nil, sm.err
}
func (sm *fakeSecretMonitor) RemoveSecretEventHandler(_ secret.SecretEventHandlerRegistration) error {
	return sm.err
}
func (sm *fakeSecretMonitor) GetSecret(_ secret.SecretEventHandlerRegistration) (*corev1.Secret, error) {
	return nil, sm.err
}

func TestRegisterRoute(t *testing.T) {
	namespace := "ns"

	scenarios := []struct {
		name               string
		rs                 []routeSecret
		sm                 fakeSecretMonitor
		expectHandlersKeys []string
		expectErr          int
	}{
		{
			name: "route can be registered only once with any secret",
			rs: []routeSecret{
				{routeName: "route", secretName: "secret"},
			},
			expectHandlersKeys: []string{namespace + "/route"},
			expectErr:          0,
		},
		{
			name: "same route cannot be registered again with same secret",
			rs: []routeSecret{
				{routeName: "route1", secretName: "secret1"},
				{routeName: "route1", secretName: "secret1"},
			},
			expectHandlersKeys: []string{namespace + "/route1"},
			expectErr:          1,
		},
		{
			name: "same route cannot be registered again with different secrets",
			rs: []routeSecret{
				{routeName: "route1", secretName: "secret1"},
				{routeName: "route1", secretName: "secret2"},
				{routeName: "route1", secretName: "secret3"},
			},
			expectHandlersKeys: []string{namespace + "/route1"},
			expectErr:          2,
		},
		{
			name: "different routes can be registered with same secret",
			rs: []routeSecret{
				{routeName: "route1", secretName: "secret1"},
				{routeName: "route2", secretName: "secret1"},
			},
			expectHandlersKeys: []string{namespace + "/route1", namespace + "/route2"},
			expectErr:          0,
		},
		{
			name: "different routes can be registered with different secrets",
			rs: []routeSecret{
				{routeName: "route1", secretName: "secret1"},
				{routeName: "route2", secretName: "secret2"},
			},
			expectHandlersKeys: []string{namespace + "/route1", namespace + "/route2"},
			expectErr:          0,
		},
		{
			name: "error while adding SecretEventHandler",
			rs: []routeSecret{
				{routeName: "route", secretName: "secret"},
			},
			sm:        fakeSecretMonitor{err: fmt.Errorf("some error")},
			expectErr: 1,
		},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			mgr := NewManager(nil, nil).WithSecretMonitor(&s.sm)

			gotErr := 0
			for i := 0; i < len(s.rs); i++ {
				if err := mgr.RegisterRoute(context.TODO(), namespace, s.rs[i].routeName, s.rs[i].secretName); err != nil {
					t.Log(err)
					gotErr += 1
				}
			}
			if gotErr != s.expectErr {
				t.Errorf("expected %d errors, got %d errors", s.expectErr, gotErr)
			}
			if len(s.expectHandlersKeys) != len(mgr.registeredHandlers) {
				t.Fatalf("expected %d keys: %v, got %d keys: %v", len(s.expectHandlersKeys), s.expectHandlersKeys, len(mgr.registeredHandlers), mgr.registeredHandlers)
			}
			for _, key := range s.expectHandlersKeys {
				if _, exists := mgr.registeredHandlers[key]; !exists {
					t.Errorf("%s key should exist", key)
				}
			}
		})
	}
}

func TestUnregisterRoute(t *testing.T) {
	var (
		namespace  = "ns"
		routeName  = "route"
		secretName = "secret"
	)
	scenarios := []struct {
		name               string
		withRegister       bool
		numUnregister      int
		sm                 fakeSecretMonitor
		expectHandlersKeys []string
		expectErr          int
	}{
		{
			name:          "unregister route without register",
			withRegister:  false,
			numUnregister: 1,
			expectErr:     1,
		},
		{
			name:          "unregister route more than once",
			withRegister:  true,
			numUnregister: 2,
			expectErr:     1,
		},
		{
			name:               "error while removing SecretEventHandler",
			withRegister:       true,
			numUnregister:      1,
			sm:                 fakeSecretMonitor{err: fmt.Errorf("some error")},
			expectHandlersKeys: []string{"some key"},
			expectErr:          1,
		},
		{
			name:          "correctly unregister route",
			withRegister:  true,
			numUnregister: 1,
			expectErr:     0,
		},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			mgr := NewManager(nil, nil)
			if s.withRegister {
				mgr.WithSecretMonitor(&fakeSecretMonitor{}) // avoid error from AddSecretEventHandler
				if err := mgr.RegisterRoute(context.TODO(), namespace, routeName, secretName); err != nil {
					t.Error(err)
				}
			}

			mgr.WithSecretMonitor(&s.sm)
			gotErr := 0
			for i := 0; i < s.numUnregister; i++ {
				if err := mgr.UnregisterRoute(namespace, routeName); err != nil {
					t.Log(err)
					gotErr += 1
				}
			}
			if gotErr != s.expectErr {
				t.Errorf("expected %d errors, got %d errors", s.expectErr, gotErr)
			}
			if len(s.expectHandlersKeys) != len(mgr.registeredHandlers) {
				t.Fatalf("expected %d keys: %v, got %d keys: %v", len(s.expectHandlersKeys), s.expectHandlersKeys, len(mgr.registeredHandlers), mgr.registeredHandlers)
			}
		})
	}
}

func TestGetSecret(t *testing.T) {
	var (
		namespace  = "ns"
		routeName  = "route"
		secretName = "secret"
	)
	scenarios := []struct {
		name         string
		withRegister bool
		sm           fakeSecretMonitor
		expectErr    int
	}{
		{
			name:         "get secret without register",
			withRegister: false,
			expectErr:    1,
		},
		{
			name:         "error from secret monitor while calling GetSecret",
			withRegister: true,
			sm:           fakeSecretMonitor{err: fmt.Errorf("some error")},
			expectErr:    1,
		},
		{
			name:         "successfully got secret",
			withRegister: true,
			expectErr:    0,
		},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			mgr := NewManager(nil, nil)
			if s.withRegister {
				mgr.WithSecretMonitor(&fakeSecretMonitor{}) // avoid error from AddSecretEventHandler
				if err := mgr.RegisterRoute(context.TODO(), namespace, routeName, secretName); err != nil {
					t.Error(err)
				}
			}

			mgr.WithSecretMonitor(&s.sm)
			gotErr := 0
			if _, err := mgr.GetSecret(namespace, routeName); err != nil {
				gotErr += 1
			}
			if gotErr != s.expectErr {
				t.Errorf("expected %d errors, got %d errors", s.expectErr, gotErr)
			}
		})
	}
}

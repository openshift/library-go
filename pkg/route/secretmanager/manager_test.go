package secretmanager

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/openshift/library-go/pkg/secret/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type routeSecret struct {
	routeName  string
	secretName string
}

func TestRegisterRoute(t *testing.T) {
	namespace := "ns"

	scenarios := []struct {
		name               string
		rs                 []routeSecret
		sm                 fake.SecretMonitor
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
			sm: fake.SecretMonitor{
				Err: fmt.Errorf("some error"),
			},
			expectErr: 1,
		},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			mgr := &manager{
				registeredHandlers: map[string]referencedSecret{},
				monitor:            &s.sm,
			}

			gotErr := 0
			for _, rs := range s.rs {
				if err := mgr.RegisterRoute(context.TODO(), namespace, rs.routeName, rs.secretName, cache.ResourceEventHandlerFuncs{}); err != nil {
					gotErr += 1
				}
			}
			if gotErr != s.expectErr {
				t.Fatalf("expected %d errors, got %d errors", s.expectErr, gotErr)
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

	type routeName string
	namespace := "ns"

	scenarios := []struct {
		name               string
		register           []routeSecret
		unregister         []routeName
		sm                 fake.SecretMonitor
		expectHandlersKeys []string
		expectErr          int
	}{
		{
			name:       "unregister route without register",
			register:   []routeSecret{},
			unregister: []routeName{"route1"},
			expectErr:  1,
		},
		{
			name: "unregister route more than once",
			register: []routeSecret{
				{routeName: "route1", secretName: "secret1"},
			},
			unregister: []routeName{"route1", "route1"},
			expectErr:  1,
		},
		{
			name: "error while removing SecretEventHandler",
			register: []routeSecret{
				{routeName: "route1", secretName: "secret1"},
			},
			unregister: []routeName{"route1"},
			sm: fake.SecretMonitor{
				Err: fmt.Errorf("some error"),
			},
			expectHandlersKeys: []string{namespace + "/route1"},
			expectErr:          1,
		},
		{
			name: "correctly unregister route",
			register: []routeSecret{
				{routeName: "route1", secretName: "secret1"},
			},
			unregister: []routeName{"route1"},
			expectErr:  0,
		},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			mgr := &manager{registeredHandlers: map[string]referencedSecret{}}
			// register
			mgr.monitor = &fake.SecretMonitor{} // avoid error from AddSecretEventHandler
			for _, rs := range s.register {
				if err := mgr.RegisterRoute(context.TODO(), namespace, rs.routeName, rs.secretName, cache.ResourceEventHandlerFuncs{}); err != nil {
					t.Fatalf("failed to register %v: %v", rs, err)
				}
			}

			// unregister
			mgr.monitor = &s.sm
			gotErr := 0
			for _, routeName := range s.unregister {
				if err := mgr.UnregisterRoute(namespace, string(routeName)); err != nil {
					t.Log(err)
					gotErr += 1
				}
			}
			if gotErr != s.expectErr {
				t.Fatalf("expected %d errors, got %d errors", s.expectErr, gotErr)
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

func TestGetSecret(t *testing.T) {
	var (
		namespace = "ns"
		routeName = "route"
	)

	scenarios := []struct {
		name      string
		register  []routeSecret
		sm        fake.SecretMonitor
		expectErr bool
	}{
		{
			name:      "get secret without register",
			register:  []routeSecret{},
			expectErr: true,
		},
		{
			name:     "error from secret monitor while calling GetSecret",
			register: []routeSecret{{routeName, "secretName"}},
			sm: fake.SecretMonitor{
				Err: fmt.Errorf("some error"),
			},
			expectErr: true,
		},
		{
			name:     "successfully got secret",
			register: []routeSecret{{routeName, "secretName"}},
			sm: fake.SecretMonitor{
				Err: nil,
				Secret: &corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secretName",
						Namespace: namespace,
					},
				},
			},
			expectErr: false,
		},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			mgr := manager{registeredHandlers: map[string]referencedSecret{}}
			// register
			mgr.monitor = &fake.SecretMonitor{} // avoid error from AddSecretEventHandler
			for _, rs := range s.register {
				if err := mgr.RegisterRoute(context.TODO(), namespace, rs.routeName, rs.secretName, cache.ResourceEventHandlerFuncs{}); err != nil {
					t.Fatalf("failed to register %v: %v", rs, err)
				}
			}

			mgr.monitor = &s.sm
			gotSec, err := mgr.GetSecret(context.TODO(), namespace, routeName)

			if (err != nil) != s.expectErr {
				t.Fatalf("expected errors to be %t, but got %t", s.expectErr, err != nil)
			}

			if !reflect.DeepEqual(s.sm.Secret, gotSec) {
				t.Fatalf("expected %v got %v", s.sm.Secret, gotSec)
			}
		})
	}
}

func TestLookupRouteSecret(t *testing.T) {
	var (
		namespace = "ns"
		routeName = "route"
	)

	scenarios := []struct {
		name             string
		register         []routeSecret
		expectExist      bool
		expectSecretName string
	}{
		{
			name:     "when route is not registered",
			register: []routeSecret{},
		},
		{
			name:             "when route is registered",
			register:         []routeSecret{{routeName, "secretName"}},
			expectExist:      true,
			expectSecretName: "secretName",
		},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			mgr := &manager{
				registeredHandlers: map[string]referencedSecret{},
				monitor:            &fake.SecretMonitor{},
			}
			// register
			for _, rs := range s.register {
				if err := mgr.RegisterRoute(context.TODO(), namespace, rs.routeName, rs.secretName, cache.ResourceEventHandlerFuncs{}); err != nil {
					t.Fatalf("failed to register %v: %v", rs, err)
				}
			}

			secret, exist := mgr.LookupRouteSecret(namespace, routeName)

			if exist != s.expectExist {
				t.Fatalf("expected %t, but got %t", s.expectExist, exist)
			}
			if secret != s.expectSecretName {
				t.Fatalf("expected secret %s, but got %s", s.expectSecretName, secret)
			}
		})
	}
}

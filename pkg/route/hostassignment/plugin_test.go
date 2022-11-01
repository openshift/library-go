package hostassignment

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	routev1 "github.com/openshift/api/route/v1"
)

func TestNewSimpleAllocationPlugin(t *testing.T) {
	tests := []struct {
		Name             string
		ErrorExpectation bool
	}{
		{
			Name:             "www.example.org",
			ErrorExpectation: false,
		},
		{
			Name:             "www^acme^org",
			ErrorExpectation: true,
		},
		{
			Name:             "bad wolf.whoswho",
			ErrorExpectation: true,
		},
		{
			Name:             "tardis#1.watch",
			ErrorExpectation: true,
		},
		{
			Name:             "こんにちはopenshift.com",
			ErrorExpectation: true,
		},
		{
			Name:             "yo!yo!@#$%%$%^&*(0){[]}:;',<>?/1.test",
			ErrorExpectation: true,
		},
		{
			Name:             "",
			ErrorExpectation: false,
		},
	}

	for _, tc := range tests {
		sap, err := NewSimpleAllocationPlugin(tc.Name)
		if err != nil && !tc.ErrorExpectation {
			t.Errorf("Test case for %s got an error where none was expected", tc.Name)
		}
		if len(tc.Name) > 0 {
			continue
		}
		dap := &SimpleAllocationPlugin{DNSSuffix: defaultDNSSuffix}
		if sap.DNSSuffix != dap.DNSSuffix {
			t.Errorf("Expected function to use defaultDNSSuffix for empty name argument.")
		}
	}
}

func TestSimpleAllocationPlugin(t *testing.T) {
	tests := []struct {
		name  string
		route *routev1.Route
		empty bool
	}{
		{
			name: "No Name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: routev1.RouteSpec{
					To: routev1.RouteTargetReference{
						Name: "service",
					},
				},
			},
			empty: true,
		},
		{
			name: "No namespace",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name: "name",
				},
				Spec: routev1.RouteSpec{
					To: routev1.RouteTargetReference{
						Name: "nonamespace",
					},
				},
			},
			empty: true,
		},
		{
			name: "No service name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
			},
		},
		{
			name: "Valid route",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					To: routev1.RouteTargetReference{
						Name: "myservice",
					},
				},
			},
		},
		{
			name: "No host",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					To: routev1.RouteTargetReference{
						Name: "myservice",
					},
				},
			},
		},
	}

	plugin, err := NewSimpleAllocationPlugin("www.example.org")
	if err != nil {
		t.Errorf("Error creating SimpleAllocationPlugin got %s", err)
		return
	}

	for _, tc := range tests {
		name, _ := plugin.GenerateHostname(tc.route)
		switch {
		case len(name) == 0 && !tc.empty, len(name) != 0 && tc.empty:
			t.Errorf("Test case %s got %d length name.", tc.name, len(name))
		case tc.empty:
			continue
		}
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			t.Errorf("Test case %s got %s - invalid DNS name.", tc.name, name)
		}
	}
}

func TestSimpleAllocationPluginViaController(t *testing.T) {
	tests := []struct {
		name  string
		route *routev1.Route
		empty bool
	}{
		{
			name: "No Name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: routev1.RouteSpec{
					To: routev1.RouteTargetReference{
						Name: "service",
					},
				},
			},
			empty: true,
		},
		{
			name: "Host but no name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: routev1.RouteSpec{
					Host: "foo.com",
				},
			},
			empty: true,
		},
		{
			name: "No namespace",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name: "name",
				},
				Spec: routev1.RouteSpec{
					To: routev1.RouteTargetReference{
						Name: "nonamespace",
					},
				},
			},
			empty: true,
		},
		{
			name: "No service name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
			},
		},
		{
			name: "Valid route",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					To: routev1.RouteTargetReference{
						Name: "s3",
					},
				},
			},
		},
	}

	plugin, err := NewSimpleAllocationPlugin("www.example.org")
	if err != nil {
		t.Fatalf("unexpected error")
	}

	for _, tc := range tests {
		name, err := plugin.GenerateHostname(tc.route)
		if err != nil {
			t.Errorf("Test case %s got an error %s", tc.name, err)
		}
		switch {
		case len(name) == 0 && !tc.empty, len(name) != 0 && tc.empty:
			t.Errorf("Test case %s got %d length name.", tc.name, len(name))
		case tc.empty:
			continue
		}
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			t.Errorf("Test case %s got %s - invalid DNS name.", tc.name, name)
		}
	}
}

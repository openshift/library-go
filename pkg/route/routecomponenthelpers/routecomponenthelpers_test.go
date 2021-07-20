package routecomponenthelpers

import (
	"reflect"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestGetCustomRouteHostname(t *testing.T) {
	tests := []struct {
		name                    string
		componentRouteNamespace string
		componentRouteName      string
		ingress                 *configv1.Ingress
		want                    string
	}{
		{
			name:                    "Return an empty string if componentRoute list is empty",
			componentRouteNamespace: "foo",
			componentRouteName:      "bar",
			ingress:                 &configv1.Ingress{},
			want:                    "",
		},
		{
			name:                    "Return an empty string if componentRoute is not present",
			componentRouteNamespace: "foo",
			componentRouteName:      "bar",
			ingress: &configv1.Ingress{
				Spec: configv1.IngressSpec{
					ComponentRoutes: []configv1.ComponentRouteSpec{
						{
							Namespace: "notFoo",
							Name:      "notBar",
							Hostname:  "shouldNotBeUsed",
						},
					},
				},
			},
			want: "",
		}, {
			name:                    "Use provided hostname if componentRoute is present",
			componentRouteNamespace: "foo",
			componentRouteName:      "bar",
			ingress: &configv1.Ingress{
				Spec: configv1.IngressSpec{
					ComponentRoutes: []configv1.ComponentRouteSpec{
						{
							Namespace: "notFoo",
							Name:      "notBar",
							Hostname:  "shouldNotBeUsed",
						},
						{
							Namespace: "foo",
							Name:      "bar",
							Hostname:  "expected.com",
						},
					},
				},
			},
			want: "expected.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetCustomRouteHostname(tt.ingress, tt.componentRouteNamespace, tt.componentRouteName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetCustomRouteHostname() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetComponentRouteSpec(t *testing.T) {
	tests := []struct {
		name                    string
		componentRouteNamespace string
		componentRouteName      string
		ingress                 *configv1.Ingress
		want                    *configv1.ComponentRouteSpec
	}{
		{
			name:                    "Return nil if ingress.Spec.ComponentRoutes list is empty",
			componentRouteNamespace: "foo",
			componentRouteName:      "bar",
			ingress:                 &configv1.Ingress{},
			want:                    nil,
		},
		{
			name:                    "Return nil if the componentRoute is not in the ingress.Spec.ComponentRoutes list",
			componentRouteNamespace: "foo",
			componentRouteName:      "bar",
			ingress: &configv1.Ingress{
				Spec: configv1.IngressSpec{
					ComponentRoutes: []configv1.ComponentRouteSpec{
						{
							Namespace: "notFoo",
							Name:      "notBar",
						},
					},
				},
			},
			want: nil,
		},
		{
			name:                    "If the componentRoute is found its pointer is returned",
			componentRouteNamespace: "foo",
			componentRouteName:      "bar",
			ingress: &configv1.Ingress{
				Spec: configv1.IngressSpec{
					ComponentRoutes: []configv1.ComponentRouteSpec{
						{
							Namespace: "notFoo",
							Name:      "notBar",
						},
						{
							Namespace: "foo",
							Name:      "bar",
							Hostname:  "hostname",
							ServingCertKeyPairSecret: configv1.SecretNameReference{
								Name: "secretName",
							},
						},
					},
				},
			},
			want: &configv1.ComponentRouteSpec{
				Namespace: "foo",
				Name:      "bar",
				Hostname:  "hostname",
				ServingCertKeyPairSecret: configv1.SecretNameReference{
					Name: "secretName",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetComponentRouteSpec(tt.ingress, tt.componentRouteNamespace, tt.componentRouteName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetComponentRouteSpec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetComponentRouteStatus(t *testing.T) {
	tests := []struct {
		name                    string
		componentRouteNamespace string
		componentRouteName      string
		ingress                 *configv1.Ingress
		want                    *configv1.ComponentRouteStatus
	}{
		{
			name:                    "Return nil if ingress.Status.ComponentRoutes list is empty",
			componentRouteNamespace: "foo",
			componentRouteName:      "bar",
			ingress:                 &configv1.Ingress{},
			want:                    nil,
		},
		{
			name:                    "Return nil if the componentRoute is not in the ingress.Status.ComponentRoutes list",
			componentRouteNamespace: "foo",
			componentRouteName:      "bar",
			ingress: &configv1.Ingress{
				Status: configv1.IngressStatus{
					ComponentRoutes: []configv1.ComponentRouteStatus{
						{
							Namespace: "notFoo",
							Name:      "notBar",
						},
					},
				},
			},
			want: nil,
		},
		{
			name:                    "If the componentRoute is found its pointer is returned",
			componentRouteNamespace: "foo",
			componentRouteName:      "bar",
			ingress: &configv1.Ingress{
				Status: configv1.IngressStatus{
					ComponentRoutes: []configv1.ComponentRouteStatus{
						{
							Namespace: "notFoo",
							Name:      "notBar",
						},
						{
							Namespace:       "foo",
							Name:            "bar",
							DefaultHostname: "expected",
						},
					},
				},
			},
			want: &configv1.ComponentRouteStatus{
				Namespace:       "foo",
				Name:            "bar",
				DefaultHostname: "expected",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetComponentRouteStatus(tt.ingress, tt.componentRouteNamespace, tt.componentRouteName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetComponentRouteStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

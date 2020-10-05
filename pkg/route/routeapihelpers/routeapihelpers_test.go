package routeapihelpers

import (
	"net/url"
	"reflect"
	"regexp"
	"testing"

	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIngressURI(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		route   *routev1.Route
		host    string
		uri     *url.URL
		ingress *routev1.RouteIngress
		error   string
	}{
		{
			name: "no ingress",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "example-namespace",
					Name:      "example-name",
				},
			},
			error: "^no admitted ingress for route example-name in namespace example-namespace$",
		},
		{
			name: "no admitted ingress, host-agnostic",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "example-namespace",
					Name:      "example-name",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host:       "example.com",
							RouterName: "example-router",
						},
					},
				},
			},
			error: "^no admitted ingress for route example-name in namespace example-namespace$",
		},
		{
			name: "explicitly non-admitted ingress, host-agnostic",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "example-namespace",
					Name:      "example-name",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host:       "example.com",
							RouterName: "example-router",
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:    routev1.RouteAdmitted,
									Status:  corev1.ConditionFalse,
									Reason:  "ExampleReason",
									Message: "Example message",
								},
							},
						},
					},
				},
			},
			error: "^no admitted ingress for route example-name in namespace example-namespace$",
		},
		{
			name: "no admitted ingress, unrecognized host",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "example-namespace",
					Name:      "example-name",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host:       "example.com",
							RouterName: "example-router",
						},
					},
				},
			},
			host:  "a.example.com",
			error: "^no ingress for host a.example.com in route example-name in namespace example-namespace$",
		},
		{
			name: "no admitted ingress, host not admitted",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "example-namespace",
					Name:      "example-name",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host:       "example.com",
							RouterName: "example-router",
						},
					},
				},
			},
			host: "example.com",
			uri: &url.URL{
				Scheme: "http",
				Host:   "example.com",
			},
			ingress: &routev1.RouteIngress{
				Host:       "example.com",
				RouterName: "example-router",
			},
			error: "^ingress for host example.com in route example-name in namespace example-namespace is not admitted$",
		},
		{
			name: "admitted ingress, host-agnostic",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "example-namespace",
					Name:      "example-name",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host:       "a.example.com",
							RouterName: "example-router",
						},
						{
							Host:       "b.example.com",
							RouterName: "example-router",
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:    routev1.RouteAdmitted,
									Status:  corev1.ConditionTrue,
									Reason:  "ExampleReason",
									Message: "Example message",
								},
							},
						},
						{
							Host:       "c.example.com",
							RouterName: "example-router",
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:    routev1.RouteAdmitted,
									Status:  corev1.ConditionTrue,
									Reason:  "ExampleReason",
									Message: "Example message",
								},
							},
						},
					},
				},
			},
			uri: &url.URL{
				Scheme: "http",
				Host:   "b.example.com",
			},
			ingress: &routev1.RouteIngress{
				Host:       "b.example.com",
				RouterName: "example-router",
				Conditions: []routev1.RouteIngressCondition{
					{
						Type:    routev1.RouteAdmitted,
						Status:  corev1.ConditionTrue,
						Reason:  "ExampleReason",
						Message: "Example message",
					},
				},
			},
		},
		{
			name: "admitted ingress, host-specific",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "example-namespace",
					Name:      "example-name",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host:       "a.example.com",
							RouterName: "example-router",
						},
						{
							Host:       "b.example.com",
							RouterName: "example-router",
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:    routev1.RouteAdmitted,
									Status:  corev1.ConditionTrue,
									Reason:  "ExampleReason",
									Message: "Example message",
								},
							},
						},
						{
							Host:       "c.example.com",
							RouterName: "example-router",
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:    routev1.RouteAdmitted,
									Status:  corev1.ConditionTrue,
									Reason:  "ExampleReason",
									Message: "Example message",
								},
							},
						},
					},
				},
			},
			host: "c.example.com",
			uri: &url.URL{
				Scheme: "http",
				Host:   "c.example.com",
			},
			ingress: &routev1.RouteIngress{
				Host:       "c.example.com",
				RouterName: "example-router",
				Conditions: []routev1.RouteIngressCondition{
					{
						Type:    routev1.RouteAdmitted,
						Status:  corev1.ConditionTrue,
						Reason:  "ExampleReason",
						Message: "Example message",
					},
				},
			},
		},
		{
			name: "admitted ingress, TLS",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "example-namespace",
					Name:      "example-name",
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{},
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host:       "example.com",
							RouterName: "example-router",
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:    routev1.RouteAdmitted,
									Status:  corev1.ConditionTrue,
									Reason:  "ExampleReason",
									Message: "Example message",
								},
							},
						},
					},
				},
			},
			uri: &url.URL{
				Scheme: "https",
				Host:   "example.com",
			},
			ingress: &routev1.RouteIngress{
				Host:       "example.com",
				RouterName: "example-router",
				Conditions: []routev1.RouteIngressCondition{
					{
						Type:    routev1.RouteAdmitted,
						Status:  corev1.ConditionTrue,
						Reason:  "ExampleReason",
						Message: "Example message",
					},
				},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			uri, ingress, err := IngressURI(testCase.route, testCase.host)
			if testCase.error != "" && err == nil {
				t.Fatalf("returned no error, expected %s", testCase.error)
			} else if testCase.error == "" && err != nil {
				t.Fatalf("expected no error, returned %v", err)
			} else if err != nil && !regexp.MustCompile(testCase.error).MatchString(err.Error()) {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(uri, testCase.uri) {
				t.Fatal(uri)
			}
			if !reflect.DeepEqual(ingress, testCase.ingress) {
				t.Fatal(ingress)
			}
		})
	}
}

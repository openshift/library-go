package routeapihelpers

import (
	"net/url"
	"reflect"
	"regexp"
	"testing"

	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	field "k8s.io/apimachinery/pkg/util/validation/field"
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

// TestValidateHost ensures not specifying a proper host name results in error and
// that a correctly specified host name passes successfully
func TestValidateRoute(t *testing.T) {
	tests := []struct {
		name              string
		host              string
		allowNonCompliant string
		expectedErrors    int
	}{
		{
			name:           "Valid host",
			host:           "host",
			expectedErrors: 0,
		},
		{
			name:           "Non-DNS-compliant host without non-compliance annotation",
			host:           "1234567890-1234567890-1234567890-1234567890-1234567890-123456789.host",
			expectedErrors: 1,
		},
		{
			name:              "Non-DNS-compliant host with non-compliance annotation",
			host:              "1234567890-1234567890-1234567890-1234567890-1234567890-123456789.host",
			allowNonCompliant: "true",
			expectedErrors:    0,
		},
		{
			name:              "Specified label too long",
			host:              "1234567890-1234567890-1234567890-1234567890-1234567890-123456789.host.com",
			allowNonCompliant: "",
			expectedErrors:    1,
		},
		{
			name:              "Specified label too long, is not an error with non-compliance allowed",
			host:              "1234567890-1234567890-1234567890-1234567890-1234567890-123456789.host.com",
			allowNonCompliant: "true",
			expectedErrors:    0,
		},
		{
			name: "Specified host name too long",
			host: "1234567890-1234567890-1234567890-1234567890-1234567890." +
				"1234567890-1234567890-1234567890-1234567890-1234567890." +
				"1234567890-1234567890-1234567890-1234567890-1234567890." +
				"1234567890-1234567890-1234567890-1234567890-1234567890." +
				"1234567890-1234567890-1234567890-1",
			allowNonCompliant: "",
			expectedErrors:    1,
		},
		{
			name: "Specified host name too long, is still an error even with non-compliance allowed",
			host: "1234567890-1234567890-1234567890-1234567890-1234567890." +
				"1234567890-1234567890-1234567890-1234567890-1234567890." +
				"1234567890-1234567890-1234567890-1234567890-1234567890." +
				"1234567890-1234567890-1234567890-1234567890-1234567890." +
				"1234567890-1234567890-1234567890-1",
			allowNonCompliant: "true",
			expectedErrors:    1,
		},
		{
			name:              "No host",
			host:              "",
			allowNonCompliant: "",
			expectedErrors:    2,
		},
		{
			name:              "Invalid DNS 952 host",
			host:              "**",
			allowNonCompliant: "",
			expectedErrors:    2,
		},
		{
			name:              "Invalid host with trailing dot",
			host:              "hostwithtrailing.",
			allowNonCompliant: "",
			expectedErrors:    2,
		},
	}

	for _, tc := range tests {
		errs := ValidateHost(tc.host, tc.allowNonCompliant, field.NewPath("spec.host"))
		if len(errs) != tc.expectedErrors {
			t.Errorf("Test case %q expected %d error(s), got %d: %v", tc.name, tc.expectedErrors, len(errs), errs)
		}
	}
}

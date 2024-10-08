package validation

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	testclient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	routev1 "github.com/openshift/api/route/v1"
	routecommon "github.com/openshift/library-go/pkg/route"
)

const (
	testCACertificate = `-----BEGIN CERTIFICATE-----
MIIClDCCAf2gAwIBAgIJAPU57OGhuqJtMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTERMA8GA1UECgwIU2VjdXJpdHkxGzAZBgNVBAsM
Ek9wZW5TaGlmdDMgdGVzdCBDQTEXMBUGA1UEAwwOaGVhZGVyLnRlc3QgQ0EwHhcN
MTYwMzEyMDQyMTAzWhcNMzYwMzEyMDQyMTAzWjBjMQswCQYDVQQGEwJVUzELMAkG
A1UECAwCQ0ExETAPBgNVBAoMCFNlY3VyaXR5MRswGQYDVQQLDBJPcGVuU2hpZnQz
IHRlc3QgQ0ExFzAVBgNVBAMMDmhlYWRlci50ZXN0IENBMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCsdVIJ6GSrkFdE9LzsMItYGE4q3qqSqIbs/uwMoVsMT+33
pLeyzeecPuoQsdO6SEuqhUM1ivUN4GyXIR1+aW2baMwMXpjX9VIJu5d4FqtGi6SD
RfV+tbERWwifPJlN+ryuvqbbDxrjQeXhemeo7yrJdgJ1oyDmoM5pTiSUUmltvQID
AQABo1AwTjAdBgNVHQ4EFgQUOVuieqGfp2wnKo7lX2fQt+Yk1C4wHwYDVR0jBBgw
FoAUOVuieqGfp2wnKo7lX2fQt+Yk1C4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOBgQA8VhmNeicRnKgXInVyYZDjL0P4WRbKJY7DkJxRMRWxikbEVHdySki6
jegpqgJqYbzU6EiuTS2sl2bAjIK9nGUtTDt1PJIC1Evn5Q6v5ylNflpv6GxtUbCt
bGvtpjWA4r9WASIDPFsxk/cDEEEO6iPxgMOf5MdpQC2y2MU0rzF/Gg==
-----END CERTIFICATE-----`

	testDestinationCACertificate = testCACertificate
)

func createRouteSpecTo(name string, kind string) routev1.RouteTargetReference {
	svc := routev1.RouteTargetReference{
		Name: name,
		Kind: kind,
	}
	return svc
}

type testSARCreator struct {
	allow bool
	err   error
	sar   *authorizationv1.SubjectAccessReview
}

func (t *testSARCreator) Create(_ context.Context, subjectAccessReview *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error) {
	t.sar = subjectAccessReview
	return &authorizationv1.SubjectAccessReview{
		Status: authorizationv1.SubjectAccessReviewStatus{
			Allowed: t.allow,
		},
	}, t.err
}

type testSecretGetter struct {
	namespace string
	secret    *corev1.Secret
}

func (t *testSecretGetter) Secrets(_ string) corev1client.SecretInterface {
	return testclient.NewSimpleClientset(t.secret).CoreV1().Secrets(t.namespace)
}

func init() {
	scheme := scheme.Scheme
	corev1.AddToScheme(scheme)
	testclient.AddToScheme(scheme)
}

// Context around testing hostname validation.
// Currently the host name validation checks along these lines
//
// DNS 1123 subdomain
// - host name ^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$
// - and not greater than 253 characters
//
// The additional test (which now aligns with the router hostname validation) is
// DNS 1123 label
// - host name label ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$
// - and not greater than 63 characters
//
// The above check can be bypassed by setting the annotation for backwards compatibility
// - route.openshift.io/allow-non-dns-compliant-host: "true"

// N.B. For tests that have the AllowNonDNSCompliantHostAnnotation annotation set to true
// - All tests return the expected behavior of the current api-server
// - The ONLY exception is the test for labels greater than 63 i.e -> name: "Valid host (64 chars label annotation override)"
// - The behavior is as follows
//   - annotation set to false (default) test name: "Valid host (64 chars label annotation override)" has expectedErrors > 0
//   - annotation set to true            test name: "Valid host (64 chars label annotation override)" has expectedErrors == 0
//
// As mentioned this allows for the edge case where customers were using DNS labels greater than 64 chars and were not using the openshift router.

// TestValidateRoute ensures not specifying a required field results in error and a fully specified
// route passes successfully
func TestValidateRoute(t *testing.T) {
	var headerNameXFrame string = "X-Frame-Options"
	var headerNameXSS string = "X-XSS-Protection"
	invalidNumRequests := make([]routev1.RouteHTTPHeader, maxRequestHeaderList+1)
	invalidNumResponses := make([]routev1.RouteHTTPHeader, maxResponseHeaderList+1)
	routeWithPathAndRewriteAnnotation := func(path, rewriteTargetAnnotation string) *routev1.Route {
		return &routev1.Route{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "wildcardpolicy",
				Namespace: "foo",
				Annotations: map[string]string{
					"haproxy.router.openshift.io/rewrite-target": rewriteTargetAnnotation,
				},
			},
			Spec: routev1.RouteSpec{
				To:   createRouteSpecTo("serviceName", "Service"),
				Path: path,
			},
		}
	}
	tests := []struct {
		name           string
		route          *routev1.Route
		expectedErrors int
	}{
		{
			name: "No Name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "host",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "No namespace",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name: "name",
				},
				Spec: routev1.RouteSpec{
					Host: "host",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "No host",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					To: createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid host",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "**",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Valid single label host",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "test",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid host (start & end alpha)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "abc.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid host (start & end numeric)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "1.test.com.2",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid host (trailing '.')",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "abc.test.com.",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Invalid host ('*' not allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "abc.*.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Invalid host ('%!&#@$^' not allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "abc.%!&#@$^.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Invalid host ('A-Z' not allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "A.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Invalid host (trailing '-' not allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "abc.test.com.-",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Valid host (many segements/labels allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "x.abc.y.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid host 63 chars label",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace-1234567890-1234567890-1234567890-1234567890-1234.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid host (64 chars label annotation override)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace-1234567890-1234567890-1234567890-1234567890-12345.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid host (253 chars)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace.a1234567890.b1234567890.c1234567890.d1234567890.e1234567890.f1234567890.g1234567890.h1234567890.i1234567890.j1234567890.k1234567890.l1234567890.m1234567890.n1234567890.o1234567890.p1234567890.q1234567890.r1234567890.s12345678.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid host (279 chars)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace.a1234567890.b1234567890.c1234567890.d1234567890.e1234567890.f1234567890.g1234567890.h1234567890.i1234567890.j1234567890.k1234567890.l1234567890.m1234567890.n1234567890.o1234567890.p1234567890.q1234567890.r1234567890.s1234567890.t1234567890.u1234567890.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Invalid host (does not conform DNS host name)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "**",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 2,
		},
		{
			name: "Valid single label host (conform DNS host name)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "test",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid host (conform DNS host name start & end alpha)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "abc.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid host (conform DNS host name - start & end numeric)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "1.abc.test.com.2",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid host (does not conform DNS host name - trailing '.')",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "abc.test.com.",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 2,
		},
		{
			name: "Invalid host (does not conform DNS host name - '*' not allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "abc.*.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 2,
		},
		{
			name: "Invalid host (does not conform DNS host name - '%!&#@$^' not allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "abc.%!&#@$^.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 2,
		},
		{
			name: "Invalid host (does not conform DNS host name - 'A-Z' not allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "A.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 2,
		},
		{
			name: "Invalid host (does not conform DNS host name - trailing '-' not allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "abc.test.com.-",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 2,
		},
		{
			name: "Valid host (conform DNS host name - many segments/labels allowed)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "x.abc.y.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid host (conform DNS host name - 63 chars label)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace-1234567890-1234567890-1234567890-1234567890-1234.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid host (does not conform  DNS host name - 64 chars label)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace-1234567890-1234567890-1234567890-1234567890-12345.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Valid host (conform DNS host name - 253 chars)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace.a1234567890.b1234567890.c1234567890.d1234567890.e1234567890.f1234567890.g1234567890.h1234567890.i1234567890.j1234567890.k1234567890.l1234567890.m1234567890.n1234567890.o1234567890.p1234567890.q1234567890.r1234567890.s123456789.t1.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid host (does conform DNS host name - 254 chars)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "false",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace.a1234567890.b1234567890.c1234567890.d1234567890.e1234567890.f1234567890.g1234567890.h1234567890.i1234567890.j1234567890.k1234567890.l1234567890.m1234567890.n1234567890.o1234567890.p1234567890.q1234567890.r1234567890.s1234567890.t12.test.com",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Valid subdomain",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Subdomain: "api.ci",
					To:        createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid subdomain (253 chars)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Subdomain: "name-namespace.a1234567890.b1234567890.c1234567890.d1234567890.e1234567890.f1234567890.g1234567890.h1234567890.i1234567890.j1234567890.k1234567890.l1234567890.m1234567890.n1234567890.o1234567890.p1234567890.q1234567890.r1234567890.s12345678.test.com",
					To:        createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid subdomain (279 chars)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Subdomain: "name-namespace.a1234567890.b1234567890.c1234567890.d1234567890.e1234567890.f1234567890.g1234567890.h1234567890.i1234567890.j1234567890.k1234567890.l1234567890.m1234567890.n1234567890.o1234567890.p1234567890.q1234567890.r1234567890.s1234567890.t1234567890.u1234567890.test.com",
					To:        createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Invalid DNS 952 subdomain",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Subdomain: "**",
					To:        createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Valid subdomain (conform DNS host name - 253 chars)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Subdomain: "name-namespace.a1234567890.b1234567890.c1234567890.d1234567890.e1234567890.f1234567890.g1234567890.h1234567890.i1234567890.j1234567890.k1234567890.l1234567890.m1234567890.n1234567890.o1234567890.p1234567890.q1234567890.r1234567890.s123456789.t1.test.com",
					To:        createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid subdomain (does conform DNS host name - 254 chars)",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "false",
					},
				},
				Spec: routev1.RouteSpec{
					Subdomain: "name-namespace.a1234567890.b1234567890.c1234567890.d1234567890.e1234567890.f1234567890.g1234567890.h1234567890.i1234567890.j1234567890.k1234567890.l1234567890.m1234567890.n1234567890.o1234567890.p1234567890.q1234567890.r1234567890.s1234567890.t12.test.com",
					To:        createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "No service name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "host",
					To:   createRouteSpecTo("", "Service"),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "No service kind",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "host",
					To:   createRouteSpecTo("serviceName", ""),
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Zero port",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					To:   createRouteSpecTo("serviceName", "Service"),
					Port: &routev1.RoutePort{
						TargetPort: intstr.FromInt(0),
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Empty string port",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					To:   createRouteSpecTo("serviceName", "Service"),
					Port: &routev1.RoutePort{
						TargetPort: intstr.FromString(""),
					},
				},
			},
			expectedErrors: 1,
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
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Valid route with path",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					To:   createRouteSpecTo("serviceName", "Service"),
					Path: "/test",
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid route with path",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					To:   createRouteSpecTo("serviceName", "Service"),
					Path: "test",
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Passthrough route with path",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					Path: "/test",
					To:   createRouteSpecTo("serviceName", "Service"),
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationPassthrough,
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "No wildcard policy",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nowildcard",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "no.wildcard.test",
					To:   createRouteSpecTo("serviceName", "Service"),
				},
			},
			expectedErrors: 0,
		},
		{
			name: "wildcard policy none",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nowildcard2",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "none.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicyNone,
				},
			},
			expectedErrors: 0,
		},
		{
			name: "wildcard policy subdomain",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Invalid wildcard policy",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "badwildcard",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "bad.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: "bad-wolf",
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Invalid host for wildcard policy",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "badhost",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Empty host for wildcard policy",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "emptyhost",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Valid headers for response but route's tls termination is passthrough",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationPassthrough,
					},
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: headerNameXFrame,
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "DENY",
										},
									},
								},
								{
									Name: headerNameXSS,
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "1;mode=block",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Valid headers for request but route's tls termination is passthrough",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationPassthrough,
					},
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "Accept",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "text/plain,text/html",
										},
									},
								},
								{
									Name: "Accept-Encoding",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Should not exceed more than 20 request items.",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
					},
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: invalidNumRequests,
						},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Should not exceed more than 20 response items.",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
					},
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: invalidNumResponses,
						},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name:           "spec.path should not contain unmatched single quotes when rewrite-target annotation is set",
			route:          routeWithPathAndRewriteAnnotation("/foo'", "foo"),
			expectedErrors: 1,
		},
		{
			name:           "spec.path should not contain unmatched double quotes when rewrite-target annotation is set",
			route:          routeWithPathAndRewriteAnnotation(`/foo"`, "foo"),
			expectedErrors: 1,
		},
		{
			name:           "spec.path should not contain hash symbol when rewrite-target annotation is set",
			route:          routeWithPathAndRewriteAnnotation("/foo#", "foo"),
			expectedErrors: 1,
		},
		{
			name:           "spec.path should not contain new lines when rewrite-target annotation is set",
			route:          routeWithPathAndRewriteAnnotation("/foo\n\r", "foo"),
			expectedErrors: 1,
		},
		{
			name:           "spec.path should not contain an invalid regex with [a-Z] when rewrite-target annotation is set",
			route:          routeWithPathAndRewriteAnnotation("/foo[a-Z]", "foo"),
			expectedErrors: 1,
		},
		{
			name:           "spec.path should not contain an invalid regex with invalid escape when rewrite-target annotation is set",
			route:          routeWithPathAndRewriteAnnotation(`/foo\o`, "foo"),
			expectedErrors: 1,
		},
		{
			name:           "spec.path should can contain an valid regex with + when rewrite-target annotation is set",
			route:          routeWithPathAndRewriteAnnotation("/foo+", "foo"),
			expectedErrors: 0,
		},
		{
			name:           "spec.path can contain an valid regex with [A-z] when rewrite-target annotation is set",
			route:          routeWithPathAndRewriteAnnotation("/foo[A-z]", "foo"),
			expectedErrors: 0,
		},
		{
			name: "spec.path can contain an invalid regex when rewrite-target annotation is NOT set",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					To:   createRouteSpecTo("serviceName", "Service"),
					Path: "/foo[a-Z]",
				},
			},
			expectedErrors: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := ValidateRoute(context.Background(), tc.route, &testSARCreator{allow: false}, &testSecretGetter{}, routecommon.RouteValidationOptions{AllowExternalCertificates: false})
			if len(errs) != tc.expectedErrors {
				t.Errorf("Test case %s expected %d error(s), got %d. %v", tc.name, tc.expectedErrors, len(errs), errs)
			}
		})
	}
}

// TestValidateHeaders verifies that validateHeaders correctly validates
// response and request header actions in the route spec and returns the
// appropriate error messages.
func TestValidateHeaders(t *testing.T) {
	var (
		tooLargeName  = strings.Repeat("x", 256)
		tooLargeValue = strings.Repeat("y", 16385)
	)
	tests := []struct {
		name                 string
		route                *routev1.Route
		expectedErrorMessage string
	}{
		{
			name: "should give an error on attempt to delete the HSTS header.",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "Strict-Transport-Security",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: "spec.httpHeaders.actions.response[0].name: Forbidden: the following headers may not be modified using this API: strict-transport-security, proxy, cookie, set-cookie",
		},
		{
			name: "should give an error on attempt to delete the Proxy header.",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "Proxy",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: "spec.httpHeaders.actions.response[0].name: Forbidden: the following headers may not be modified using this API: strict-transport-security, proxy, cookie, set-cookie",
		},
		{
			name: "should give an error on attempt to delete the Cookie header.",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "Cookie",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: "spec.httpHeaders.actions.request[0].name: Forbidden: the following headers may not be modified using this API: strict-transport-security, proxy, cookie, set-cookie",
		},
		{
			name: "should give an error on attempt to delete the Set-Cookie header.",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "Set-Cookie",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: "spec.httpHeaders.actions.response[0].name: Forbidden: the following headers may not be modified using this API: strict-transport-security, proxy, cookie, set-cookie",
		},
		{
			name: "should give an error when brackets are not closed properly.",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "expires",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%{+Q}[ssl_c_der,base64",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.response[0].action.set.value: Invalid value: "%{+Q}[ssl_c_der,base64": Either header value provided is not in correct format or the converter specified is not allowed. The dynamic header value  may use HAProxy's %[] syntax and otherwise must be a valid HTTP header value as defined in https://datatracker.ietf.org/doc/html/rfc7230#section-3.2 Sample fetchers allowed are res.hdr, ssl_c_der. Converters allowed are lower, base64.`,
		},
		{
			name: "should give an error if the converter in dynamic header value is not permitted.",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "map",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%[res.hdr(host),bogus]",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.response[0].action.set.value: Invalid value: "%[res.hdr(host),bogus]": Either header value provided is not in correct format or the converter specified is not allowed. The dynamic header value  may use HAProxy's %[] syntax and otherwise must be a valid HTTP header value as defined in https://datatracker.ietf.org/doc/html/rfc7230#section-3.2 Sample fetchers allowed are res.hdr, ssl_c_der. Converters allowed are lower, base64.`,
		},
		{
			name: "should give an error when same header name provided more than once",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "X-Frame-Options",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "DENY",
										},
									},
								},
								{
									Name: "X-Server",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
								{
									Name: "X-Frame-Options",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "SAMEORIGIN",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.response[2].name: Duplicate value: "X-Frame-Options"`,
		},
		{
			name: "valid request headers",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "Accept",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "text/plain,text/html",
										},
									},
								},
								{
									Name: "Accept-Encoding",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
								{
									Name: "Conditional",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%[req.hdr(Host)] if foo",
										},
									},
								},
								{
									Name: "Condition",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: `%[req.hdr(Host)]\ if\ foo`,
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: "",
		},
		{
			name: "valid request and response headers",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-request-and-response-headers",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "subdomain.example.test",
					To:   createRouteSpecTo("serviceName", "Service"),
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "x-foo",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%{+Q}[ssl_c_der,base64]",
										},
									},
								},
								{
									Name: "x-bar",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
								{
									Name: "x-baz",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%[req.hdr(Host),lower]",
										},
									},
								},
							},
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "x-foo",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%{+Q}[ssl_c_der,base64]",
										},
									},
								},
								{
									Name: "x-fooby",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
								{
									Name: "x-barby",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%[res.hdr(server),lower]",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: "",
		},
		{
			name: "invalid request and response headers",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-request-and-response-headers",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "subdomain.example.test",
					To:   createRouteSpecTo("serviceName", "Service"),
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "x-foo",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%+Q[ssl_c_der,base64]",
										},
									},
								},
								{
									Name: "x-bar",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
								{
									Name: "x-baz",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%[req.hdr(Host),lower",
										},
									},
								},
							},
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "x-foo",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%{+Q}[ssl_c_der,base64]",
										},
									},
								},
								{
									Name: "x-fooby",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
								{
									Name: "x-barby",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%[res.hdr(server),tolower]",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `[spec.httpHeaders.actions.response[2].action.set.value: Invalid value: "%[res.hdr(server),tolower]": Either header value provided is not in correct format or the converter specified is not allowed. The dynamic header value  may use HAProxy's %[] syntax and otherwise must be a valid HTTP header value as defined in https://datatracker.ietf.org/doc/html/rfc7230#section-3.2 Sample fetchers allowed are res.hdr, ssl_c_der. Converters allowed are lower, base64., spec.httpHeaders.actions.request[0].action.set.value: Invalid value: "%+Q[ssl_c_der,base64]": Either header value provided is not in correct format or the converter specified is not allowed. The dynamic header value  may use HAProxy's %[] syntax and otherwise must be a valid HTTP header value as defined in https://datatracker.ietf.org/doc/html/rfc7230#section-3.2 Sample fetchers allowed are req.hdr, ssl_c_der. Converters allowed are lower, base64., spec.httpHeaders.actions.request[2].action.set.value: Invalid value: "%[req.hdr(Host),lower": Either header value provided is not in correct format or the converter specified is not allowed. The dynamic header value  may use HAProxy's %[] syntax and otherwise must be a valid HTTP header value as defined in https://datatracker.ietf.org/doc/html/rfc7230#section-3.2 Sample fetchers allowed are req.hdr, ssl_c_der. Converters allowed are lower, base64.]`,
		},
		{
			name: "should give an error if the header value exceeds 16384 chars",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "X-SSL-Client-Cert",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: tooLargeValue,
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: fmt.Sprintf("spec.httpHeaders.actions.response[0].action.set.value: Invalid value: %q: value exceeds the maximum length, which is 16384", tooLargeValue),
		},
		{
			name: "should give an error if the header value is 0 chars",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "X-SSL-Client-Cert",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: "spec.httpHeaders.actions.response[0].action.set.value: Required value",
		},
		{
			name: "should give an error if the header name exceeds 1024 chars",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: tooLargeName,
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "foo",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: fmt.Sprintf("spec.httpHeaders.actions.response[0].name: Invalid value: %q: name exceeds the maximum length, which is 255", tooLargeName),
		},
		{
			name: "should give an error if the header name is 0 chars",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "foo",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: "spec.httpHeaders.actions.response[0].name: Required value",
		},
		{
			name: "should give an error if the response header's value has sample fetcher req.hdr",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Response: []routev1.RouteHTTPHeader{
								{
									Name: "X-SSL-Client-Cert",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%[req.hdr(host),lower]",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.response[0].action.set.value: Invalid value: "%[req.hdr(host),lower]": Either header value provided is not in correct format or the converter specified is not allowed. The dynamic header value  may use HAProxy's %[] syntax and otherwise must be a valid HTTP header value as defined in https://datatracker.ietf.org/doc/html/rfc7230#section-3.2 Sample fetchers allowed are res.hdr, ssl_c_der. Converters allowed are lower, base64.`,
		},
		{
			name: "should give an error if the request header's value has converter base_64",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "X-SSL-Client-Cert",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "%[ssl_c_der,base_64]",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.request[0].action.set.value: Invalid value: "%[ssl_c_der,base_64]": Either header value provided is not in correct format or the converter specified is not allowed. The dynamic header value  may use HAProxy's %[] syntax and otherwise must be a valid HTTP header value as defined in https://datatracker.ietf.org/doc/html/rfc7230#section-3.2 Sample fetchers allowed are req.hdr, ssl_c_der. Converters allowed are lower, base64.`,
		},
		{
			name: "should not allow repetition of a header name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcardpolicy",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host:           "subdomain.wildcard.test",
					To:             createRouteSpecTo("serviceName", "Service"),
					WildcardPolicy: routev1.WildcardPolicySubdomain,
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "Accept",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "text/plain,text/html",
										},
									},
								},
								{
									Name: "Accept",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.request[1].name: Duplicate value: "Accept"`,
		},
		{
			name: "set is required when type is Set",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "missing-set-field",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "subdomain.example.test",
					To:   createRouteSpecTo("serviceName", "Service"),
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "Accept",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Set,
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.request[0].action.set: Required value: set is required when type is Set, and forbidden otherwise`,
		},
		{
			name: "set is forbidden when type is not Set",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "missing-set-field",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "subdomain.example.test",
					To:   createRouteSpecTo("serviceName", "Service"),
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "Accept",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
										Set: &routev1.RouteSetHTTPHeader{
											Value: "text/plain,text/html",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.request[0].action.set: Required value: set is required when type is Set, and forbidden otherwise`,
		},
		{
			name: "empty header name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "subdomain.example.test",
					To:   createRouteSpecTo("serviceName", "Service"),
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: "spec.httpHeaders.actions.request[0].name: Required value",
		},
		{
			name: "invalid header name",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-name",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "subdomain.example.test",
					To:   createRouteSpecTo("serviceName", "Service"),
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "foo bar",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: routev1.Delete,
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.request[0].name: Invalid value: "foo bar": name must be a valid HTTP header name as defined in RFC 2616 section 4.2`,
		},
		{
			name: "empty action",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-action",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "subdomain.example.test",
					To:   createRouteSpecTo("serviceName", "Service"),
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "x-foo",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: "",
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.request[0].action.type: Invalid value: "": type must be "Set" or "Delete"`,
		},
		{
			name: "invalid action",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-action",
					Namespace: "foo",
				},
				Spec: routev1.RouteSpec{
					Host: "subdomain.example.test",
					To:   createRouteSpecTo("serviceName", "Service"),
					HTTPHeaders: &routev1.RouteHTTPHeaders{
						Actions: routev1.RouteHTTPHeaderActions{
							Request: []routev1.RouteHTTPHeader{
								{
									Name: "x-foo",
									Action: routev1.RouteHTTPHeaderActionUnion{
										Type: "Replace",
									},
								},
							},
						},
					},
				},
			},
			expectedErrorMessage: `spec.httpHeaders.actions.request[0].action.type: Invalid value: "Replace": type must be "Set" or "Delete"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var allErrs field.ErrorList
			allErrs = append(allErrs, validateHeaders(field.NewPath("spec", "httpHeaders", "actions", "response"), tc.route.Spec.HTTPHeaders.Actions.Response, permittedResponseHeaderValueRE, permittedResponseHeaderValueErrorMessage)...)
			allErrs = append(allErrs, validateHeaders(field.NewPath("spec", "httpHeaders", "actions", "request"), tc.route.Spec.HTTPHeaders.Actions.Request, permittedRequestHeaderValueRE, permittedRequestHeaderValueErrorMessage)...)
			var actualErrorMessage string
			if err := allErrs.ToAggregate(); err != nil {
				actualErrorMessage = err.Error()
			}
			switch {
			case tc.expectedErrorMessage == "" && actualErrorMessage != "":
				t.Fatalf("unexpected error: %v", actualErrorMessage)
			case tc.expectedErrorMessage != "" && actualErrorMessage == "":
				t.Fatalf("got nil, expected %v", tc.expectedErrorMessage)
			case tc.expectedErrorMessage != actualErrorMessage:
				t.Fatalf("unexpected error: %v, expected: %v", actualErrorMessage, tc.expectedErrorMessage)
			}
		})
	}
}

func TestValidateTLS(t *testing.T) {
	tests := []struct {
		name           string
		route          *routev1.Route
		expectedErrors int

		// fields for externalCertificate
		allow  bool
		secret *corev1.Secret
		opts   routecommon.RouteValidationOptions
	}{
		{
			name: "No TLS Termination",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: "",
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Passthrough termination OK",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationPassthrough,
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Reencrypt termination OK with certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						Certificate:              "def",
						Key:                      "ghi",
						CACertificate:            "jkl",
						DestinationCACertificate: "abc",
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Reencrypt termination OK without certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						DestinationCACertificate: "abc",
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Reencrypt termination no dest cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationReencrypt,
						Certificate:   "def",
						Key:           "ghi",
						CACertificate: "jkl",
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Edge termination OK with certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationEdge,
						Certificate:   "abc",
						Key:           "abc",
						CACertificate: "abc",
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Edge termination OK without certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Edge termination, dest cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationEdge,
						DestinationCACertificate: "abc",
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Passthrough termination, cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{Termination: routev1.TLSTerminationPassthrough, Certificate: "test"},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Passthrough termination, key",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{Termination: routev1.TLSTerminationPassthrough, Key: "test"},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Passthrough termination, ca cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{Termination: routev1.TLSTerminationPassthrough, CACertificate: "test"},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Passthrough termination, dest ca cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{Termination: routev1.TLSTerminationPassthrough, DestinationCACertificate: "test"},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "Invalid termination type",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: "invalid",
					},
				},
			},

			expectedErrors: 1,
		},
		{
			name: "Invalid Reencrypt route as externalCertificate and certificate set",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationReencrypt,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
						Certificate: "dummy",
					},
				},
			},
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 1,
		},
		{
			name: "Invalid Edge route as externalCertificate and certificate set",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
						Certificate: "dummy",
					},
				},
			},
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 1,
		},
		{
			name: "Invalid Passthrough route as externalCertificate is set",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationPassthrough,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
					},
				},
			},
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 1,
		},
		{
			name: "Invalid Edge route for externalCertificate as not authorized",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-test",
					Namespace: "sandbox",
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "sandbox",
				},
				Type: corev1.SecretTypeTLS,
			},
			allow:          false,
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 5,
		},
		{
			name: "Invalid Reencrypt route for externalCertificate as not authorized",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-test",
					Namespace: "sandbox",
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationReencrypt,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "sandbox",
				},
				Type: corev1.SecretTypeTLS,
			},
			allow:          false,
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 5,
		},
		{
			name: "Invalid Edge route for externalCertificate as secret not found",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-test",
					Namespace: "sandbox",
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "other-sandbox",
				},
				Type: corev1.SecretTypeTLS,
			},
			allow:          true,
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 1,
		},
		{
			name: "Invalid Reencrypt route for externalCertificate as secret not found",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-test",
					Namespace: "sandbox",
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationReencrypt,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "other-sandbox",
				},
				Type: corev1.SecretTypeTLS,
			},
			allow:          true,
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 1,
		},
		{
			name: "Invalid Edge route for externalCertificate as secret of incorrect type",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-test",
					Namespace: "sandbox",
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "sandbox",
				},
				Type: corev1.SecretTypeBasicAuth,
			},
			allow:          true,
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 1,
		},
		{
			name: "Invalid Reencrypt route for externalCertificate as secret of incorrect type",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-test",
					Namespace: "sandbox",
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationReencrypt,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "sandbox",
				},
				Type: corev1.SecretTypeBasicAuth,
			},
			allow:          true,
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 1,
		},
		{
			name: "Valid Edge route with externalCertificate",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-test",
					Namespace: "sandbox",
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "sandbox",
				},
				Type: corev1.SecretTypeTLS,
			},
			allow:          true,
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 0,
		},
		{
			name: "Valid Reencrypt route with externalCertificate",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-test",
					Namespace: "sandbox",
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationReencrypt,
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "tls-secret",
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "sandbox",
				},
				Type: corev1.SecretTypeTLS,
			},
			allow:          true,
			opts:           routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			expectedErrors: 0,
		},
	}

	ctx := request.WithUser(context.Background(), &user.DefaultInfo{})
	for _, tc := range tests {
		errs := validateTLS(ctx, tc.route, nil, &testSARCreator{allow: tc.allow}, &testSecretGetter{namespace: tc.route.Namespace, secret: tc.secret}, tc.opts)
		if len(errs) != tc.expectedErrors {
			t.Errorf("Test case %s expected %d error(s), got %d. %v", tc.name, tc.expectedErrors, len(errs), errs)
		}
	}
}

func TestValidatePassthroughInsecureEdgeTerminationPolicy(t *testing.T) {

	insecureTypes := map[routev1.InsecureEdgeTerminationPolicyType]bool{
		"": false,
		routev1.InsecureEdgeTerminationPolicyNone:     false,
		routev1.InsecureEdgeTerminationPolicyAllow:    true,
		routev1.InsecureEdgeTerminationPolicyRedirect: false,
		"support HTTPsec": true,
		"or maybe HSTS":   true,
	}

	for key, expected := range insecureTypes {
		route := &routev1.Route{
			Spec: routev1.RouteSpec{
				TLS: &routev1.TLSConfig{
					Termination:                   routev1.TLSTerminationPassthrough,
					InsecureEdgeTerminationPolicy: key,
				},
			},
		}
		route.Spec.TLS.InsecureEdgeTerminationPolicy = key
		errs := validateTLS(context.Background(), route, nil, &testSARCreator{allow: false}, &testSecretGetter{}, routecommon.RouteValidationOptions{})
		if !expected && len(errs) != 0 {
			t.Errorf("Test case for Passthrough termination with insecure=%s got %d errors where none where expected. %v",
				key, len(errs), errs)
		}
		if expected && len(errs) == 0 {
			t.Errorf("Test case for Passthrough termination with insecure=%s got no errors where some where expected.", key)
		}
	}
}

// TestValidateRouteUpdate ensures not specifying a required field results in error and a fully specified
// route passes successfully
func TestValidateRouteUpdate(t *testing.T) {
	tests := []struct {
		name           string
		route          *routev1.Route
		change         func(route *routev1.Route)
		expectedErrors int
	}{
		{
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "bar",
					Namespace:       "foo",
					ResourceVersion: "1",
				},
				Spec: routev1.RouteSpec{
					Host: "host",
					To: routev1.RouteTargetReference{
						Name: "serviceName",
						Kind: "Service",
					},
				},
			},
			change:         func(route *routev1.Route) { route.Spec.Host = "" },
			expectedErrors: 0, // now controlled by rbac
		},
		{
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "bar",
					Namespace:       "foo",
					ResourceVersion: "1",
				},
				Spec: routev1.RouteSpec{
					Host: "host",
					To: routev1.RouteTargetReference{
						Name: "serviceName",
						Kind: "Service",
					},
				},
			},
			change:         func(route *routev1.Route) { route.Spec.Host = "other" },
			expectedErrors: 0, // now controlled by rbac
		},
		{
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "bar",
					Namespace:       "foo",
					ResourceVersion: "1",
				},
				Spec: routev1.RouteSpec{
					Host: "host",
					To: routev1.RouteTargetReference{
						Name: "serviceName",
						Kind: "Service",
					},
				},
			},
			change:         func(route *routev1.Route) { route.Name = "baz" },
			expectedErrors: 1,
		},
		{
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "bar",
					Namespace:       "foo",
					ResourceVersion: "1",
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace-1234567890-1234567890-1234567890-1234567890-12345.test.com",
					To: routev1.RouteTargetReference{
						Name: "serviceName",
						Kind: "Service",
					},
				},
			},
			change: func(route *routev1.Route) {
				route.Spec.Host = "abc.test.com"
			}, // old route was invalid - ignore validation check
			expectedErrors: 0,
		},
		{
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "bar",
					Namespace:       "foo",
					ResourceVersion: "1",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "name-namespace-1234567890-1234567890-1234567890-1234567890-12345.test.com",
					To: routev1.RouteTargetReference{
						Name: "serviceName",
						Kind: "Service",
					},
				},
			},
			change: func(route *routev1.Route) {
				route.Spec.Host = "abc.test.com"
			}, // old route was invalid - ignore validation check even if annoatation is set
			expectedErrors: 0,
		},
		{
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "bar",
					Namespace:       "foo",
					ResourceVersion: "1",
					Annotations: map[string]string{
						routev1.AllowNonDNSCompliantHostAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "abc.test.com",
					To: routev1.RouteTargetReference{
						Name: "serviceName",
						Kind: "Service",
					},
				},
			},
			change: func(route *routev1.Route) {
				route.Spec.Host = "name-namespace-1234567890-1234567890-1234567890-1234567890-12345.test.com"
			}, // new route is invalid - skip check as annotation is set
			expectedErrors: 0,
		},
		{
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "bar",
					Namespace:       "foo",
					ResourceVersion: "1",
				},
				Spec: routev1.RouteSpec{
					Host: "abc.test.com",
					To: routev1.RouteTargetReference{
						Name: "serviceName",
						Kind: "Service",
					},
				},
			},
			change: func(route *routev1.Route) {
				route.Spec.Host = "name-namespace-1234567890-1234567890-1234567890-1234567890-12345.test.com"
			}, // new route is invalid - do labels check
			expectedErrors: 1,
		},
	}

	for i, tc := range tests {
		newRoute := tc.route.DeepCopy()
		tc.change(newRoute)
		errs := ValidateRouteUpdate(context.Background(), newRoute, tc.route, &testSARCreator{allow: false}, &testSecretGetter{}, routecommon.RouteValidationOptions{})
		if len(errs) != tc.expectedErrors {
			t.Errorf("%d: expected %d error(s), got %d. %v", i, tc.expectedErrors, len(errs), errs)
		}
	}
}

// This unit test tests the Route header regex for validating user input.
func TestPermittedHeaderRegexp(t *testing.T) {
	// The syntax is http-request set-header <name> <fmt>. As per this http://cbonte.github.io/haproxy-dconv/2.6/configuration.html#4.2-http-request%20add-header
	// the format  follows the log-format rules (see Custom Log Format in section 8.2.4) i.e http://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.4
	// The usage of it shall be as per section 8.2.6
	// However for dynamic values, req.hdr, res.hdr, ssl_c_der are the allowed fetchers and lower, base64 are the allowed converters.
	type HeaderValueTest struct {
		description string
		validInput  bool
		input       string
	}

	tests := []HeaderValueTest{
		{description: "empty value", input: ``, validInput: false},
		{description: "single character", input: `a`, validInput: true},
		{description: "multiple characters", input: `abc`, validInput: true},
		{description: "multiple words without escaped space", input: `abc def`, validInput: true},
		{description: "multiple words with escaped space", input: `abc\ def`, validInput: true},
		{description: "multiple words each word quoted", input: `"abc"\ "def"`, validInput: true},
		{description: "multiple words each word quoted and with an embedded space", input: `"abc "\ "def "`, validInput: true},
		{description: "multiple words each word one double quoted and other single quoted and with an embedded space", input: `"abc "\ 'def '`, validInput: true},
		{description: "single % character", input: `%`, validInput: false},
		{description: "escaped % character", input: `%%`, validInput: true},
		{description: "escaped % and only a % character", input: `%%%`, validInput: false},
		{description: "two literal % characters", input: `%%%%`, validInput: true},
		{description: "zero percent", input: `%%%%%%0`, validInput: true},
		{description: "escaped expression", input: `%%[XYZ.hdr(Host)]\ %[XYZ.hdr(Host)]`, validInput: true},
		{description: "simple empty expression", input: `%[]`, validInput: false},
		{description: "nested empty expressions", input: `%[%[]]`, validInput: false},
		{description: "empty quoted value", input: `%{+Q}`, validInput: false},
		{description: "quoted value", input: `%{+Q}foo`, validInput: false},
		{description: "quoted value", input: `%{+Q} ssl_c_der`, validInput: false},
		{description: "valid input", input: `{+Q}[ssl_c_der,base64]`, validInput: true},
		{description: "valid input", input: `%{+Q}[ssl_c_der,base64]`, validInput: true},

		{description: "hdr with empty field", input: `%[XYZ.hdr()]`, validInput: false},
		{description: "hdr with percent field", input: `%[XYZ.hdr(%)]`, validInput: false},
		{description: "hdr with known field", input: `%[XYZ.hdr(Host)]`, validInput: true},
		{description: "hdr with syntax error", input: `%[XYZ.hdr(Host]`, validInput: false},

		{description: "hdr with valid X-XSS-Protection value", input: `1;mode=block`, validInput: true},
		{description: "hdr with valid Content-Type value", input: `text/plain,text/html`, validInput: true},

		{description: "incomplete expression", input: `%[req`, validInput: false},
		{description: "quoted field", input: `%[XYZ.hdr(%{+Q}Host)]`, validInput: false},

		// If the value has "if foo" in it, the string "if foo" will be taken literally as part of the value.
		// The router will quote the entire value so that the "if foo" is not interpreted as a conditional.
		{description: "value with conditional expression", input: `%[XYZ.hdr(Host)] if foo`, validInput: true},
		{description: "value with what looks like a conditional expression", input: `%[XYZ.hdr(Host)]\ if\ foo`, validInput: true},

		{description: "unsupported fetcher and converter", input: `%[date(3600),http_date]`, validInput: false},
		{description: "not allowed sample fetchers", input: `%[foo,lower]`, validInput: false},
		{description: "not allowed converters", input: `%[req.hdr(host),foo]`, validInput: false},
		{description: "missing parentheses or braces `}`", input: `%{Q[req.hdr(host)]`, validInput: false},
		{description: "missing parentheses or braces `{`", input: `%Q}[req.hdr(host)]`, validInput: false},
		{description: "missing parentheses or braces `}`", input: `%{{Q}[req.hdr(host)]`, validInput: false},
		{description: "missing parentheses or braces `]`", input: `%[req.hdr(host)`, validInput: false},
		{description: "missing parentheses or braces `[`", input: `%req.hdr(host)]`, validInput: false},
		{description: "missing parentheses or braces `(`", input: `%[req.hdrhost)]`, validInput: false},
		{description: "missing parentheses or braces `)`", input: `%[req.hdr(host]`, validInput: false},
		{description: "missing parentheses or braces `)]`", input: `%[req.hdr(host`, validInput: false},
		{description: "missing parentheses or braces `[]`", input: `%{req.hdr(host)}`, validInput: false},
		{description: "parameters for a sample fetcher that doesn't take parameters", input: `%[ssl_c_der(host)]`, validInput: false},
		{description: "dangerous sample fetchers and converters", input: `%[env(FOO)]`, validInput: false},
		{description: "dangerous sample fetchers and converters", input: `%[req.hdr(host),debug()]`, validInput: false},
		{description: "extra comma", input: `%[req.hdr(host),,lower]`, validInput: false},

		// CR and LF are not allowed in header value as per RFC https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.4
		{description: "carriage return", input: "\r", validInput: false},
		{description: "CRLF", input: "\r\n", validInput: false},

		// HAProxy does not interpret ${} syntax, so it is safe to have ${ in the value; it will be taken
		// literally as part of the header value.
		{description: "environment variable with a bracket missing", input: `${NET_COOLOCP_HOSTPRIMARY`, validInput: true},
		{description: "value with conditional expression and env var", input: `%[XYZ.hdr(Host)] if ${NET_COOLOCP_HOSTPRIMARY`, validInput: true},
		{description: "value with what looks like a conditional expression and env var", input: `%[XYZ.hdr(Host)]\ if\ ${NET_COOLOCP_HOSTPRIMARY`, validInput: true},

		{description: "sample value", input: `%ci:%cp [%tr] %ft %ac/%fc %[fc_err]/%[ssl_fc_err,hex]/%[ssl_c_err]/%[ssl_c_ca_err]/%[ssl_fc_is_resumed] %[ssl_fc_sni]/%sslv/%sslc`, validInput: false},
		{description: "interpolation of T i.e %T", input: `%T`, validInput: false},

		// url
		// regex does not check validity of url in a header value.
		{description: "hdr with url", input: `http:??//url/hack`, validInput: true},

		// spaces and tab
		// regex allows spaces before and after. The reason is that after a dynamic value is provided someone might provide a condition `%[XYZ.hdr(Host)] if foo` which would have
		// spaces after the dynamic value and if condition.
		// tab is rejected as control characters are not allowed by the regex.
		{description: "space before and after the value", input: ` T `, validInput: true},
		{description: "double space before and after the value", input: `  T  `, validInput: true},
		{description: "tab before and after the value", input: "\tT\t", validInput: false},
	}

	var requestTypes = []struct {
		description          string
		regexp               *regexp.Regexp
		testInputSubstituter func(s string) string
	}{{
		description:          "request",
		regexp:               permittedRequestHeaderValueRE,
		testInputSubstituter: func(s string) string { return strings.ReplaceAll(s, "XYZ", "req") },
	}, {
		description:          "response",
		regexp:               permittedResponseHeaderValueRE,
		testInputSubstituter: func(s string) string { return strings.ReplaceAll(s, "XYZ", "res") },
	}}

	for _, rt := range requestTypes {
		t.Run(rt.description, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.description, func(t *testing.T) {
					input := rt.testInputSubstituter(tc.input)
					if got := rt.regexp.MatchString(input); got != tc.validInput {
						t.Errorf("%q: expected %v, got %t", input, tc.validInput, got)
					}
				})
			}
		})
	}
}

func TestValidateInsecureEdgeTerminationPolicy(t *testing.T) {
	tests := []struct {
		name           string
		insecure       routev1.InsecureEdgeTerminationPolicyType
		expectedErrors int
	}{
		{
			name:           "empty insecure option",
			insecure:       "",
			expectedErrors: 0,
		},
		{
			name:           "foobar insecure option",
			insecure:       "foobar",
			expectedErrors: 1,
		},
		{
			name:           "insecure option none",
			insecure:       routev1.InsecureEdgeTerminationPolicyNone,
			expectedErrors: 0,
		},
		{
			name:           "insecure option allow",
			insecure:       routev1.InsecureEdgeTerminationPolicyAllow,
			expectedErrors: 0,
		},
		{
			name:           "insecure option redirect",
			insecure:       routev1.InsecureEdgeTerminationPolicyRedirect,
			expectedErrors: 0,
		},
		{
			name:           "insecure option other",
			insecure:       "something else",
			expectedErrors: 1,
		},
	}

	for _, tc := range tests {
		route := &routev1.Route{
			Spec: routev1.RouteSpec{
				TLS: &routev1.TLSConfig{
					Termination:                   routev1.TLSTerminationEdge,
					InsecureEdgeTerminationPolicy: tc.insecure,
				},
			},
		}
		errs := validateTLS(context.Background(), route, nil, &testSARCreator{allow: false}, &testSecretGetter{}, routecommon.RouteValidationOptions{})

		if len(errs) != tc.expectedErrors {
			t.Errorf("Test case %s expected %d error(s), got %d. %v", tc.name, tc.expectedErrors, len(errs), errs)
		}
	}
}

func TestValidateEdgeReencryptInsecureEdgeTerminationPolicy(t *testing.T) {
	tests := []struct {
		name  string
		route *routev1.Route
	}{
		{
			name: "Reencrypt termination",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						DestinationCACertificate: "dca",
					},
				},
			},
		},
		{
			name: "Reencrypt termination DestCACert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						DestinationCACertificate: testDestinationCACertificate,
					},
				},
			},
		},
		{
			name: "Edge termination",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
					},
				},
			},
		},
	}

	insecureTypes := map[routev1.InsecureEdgeTerminationPolicyType]bool{
		routev1.InsecureEdgeTerminationPolicyNone:     false,
		routev1.InsecureEdgeTerminationPolicyAllow:    false,
		routev1.InsecureEdgeTerminationPolicyRedirect: false,
		"support HTTPsec": true,
		"or maybe HSTS":   true,
	}

	for _, tc := range tests {
		for key, expected := range insecureTypes {
			tc.route.Spec.TLS.InsecureEdgeTerminationPolicy = key
			errs := validateTLS(context.Background(), tc.route, nil, &testSARCreator{allow: false}, &testSecretGetter{}, routecommon.RouteValidationOptions{})
			if !expected && len(errs) != 0 {
				t.Errorf("Test case %s with insecure=%s got %d errors where none were expected. %v",
					tc.name, key, len(errs), errs)
			}
			if expected && len(errs) == 0 {
				t.Errorf("Test case %s  with insecure=%s got no errors where some were expected.", tc.name, key)
			}
		}
	}
}

func TestWarnings(t *testing.T) {
	for _, tc := range []struct {
		name                string
		host                string
		subdomain           string
		path                string
		rewriteTargetExists bool
		expected            []string
	}{
		{
			name:      "both host and subdomain set",
			host:      "foo",
			subdomain: "bar",
			expected:  []string{"spec.host is set; spec.subdomain may be ignored"},
		},
		{
			name: "only host set",
			host: "foo",
		},
		{
			name:      "only subdomain set",
			subdomain: "bar",
		},
		{
			name: "both host and subdomain unset",
		},
		{
			name:                "no-warning path with rewrite-target annotation",
			path:                "/foo",
			rewriteTargetExists: true,
			expected:            []string{},
		},
		{
			name:                "warning path with single quotes with rewrite-target annotation",
			path:                "/'foo'",
			rewriteTargetExists: true,
			expected:            []string{"spec.path contains a ' haproxy.router.openshift.io/rewrite-target may produce an unexpected result"},
		},
		{
			name:                "warning path with double quotes with rewrite-target annotation",
			path:                `/"foo"`,
			rewriteTargetExists: true,
			expected:            []string{"spec.path contains a \" haproxy.router.openshift.io/rewrite-target may produce an unexpected result"},
		},
		{
			name:                "warning path with regex meta character with rewrite-target annotation",
			path:                "/foo$",
			rewriteTargetExists: true,
			expected:            []string{"spec.path contains regex meta characters, haproxy.router.openshift.io/rewrite-target may provide an unexpected result"},
		},
		{
			name:                "no-warning path with hash character with rewrite-target annotation (will be rejected)",
			path:                "/foo#",
			rewriteTargetExists: true,
			expected:            []string{},
		},
		{
			name:                "no-warning path with regex meta character without rewrite-target annotation",
			path:                "/foo^",
			rewriteTargetExists: false,
			expected:            []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := &routev1.Route{
				Spec: routev1.RouteSpec{
					Path:      tc.path,
					Host:      tc.host,
					Subdomain: tc.subdomain,
				},
			}
			if tc.rewriteTargetExists {
				route.Annotations = map[string]string{
					"haproxy.router.openshift.io/rewrite-target": "foo",
				}
			}
			actual := Warnings(route)
			if len(actual) != len(tc.expected) {
				t.Fatalf("expected %#v, got %#v", tc.expected, actual)
			}
			for i := range actual {
				if actual[i] != tc.expected[i] {
					t.Fatalf("expected %#v, got %#v", tc.expected, actual)
				}
			}
		})
	}
}

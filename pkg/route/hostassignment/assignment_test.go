package hostassignment

import (
	"context"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/route"
)

type testAllocator struct {
}

func (t testAllocator) GenerateHostname(*routev1.Route) (string, error) {
	return "mygeneratedhost.com", nil
}

type testSAR struct {
	allow bool
	err   error
	sar   *authorizationv1.SubjectAccessReview
}

func (t *testSAR) Create(_ context.Context, subjectAccessReview *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error) {
	t.sar = subjectAccessReview
	return &authorizationv1.SubjectAccessReview{
		Status: authorizationv1.SubjectAccessReviewStatus{
			Allowed: t.allow,
		},
	}, t.err
}

func TestHostWithWildcardPolicies(t *testing.T) {
	ctx := request.NewContext()
	ctx = request.WithUser(ctx, &user.DefaultInfo{Name: "bob"})

	tests := []struct {
		name          string
		host, oldHost string

		subdomain, oldSubdomain string

		wildcardPolicy routev1.WildcardPolicyType
		tls, oldTLS    *routev1.TLSConfig

		expected          string
		expectedSubdomain string

		// field for externalCertificate
		opts route.RouteValidationOptions

		errs  int
		allow bool
	}{
		{
			name:     "no-host-empty-policy",
			expected: "mygeneratedhost.com",
			allow:    true,
		},
		{
			name:           "no-host-nopolicy",
			wildcardPolicy: routev1.WildcardPolicyNone,
			expected:       "mygeneratedhost.com",
			allow:          true,
		},
		{
			name:           "no-host-wildcard-subdomain",
			wildcardPolicy: routev1.WildcardPolicySubdomain,
			expected:       "",
			allow:          true,
			errs:           0,
		},
		{
			name:     "host-empty-policy",
			host:     "empty.policy.test",
			expected: "empty.policy.test",
			allow:    true,
		},
		{
			name:           "host-no-policy",
			host:           "no.policy.test",
			wildcardPolicy: routev1.WildcardPolicyNone,
			expected:       "no.policy.test",
			allow:          true,
		},
		{
			name:           "host-wildcard-subdomain",
			host:           "wildcard.policy.test",
			wildcardPolicy: routev1.WildcardPolicySubdomain,
			expected:       "wildcard.policy.test",
			allow:          true,
		},
		{
			name:           "custom-host-permission-denied",
			host:           "another.test",
			expected:       "another.test",
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "tls-permission-denied-destination",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationReencrypt, DestinationCACertificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "tls-permission-denied-cert",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "tls-permission-denied-ca-cert",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, CACertificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "tls-permission-denied-key",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Key: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "no-host-but-allowed",
			expected:       "mygeneratedhost.com",
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
		},
		{
			name:           "update-changed-host-denied",
			host:           "new.host",
			expected:       "new.host",
			oldHost:        "original.host",
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "update-changed-host-allowed",
			host:           "new.host",
			expected:       "new.host",
			oldHost:        "original.host",
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          true,
			errs:           0,
		},
		{
			name:              "update-changed-subdomain-denied",
			subdomain:         "new.host",
			expectedSubdomain: "new.host",
			oldSubdomain:      "original.host",
			wildcardPolicy:    routev1.WildcardPolicyNone,
			allow:             false,
			errs:              1,
		},
		{
			name:              "update-changed-subdomain-allowed",
			subdomain:         "new.host",
			expectedSubdomain: "new.host",
			oldSubdomain:      "original.host",
			wildcardPolicy:    routev1.WildcardPolicyNone,
			allow:             true,
			errs:              0,
		},
		{
			name:           "key-unchanged",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Key: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Key: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           0,
		},
		{
			name:           "key-changed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Key: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Key: "b"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "certificate-unchanged",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           0,
		},
		{
			name:           "certificate-changed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "b"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "no-certificate-changed-to-external-certificate-denied",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "b"}},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,

			opts: route.RouteValidationOptions{AllowExternalCertificates: true},
		},
		{
			name:           "no-certificate-changed-to-external-certificate-allowed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "b"}},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          true,
			errs:           0,

			opts: route.RouteValidationOptions{AllowExternalCertificates: true},
		},
		{
			name:           "external-certificate-changed-to-certificate-denied",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "b"}},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           2,

			opts: route.RouteValidationOptions{AllowExternalCertificates: true},
		},
		{
			name:           "external-certificate-changed-to-certificate-allowed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "b"}},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          true,
			errs:           0,

			opts: route.RouteValidationOptions{AllowExternalCertificates: true},
		},
		{
			name:           "certificate-changed-to-external-certificate-denied",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "b"}},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           2,

			opts: route.RouteValidationOptions{AllowExternalCertificates: true},
		},
		{
			name:           "certificate-changed-to-external-certificate-allowed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "b"}},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          true,
			errs:           0,

			opts: route.RouteValidationOptions{AllowExternalCertificates: true},
		},
		{
			name:     "certificate-changed-to-external-certificate-allowed-but-featuregate-is-not-set",
			host:     "host",
			expected: "host",
			oldHost:  "host",
			// if the featuregate was disabled, and ExternalCertificate wasn't previously set, apiserver will strip ExternalCertificate field.
			// https://github.com/openshift/openshift-apiserver/blob/1fac5e7e3a6153efae875185af2dba48fbad41ab/pkg/route/apiserver/registry/route/strategy.go#L73-L93
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: nil},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Certificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          true,
			errs:           0,

			opts: route.RouteValidationOptions{AllowExternalCertificates: false},
		},
		{
			name:           "external-certificate-changed-denied",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "a"}},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "old-b"}},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,

			opts: route.RouteValidationOptions{AllowExternalCertificates: true},
		},
		{
			name:           "external-certificate-changed-allowed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "a"}},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "old-b"}},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          true,
			errs:           0,

			opts: route.RouteValidationOptions{AllowExternalCertificates: true},
		},
		{
			name:           "external-certificate-secret-unchanged",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "a"}},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, ExternalCertificate: &routev1.LocalObjectReference{Name: "a"}},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           0,

			opts: route.RouteValidationOptions{AllowExternalCertificates: true},
		},
		{
			name:           "ca-certificate-unchanged",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, CACertificate: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, CACertificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           0,
		},
		{
			name:           "ca-certificate-changed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, CACertificate: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, CACertificate: "b"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "key-unchanged",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Key: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Key: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           0,
		},
		{
			name:           "key-changed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Key: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge, Key: "b"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "destination-ca-certificate-unchanged",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationReencrypt, DestinationCACertificate: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationReencrypt, DestinationCACertificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           0,
		},
		{
			name:           "destination-ca-certificate-changed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationReencrypt, DestinationCACertificate: "a"},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationReencrypt, DestinationCACertificate: "b"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
		{
			name:           "set-to-edge-changed",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge},
			oldTLS:         nil,
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           0,
		},
		{
			name:           "cleared-edge",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            nil,
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationEdge},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           0,
		},
		{
			name:           "removed-certificate",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationReencrypt},
			oldTLS:         &routev1.TLSConfig{Termination: routev1.TLSTerminationReencrypt, Certificate: "a"},
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           0,
		},
		{
			name:           "added-certificate-and-fails",
			host:           "host",
			expected:       "host",
			oldHost:        "host",
			tls:            &routev1.TLSConfig{Termination: routev1.TLSTerminationReencrypt, Certificate: "a"},
			oldTLS:         nil,
			wildcardPolicy: routev1.WildcardPolicyNone,
			allow:          false,
			errs:           1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			route := &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "wildcard",
					Name:            tc.name,
					UID:             types.UID("wild"),
					ResourceVersion: "1",
				},
				Spec: routev1.RouteSpec{
					Host:           tc.host,
					Subdomain:      tc.subdomain,
					WildcardPolicy: tc.wildcardPolicy,
					TLS:            tc.tls,
					To: routev1.RouteTargetReference{
						Name: "test",
						Kind: "Service",
					},
				},
			}

			var errs field.ErrorList
			if len(tc.oldHost) > 0 || len(tc.oldSubdomain) > 0 || tc.oldTLS != nil {
				oldRoute := &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:       "wildcard",
						Name:            tc.name,
						UID:             types.UID("wild"),
						ResourceVersion: "1",
					},
					Spec: routev1.RouteSpec{
						Host:           tc.oldHost,
						Subdomain:      tc.oldSubdomain,
						WildcardPolicy: tc.wildcardPolicy,
						TLS:            tc.oldTLS,
						To: routev1.RouteTargetReference{
							Name: "test",
							Kind: "Service",
						},
					},
				}
				errs = ValidateHostUpdate(ctx, route, oldRoute, &testSAR{allow: tc.allow}, tc.opts)
			} else {
				errs = AllocateHost(ctx, route, &testSAR{allow: tc.allow}, testAllocator{}, tc.opts)
			}

			if route.Spec.Host != tc.expected {
				t.Fatalf("expected host %s, got %s", tc.expected, route.Spec.Host)
			}
			if route.Spec.Subdomain != tc.expectedSubdomain {
				t.Fatalf("expected subdomain %s, got %s", tc.expectedSubdomain, route.Spec.Subdomain)
			}
			if len(errs) != tc.errs {
				t.Fatalf("expected %d errors, got %d: %v", tc.errs, len(errs), errs)
			}
		})
	}
}

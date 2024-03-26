package hostassignment

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	routev1 "github.com/openshift/api/route/v1"
	routecommon "github.com/openshift/library-go/pkg/route"
)

func TestValidateHostExternalCertificate(t *testing.T) {
	tests := []struct {
		name  string
		ctx   context.Context
		new   *routev1.Route
		old   *routev1.Route
		allow bool
		opts  routecommon.RouteValidationOptions
		want  field.ErrorList
	}{
		{
			name: "Updating new route and old route with nil TLS",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{},
			},
			allow: false,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want:  nil,
		},
		{
			name: "Updating new route with nil TLS",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Certificate: "old-cert",
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{},
			},
			allow: false,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want:  nil,
		},
		{
			name: "Updating new route with certificate from nil TLS",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Certificate: "new-cert",
					},
				},
			},
			allow: false,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want:  nil,
		},
		{
			name: "Updating new route with externalCertificate from nil TLS without permission",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "dummy-cert",
						},
					},
				},
			},
			allow: false,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want: field.ErrorList{
				field.Forbidden(nil, "somedetail"),
				field.Forbidden(nil, "somedetail"),
			},
		},
		{
			name: "Updating new route with externalCertificate from nil TLS with permission",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "dummy-cert",
						},
					},
				},
			},
			allow: true,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want:  nil,
		},
		{
			name: "Updating new route with nil TLS from externalCertificate without permission",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "dummy-cert",
						},
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{},
			},
			allow: false,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want: field.ErrorList{
				field.Forbidden(nil, "somedetail"),
				field.Forbidden(nil, "somedetail"),
			},
		},
		{
			name: "Updating new route with nil TLS from externalCertificate with permission",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "dummy-cert",
						},
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{},
			},
			allow: true,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want:  nil,
		},
		{
			name: "Updating new route with externalCertificate from old certificate without permissions",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Certificate: "old-cert",
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "dummy-cert",
						},
					},
				},
			},
			allow: false,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want: field.ErrorList{
				field.Forbidden(nil, "somedetail"),
				field.Forbidden(nil, "somedetail"),
			},
		},
		{
			name: "Updating new route with externalCertificate from old certificate with permissions",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Certificate: "old-cert",
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "dummy-cert",
						},
					},
				},
			},
			allow: true,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want:  nil,
		},
		{
			name: "Updating new route to certificate from old externalCertificate without permissions",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "dummy-cert",
						},
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Certificate: "new-cert",
					},
				},
			},
			allow: false,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want: field.ErrorList{
				field.Forbidden(nil, "somedetail"),
				field.Forbidden(nil, "somedetail"),
			},
		},
		{
			name: "Updating new route to certificate from old externalCertificate with permissions",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "dummy-cert",
						},
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Certificate: "new-cert",
					},
				},
			},
			allow: true,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want:  nil,
		},
		{
			name: "Updating new route to externalCertificate from old externalCertificate without permissions",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "old-cert",
						},
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "new-cert",
						},
					},
				},
			},
			allow: false,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want: field.ErrorList{
				field.Forbidden(nil, "somedetail"),
				field.Forbidden(nil, "somedetail"),
			},
		},
		{
			name: "Updating new route to externalCertificate from old externalCertificate with permissions",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "old-cert",
						},
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "new-cert",
						},
					},
				},
			},
			allow: true,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			want:  nil,
		},
		{
			name: "Updating new route to certificate from externalCertificate when feature gate is off and no permission",
			ctx:  request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
			old: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						ExternalCertificate: &routev1.LocalObjectReference{
							Name: "dummy-cert",
						},
					},
				},
			},
			new: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Certificate: "new-cert",
					},
				},
			},
			allow: false,
			opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: false},
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := cmpopts.IgnoreFields(field.Error{}, "Field", "BadValue", "Detail")
			if got := ValidateHostExternalCertificate(tt.ctx, tt.new, tt.old, &testSAR{allow: tt.allow}, tt.opts); !cmp.Equal(got, tt.want, opts, cmpopts.EquateEmpty()) {
				t.Errorf("ValidateHostExternalCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

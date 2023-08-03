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

	type args struct {
		ctx   context.Context
		new   *routev1.Route
		older *routev1.Route
		allow bool
		opts  routecommon.RouteValidationOptions
	}
	tests := []struct {
		name string
		args args
		want field.ErrorList
	}{
		{
			name: "Updating new route and old route with nil TLS",
			args: args{
				ctx: request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
				new: &routev1.Route{
					Spec: routev1.RouteSpec{},
				},
				older: &routev1.Route{
					Spec: routev1.RouteSpec{},
				},
				allow: false,
				opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			},
			want: field.ErrorList{},
		},
		{
			name: "Updating new route with nil TLS",
			args: args{
				ctx: request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
				new: &routev1.Route{
					Spec: routev1.RouteSpec{},
				},
				older: &routev1.Route{
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Certificate: "old-cert",
						},
					},
				},
				allow: false,
				opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			},
			want: field.ErrorList{},
		},
		{
			name: "Updating route from externalCertificate to certificate without permissions",
			args: args{
				ctx: request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
				new: &routev1.Route{
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							ExternalCertificate: &routev1.LocalObjectReference{
								Name: "dummy-cert",
							},
						},
					},
				},
				older: &routev1.Route{
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Certificate: "old-cert",
						},
					},
				},
				allow: false,
				opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			},
			want: field.ErrorList{
				field.Forbidden(nil, "somedetail"),
				field.Forbidden(nil, "somedetail"),
			},
		},
		{
			name: "Updating route from externalCertificate to certificate without permissions",
			args: args{
				ctx: request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
				new: &routev1.Route{
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							ExternalCertificate: &routev1.LocalObjectReference{
								Name: "dummy-cert",
							},
						},
					},
				},
				older: &routev1.Route{
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Certificate: "old-cert",
						},
					},
				},
				allow: false,
				opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			},
			want: field.ErrorList{
				field.Forbidden(nil, "somedetail"),
				field.Forbidden(nil, "somedetail"),
			},
		},
		{
			name: "Updating route from certificate to externalCertificate without permissions",
			args: args{
				ctx: request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
				older: &routev1.Route{
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
							Certificate: "old-cert",
						},
					},
				},
				allow: false,
				opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			},
			want: field.ErrorList{
				field.Forbidden(nil, "somedetail"),
				field.Forbidden(nil, "somedetail"),
			},
		},
		{
			name: "Updating route from certificate to externalCertificate with permissions",
			args: args{
				ctx: request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
				older: &routev1.Route{
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
							Certificate: "old-cert",
						},
					},
				},
				allow: true,
				opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: true},
			},
			want: field.ErrorList{},
		},
		{
			name: "Updating route from certificate to externalCertificate when feature gate is off and no permission",
			args: args{
				ctx: request.WithUser(context.Background(), &user.DefaultInfo{Name: "user1"}),
				older: &routev1.Route{
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
							Certificate: "old-cert",
						},
					},
				},
				allow: false,
				opts:  routecommon.RouteValidationOptions{AllowExternalCertificates: false},
			},
			want: field.ErrorList{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := cmpopts.IgnoreFields(field.Error{}, "Field", "BadValue", "Detail")
			if got := ValidateHostExternalCertificate(tt.args.ctx, tt.args.new, tt.args.older, &testSAR{allow: tt.args.allow}, tt.args.opts); !cmp.Equal(got, tt.want, opts, cmpopts.EquateEmpty()) {
				t.Errorf("ValidateHostExternalCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

package route

import (
	"context"
	"fmt"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/endpoints/request"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/authorization/authorizationutil"
)

// Registry is an interface for performing subject access reviews
type SubjectAccessReviewCreator interface {
	Create(ctx context.Context, sar *authorizationv1.SubjectAccessReview, opts metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error)
}

// routeValidationOptions used to tweak how/what fields are validated. These
// options are propagated by the apiserver.
type RouteValidationOptions struct {

	// allowExternalCertificates option is set when RouteExternalCertificate
	// feature gate is enabled on the apiserver.
	AllowExternalCertificates bool
}

func CheckRouteCustomHostSAR(ctx context.Context, fldPath *field.Path, sarc SubjectAccessReviewCreator) field.ErrorList {

	var errs field.ErrorList
	user, ok := request.UserFrom(ctx)
	if !ok {
		return field.ErrorList{field.InternalError(fldPath, fmt.Errorf("unable to verify access"))}
	}

	if err := authorizationutil.Authorize(sarc, user, &authorizationv1.ResourceAttributes{
		Namespace:   request.NamespaceValue(ctx),
		Verb:        "create",
		Group:       routev1.GroupName,
		Resource:    "routes",
		Subresource: "custom-host",
	}); err != nil {
		errs = append(errs, field.Forbidden(fldPath, "user does not have create permission on custom-host"))
	}

	if err := authorizationutil.Authorize(sarc, user, &authorizationv1.ResourceAttributes{
		Namespace:   request.NamespaceValue(ctx),
		Verb:        "update",
		Group:       routev1.GroupName,
		Resource:    "routes",
		Subresource: "custom-host",
	}); err != nil {
		errs = append(errs, field.Forbidden(fldPath, "user does not have update permission on custom-host"))
	}

	return errs
}

package hostassignment

import (
	"context"

	"k8s.io/apimachinery/pkg/util/validation/field"

	routev1 "github.com/openshift/api/route/v1"
	routecommon "github.com/openshift/library-go/pkg/route"
)

// validateHostExternalCertificate checks if the user has permissions to create and update
// custom-host subresource of routes. This check is required to be done prior to ValidateHostUpdate()
// since updating hosts while using externalCertificate is contingent on the user having both these
// permissions. The ValidateHostUpdate() cannot differentiate if the certificate has changed since
// now the certificates will be present as a secret object, due to this it proceeds with the assumtion
// that the certificate has changed when the route has externalCertificate set.
func ValidateHostExternalCertificate(ctx context.Context, new, older *routev1.Route, sarc routecommon.SubjectAccessReviewCreator, opts routecommon.RouteValidationOptions) field.ErrorList {
	newTLS := new.Spec.TLS
	oldTLS := older.Spec.TLS

	if !opts.AllowExternalCertificates {
		// return nil since if the feature gate is off
		// ValidateHostUpdate() is sufficient to validate
		// permissions
		return nil
	}

	fldPath := field.NewPath("spec", "TLS", "externalCertificate")
	var errs field.ErrorList
	if (newTLS != nil && newTLS.ExternalCertificate != nil) || (oldTLS != nil && oldTLS.ExternalCertificate != nil) {
		errs = append(errs, routecommon.CheckRouteCustomHostSAR(ctx, fldPath, sarc)...)
	}

	return errs
}

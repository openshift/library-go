package resourceapply

import (
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/manifest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

type manifestFeatureSetChecker struct {
	featureGateLister configv1listers.FeatureGateLister
}

func NewManifestFeatureSetChecker(featureGateLister configv1listers.FeatureGateLister) ManifestConditionalFunction {
	return manifestFeatureSetChecker{featureGateLister: featureGateLister}.DoesManifestHaveRequiredFeatureSet
}

func (c manifestFeatureSetChecker) DoesManifestHaveRequiredFeatureSet(obj runtime.Object) (bool, error) {
	requiredFeatureSet := ""
	featureGate, err := c.featureGateLister.Get("cluster")
	switch {
	case apierrors.IsNotFound(err):
		// do nothing, if there's no featureset, this is correct
	case err != nil:
		return false, err
	default:
		requiredFeatureSet = string(featureGate.Spec.FeatureSet)
	}

	metadata, err := meta.Accessor(obj)
	if err != nil {
		return false, err // this will mean something else will likely fail and report a better message.
	}
	matches, err := manifest.ResourceSatisfiesFeatureSetRequirement(requiredFeatureSet, metadata.GetAnnotations())
	if err != nil {
		return false, err
	}

	return matches, nil
}

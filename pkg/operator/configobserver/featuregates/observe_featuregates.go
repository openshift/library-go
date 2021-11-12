package featuregates

import (
	"fmt"
	"reflect"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/config/featuregate"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
)

type FeatureGateLister interface {
	FeatureGateLister() configlistersv1.FeatureGateLister
}

// NewObserveFeatureFlagsFunc produces a configobserver for feature gates.  If non-nil, the featureWhitelist filters
// feature gates to a known subset (instead of everything).  The featureBlacklist will stop certain features from making
// it through the list.  The featureBlacklist should be empty, but for a brief time, some featuregates may need to skipped.
// @smarterclayton will live forever in shame for being the first to require this for "IPv6DualStack".
func NewObserveFeatureFlagsFunc(featureWhitelist sets.String, featureBlacklist sets.String, configPath []string) configobserver.ObserveConfigFunc {
	return (&featureFlags{
		allowAll:         len(featureWhitelist) == 0,
		featureWhitelist: featureWhitelist,
		featureBlacklist: featureBlacklist,
		configPath:       configPath,
	}).ObserveFeatureFlags
}

type featureFlags struct {
	allowAll         bool
	featureWhitelist sets.String
	// we add a forceDisableFeature list because we've now had bad featuregates break individual operators.  Awesome.
	featureBlacklist sets.String
	configPath       []string
}

// ObserveFeatureFlags fills in --feature-flags for the kube-apiserver
func (f *featureFlags) ObserveFeatureFlags(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	defer func() {
		ret = configobserver.Pruned(ret, f.configPath)
	}()

	listers := genericListers.(FeatureGateLister)
	errs := []error{}

	observedConfig := map[string]interface{}{}
	configResource, err := listers.FeatureGateLister().Get("cluster")
	// if we have no featuregate, then the installer and MCO probably still have way to reconcile certain custom resources
	// we will assume that this means the same as default and hope for the best
	if apierrors.IsNotFound(err) {
		configResource = &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.Default,
				},
			},
		}
	} else if err != nil {
		return existingConfig, append(errs, err)
	}

	newConfigValue, err := f.getWhitelistedFeatureNames(configResource)
	if err != nil {
		return existingConfig, append(errs, err)
	}
	currentConfigValue, _, err := unstructured.NestedStringSlice(existingConfig, f.configPath...)
	if err != nil {
		errs = append(errs, err)
		// keep going on read error from existing config
	}
	if !reflect.DeepEqual(currentConfigValue, newConfigValue) {
		recorder.Eventf("ObserveFeatureFlagsUpdated", "Updated %v to %s", strings.Join(f.configPath, "."), strings.Join(newConfigValue, ","))
	}

	if err := unstructured.SetNestedStringSlice(observedConfig, newConfigValue, f.configPath...); err != nil {
		recorder.Warningf("ObserveFeatureFlags", "Failed setting %v: %v", strings.Join(f.configPath, "."), err)
		return existingConfig, append(errs, err)
	}

	return observedConfig, errs
}

func (f *featureFlags) getWhitelistedFeatureNames(fg *configv1.FeatureGate) ([]string, error) {
	var err error
	newConfigValue := []string{}
	enabledFeatures := []string{}
	disabledFeatures := []string{}
	formatEnabledFunc := func(fs string) string {
		return fmt.Sprintf("%s=true", fs)
	}
	formatDisabledFunc := func(fs string) string {
		return fmt.Sprintf("%s=false", fs)
	}

	enabledFeatures, disabledFeatures, err = featuregate.GetEnabledAndDisabledFeatures(fg)
	if err != nil {
		return nil, err
	}

	for _, enable := range enabledFeatures {
		if f.featureBlacklist.Has(enable) {
			continue
		}
		// only add whitelisted feature flags
		if !f.allowAll && !f.featureWhitelist.Has(enable) {
			continue
		}
		newConfigValue = append(newConfigValue, formatEnabledFunc(enable))
	}
	for _, disable := range disabledFeatures {
		if f.featureBlacklist.Has(disable) {
			continue
		}
		// only add whitelisted feature flags
		if !f.allowAll && !f.featureWhitelist.Has(disable) {
			continue
		}
		newConfigValue = append(newConfigValue, formatDisabledFunc(disable))
	}

	return newConfigValue, nil
}

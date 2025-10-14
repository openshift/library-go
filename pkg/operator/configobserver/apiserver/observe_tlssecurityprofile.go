package apiserver

import (
	"fmt"
	"reflect"

	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ObserveTLSSecurityProfile observes APIServer.Spec.TLSSecurityProfile field and sets
// the ServingInfo.MinTLSVersion, ServingInfo.CipherSuites fields of observed config
func ObserveTLSSecurityProfile(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	return innerTLSSecurityProfileObservations(genericListers, recorder, existingConfig, []string{"servingInfo", "minTLSVersion"}, []string{"servingInfo", "cipherSuites"})
}

// ObserveTLSSecurityProfileWithPaths is like ObserveTLSSecurityProfile, but accepts
// custom paths for ServingInfo.MinTLSVersion and ServingInfo.CipherSuites fields of observed config.
func ObserveTLSSecurityProfileWithPaths(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}, minTLSVersionPath, cipherSuitesPath []string) (map[string]interface{}, []error) {
	return innerTLSSecurityProfileObservations(genericListers, recorder, existingConfig, minTLSVersionPath, cipherSuitesPath)
}

// ObserveTLSSecurityProfileToArguments observes APIServer.Spec.TLSSecurityProfile field and sets
// the tls-min-version and tls-cipher-suites fileds of observedConfig.apiServerArguments
func ObserveTLSSecurityProfileToArguments(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	return innerTLSSecurityProfileObservations(genericListers, recorder, existingConfig, []string{"apiServerArguments", "tls-min-version"}, []string{"apiServerArguments", "tls-cipher-suites"})
}

func innerTLSSecurityProfileObservations(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}, minTLSVersionPath, cipherSuitesPath []string) (ret map[string]interface{}, _ []error) {
	defer func() {
		ret = configobserver.Pruned(ret, minTLSVersionPath, cipherSuitesPath)
	}()

	listers := genericListers.(APIServerLister).APIServerLister()

	return GetTLSSecurityProfileObservations(listers, recorder, existingConfig, minTLSVersionPath, cipherSuitesPath, nil)
}

func GetTLSSecurityProfileObservations(listers configlistersv1.APIServerLister, recorder events.Recorder, existingConfig map[string]interface{}, minTLSVersionPath, cipherSuitesPath, profileTypePath []string) (ret map[string]interface{}, _ []error) {
	errs := []error{}

	currentMinTLSVersion, _, versionErr := unstructured.NestedString(existingConfig, minTLSVersionPath...)
	if versionErr != nil {
		errs = append(errs, fmt.Errorf("failed to retrieve %v: %v", minTLSVersionPath, versionErr))
		// keep going on read error from existing config
	}

	currentCipherSuites, _, suitesErr := unstructured.NestedStringSlice(existingConfig, cipherSuitesPath...)
	if suitesErr != nil {
		errs = append(errs, fmt.Errorf("failed to retrieve %v: %v", cipherSuitesPath, suitesErr))
		// keep going on read error from existing config
	}

	// Only get the profileType if the profileTypePath is set
	var currentProfileType string
	if len(profileTypePath) > 0 {
		var profileErr error
		currentProfileType, _, profileErr = unstructured.NestedString(existingConfig, profileTypePath...)
		if profileErr != nil {
			errs = append(errs, fmt.Errorf("failed to retrieve %v: %v", profileTypePath, profileErr))
			// keep going on read error from existing config
		}
	}

	apiServer, err := listers.Get("cluster")
	if errors.IsNotFound(err) {
		klog.Warningf("apiserver.config.openshift.io/cluster: not found")
		apiServer = &configv1.APIServer{}
	} else if err != nil {
		return existingConfig, append(errs, err)
	}

	observedConfig := map[string]interface{}{}
	observedMinTLSVersion, observedCipherSuites, observedProfileType := getSecurityProfileCiphers(apiServer.Spec.TLSSecurityProfile)
	if err = unstructured.SetNestedField(observedConfig, observedMinTLSVersion, minTLSVersionPath...); err != nil {
		return existingConfig, append(errs, err)
	}
	if err = unstructured.SetNestedStringSlice(observedConfig, observedCipherSuites, cipherSuitesPath...); err != nil {
		return existingConfig, append(errs, err)
	}
	// Only set the profileType if the profileTypePath is set
	if len(profileTypePath) > 0 {
		if err = unstructured.SetNestedField(observedConfig, observedProfileType, profileTypePath...); err != nil {
			return existingConfig, append(errs, err)
		}
	}

	if observedMinTLSVersion != currentMinTLSVersion {
		recorder.Eventf("ObserveTLSSecurityProfile", "minTLSVersion changed to %s", observedMinTLSVersion)
	}
	if !reflect.DeepEqual(observedCipherSuites, currentCipherSuites) {
		recorder.Eventf("ObserveTLSSecurityProfile", "cipherSuites changed to %q", observedCipherSuites)
	}
	// Only generate an event on profileType if the profileTypePath is set
	if len(profileTypePath) > 0 && observedProfileType != currentProfileType {
		recorder.Eventf("ObserveTLSSecurityProfile", "profileType changed to %q", observedProfileType)
	}

	return observedConfig, errs
}

// Extracts the minimum TLS version, cipher suites and profile name from TLSSecurityProfile object,
// Converts the ciphers to IANA names as supported by Kube ServingInfo config.
// If profile is nil, returns config defined by the Intermediate TLS Profile
func getSecurityProfileCiphers(profile *configv1.TLSSecurityProfile) (string, []string, string) {
	var profileType configv1.TLSProfileType
	var returnedProfileType configv1.TLSProfileType
	if profile == nil {
		profileType = configv1.TLSProfileIntermediateType
	} else {
		profileType = profile.Type
		returnedProfileType = profile.Type
	}

	var profileSpec *configv1.TLSProfileSpec
	if profileType == configv1.TLSProfileCustomType {
		if profile.Custom != nil {
			profileSpec = &profile.Custom.TLSProfileSpec
		}
	} else {
		profileSpec = configv1.TLSProfiles[profileType]
	}

	// nothing found / custom type set but no actual custom spec
	if profileSpec == nil {
		profileSpec = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	}

	// need to remap all Ciphers to their respective IANA names used by Go
	return string(profileSpec.MinTLSVersion), crypto.OpenSSLToIANACipherSuites(profileSpec.Ciphers), string(returnedProfileType)
}

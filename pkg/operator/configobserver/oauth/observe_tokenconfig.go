package oauth

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"

	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
)

// OAuthLister lists OAuth information
type OAuthLister interface {
	OAuthLister() configlistersv1.OAuthLister
}

const (
	defaultAccessTokenMaxAgeSeconds   = float64(86400) // a day
	fieldAccessTokenMaxAgeSeconds     = "accessTokenMaxAgeSeconds"
	fieldAccessTokenInactivityTimeout = "accessTokenInactivityTimeout"
)

// ObserveAccessTokenMaxAgeSeconds returns an unstructured fragment of KubeAPIServerConfig that changes the default value for access token max age,
// if there is a valid value for it in OAuth cluster config.
func ObserveAccessTokenMaxAgeSeconds(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, errs []error) {
	errs = []error{}
	tokenConfigPath := []string{"oauthConfig", "tokenConfig"}
	tokenMaxAgePath := append(tokenConfigPath, fieldAccessTokenMaxAgeSeconds)
	defer func() {
		// Prune the observed config so that it only contains access token max age field.
		ret = configobserver.Pruned(ret, tokenMaxAgePath)
	}()

	listers, ok := genericlisters.(OAuthLister)
	if !ok {
		return existingConfig, append(errs, fmt.Errorf("failed to assert: given lister does not implement an OAuth lister"))
	}

	oauthConfig, err := listers.OAuthLister().Get("cluster")
	if err != nil {
		// Failed to read OAuth cluster config.
		if errors.IsNotFound(err) {
			klog.Warning("oauth.config.openshift.io/cluster: not found")
		}
		// return whatever is present in existing config.
		return existingConfig, append(errs, err)
	}

	observedAccessTokenMaxAgeSeconds := float64(oauthConfig.Spec.TokenConfig.AccessTokenMaxAgeSeconds)
	if observedAccessTokenMaxAgeSeconds == 0 {
		// As the value 0 indicates that this field is not set or missing in OAuth cluster config, use the default value.
		observedAccessTokenMaxAgeSeconds = defaultAccessTokenMaxAgeSeconds
	}

	existingAccessTokenMaxAgeSeconds, _, err := unstructured.NestedFloat64(existingConfig, tokenMaxAgePath...)
	if err != nil {
		errs = append(errs, err)
	}

	if existingAccessTokenMaxAgeSeconds != observedAccessTokenMaxAgeSeconds {
		recorder.Eventf("ObserveAccessTokenMaxAgeSeconds", "%s changed from %d to %d", fieldAccessTokenMaxAgeSeconds,
			existingAccessTokenMaxAgeSeconds,
			observedAccessTokenMaxAgeSeconds)
	}

	return buildUnstructuredTokenConfig(observedAccessTokenMaxAgeSeconds, tokenMaxAgePath), errs
}

// ObserveAccessTokenInactivityTimeout returns an unstructured fragment of KubeAPIServerConfig that has access token inactivity timeout,
// if there is a valid value for it in OAuth cluster config.
func ObserveAccessTokenInactivityTimeout(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, errs []error) {
	errs = []error{}
	tokenConfigPath := []string{"oauthConfig", "tokenConfig"}
	tokenInactivityTimeoutPath := append(tokenConfigPath, fieldAccessTokenInactivityTimeout)
	defer func() {
		// Prune the observed config so that it only contains access token inactivity timeout field.
		ret = configobserver.Pruned(ret, tokenInactivityTimeoutPath)
	}()

	listers, ok := genericlisters.(OAuthLister)
	if !ok {
		return existingConfig, append(errs, fmt.Errorf("failed to assert: given lister does not implement OAuth lister"))
	}

	oauthConfig, err := listers.OAuthLister().Get("cluster")
	if err != nil {
		// Failed to read OAuth cluster config.
		if errors.IsNotFound(err) {
			klog.Warning("oauth.config.openshift.io/cluster: not found")
		}
		// Return whatever is present in existing config
		return existingConfig, append(errs, err)
	}

	existingAccessTokenInactivityTimeout, _, err := unstructured.NestedString(existingConfig, tokenInactivityTimeoutPath...)
	if err != nil {
		errs = append(errs, err)
	}

	observedConfig := map[string]interface{}{}
	observedAccessTokenInactivityTimeout := ""
	if oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeout != nil {
		observedAccessTokenInactivityTimeout = oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeout.Duration.String()
		observedConfig = buildUnstructuredTokenConfig(observedAccessTokenInactivityTimeout, tokenInactivityTimeoutPath)
	}

	if existingAccessTokenInactivityTimeout != observedAccessTokenInactivityTimeout {
		recorder.Eventf("ObserveAccessTokenInactivityTimeout", "%s changed from %v to %v", fieldAccessTokenInactivityTimeout,
			existingAccessTokenInactivityTimeout,
			observedAccessTokenInactivityTimeout)
	}

	return observedConfig, errs
}

func buildUnstructuredTokenConfig(val interface{}, fields []string) map[string]interface{} {
	unstructuredConfig := map[string]interface{}{}

	if err := unstructured.SetNestedField(unstructuredConfig, val, fields...); err != nil {
		// SetNestedField can return an error if one of the nesting level is not map[string]interface{}.
		// As unstructuredConfig is empty, this error must never happen.
		klog.Warningf("failed to write unstructured config for fields %v: %v", fields, err)
	}

	return unstructuredConfig
}

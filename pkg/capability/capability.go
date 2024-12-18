package capability

import (
	"k8s.io/apimachinery/pkg/util/sets"

	configv1 "github.com/openshift/api/config/v1"
)

// ClusterCapabilities represents various types of ClusterVersionCapabilities
type ClusterCapabilities struct {
	// Known is a set of all known ClusterVersionCapabilities. It may grow as OpenShift evolves.
	Known sets.Set[configv1.ClusterVersionCapability]
	// Enabled is a set of the ClusterVersionCapabilities that are enabled on a cluster.
	Enabled sets.Set[configv1.ClusterVersionCapability]
	// ImplicitlyEnabled is a set of the ClusterVersionCapabilities that are implicitly enabled on a cluster.
	// For example, "ImageRegistry" is a new ClusterVersionCapability in 4.14.
	// ImageRegistry becomes implicitly enabled on a 4.14 cluster upgraded from 4.13 with ImageRegistry running already.
	// https://docs.openshift.com/container-platform/4.17/installing/overview/cluster-capabilities.html
	ImplicitlyEnabled sets.Set[configv1.ClusterVersionCapability]
}

// GetImplicitlyEnabledCapabilities returns the capabilities from
// a set of capabilities that are not (even implicitly) enabled in ClusterCapabilities:
func GetImplicitlyEnabledCapabilities(
	capabilities sets.Set[configv1.ClusterVersionCapability],
	enabledCapabilities sets.Set[configv1.ClusterVersionCapability],
	clusterCapabilities ClusterCapabilities,
) sets.Set[configv1.ClusterVersionCapability] {
	if capabilities == nil {
		return nil
	}
	caps := capabilities.Difference(enabledCapabilities).Difference(clusterCapabilities.Enabled).Difference(clusterCapabilities.ImplicitlyEnabled)
	return caps
}

// SetCapabilities populates a ClusterCapabilities object from ClusterVersion clusterCapabilities spec. This method also
// ensures that each capability in others is still enabled: if not enabled then enabled implicitly.
func SetCapabilities(config *configv1.ClusterVersion,
	others sets.Set[configv1.ClusterVersionCapability]) ClusterCapabilities {
	var capabilities ClusterCapabilities
	capabilities.Known = sets.New[configv1.ClusterVersionCapability]()
	for _, s := range configv1.ClusterVersionCapabilitySets {
		capabilities.Known.Insert(s...)
	}
	key := configv1.ClusterVersionCapabilitySetCurrent
	if config.Spec.Capabilities != nil && config.Spec.Capabilities.BaselineCapabilitySet != "" {
		key = config.Spec.Capabilities.BaselineCapabilitySet
	}
	capabilities.Enabled = sets.New[configv1.ClusterVersionCapability](configv1.ClusterVersionCapabilitySets[key]...)
	if config.Spec.Capabilities != nil {
		capabilities.Enabled.Insert(config.Spec.Capabilities.AdditionalEnabledCapabilities...)
	}
	capabilities.ImplicitlyEnabled = others.Difference(capabilities.Enabled)
	return capabilities
}

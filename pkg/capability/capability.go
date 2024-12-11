package capability

import (
	"sort"
	"strings"

	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/library-go/pkg/manifest"
)

type ClusterCapabilities struct {
	KnownCapabilities             map[configv1.ClusterVersionCapability]struct{}
	EnabledCapabilities           map[configv1.ClusterVersionCapability]struct{}
	ImplicitlyEnabledCapabilities []configv1.ClusterVersionCapability
}

// getImplicitlyEnabledCapabilities iterates through a set of capabilities from an update and filters out
// the ones that
// - are not in the list enabledManifestCaps of capabilities
// - are not the keys of ClusterCapabilities.EnabledCapabilities
// - are not in the list ClusterCapabilities.ImplicitlyEnabledCapabilities
// The returned list are capabilities which must be implicitly enabled.
func getImplicitlyEnabledCapabilities(enabledManifestCaps []configv1.ClusterVersionCapability,
	updateManifestCaps []configv1.ClusterVersionCapability,
	capabilities ClusterCapabilities) []configv1.ClusterVersionCapability {
	var caps []configv1.ClusterVersionCapability
	for _, c := range updateManifestCaps {
		if contains(enabledManifestCaps, c) {
			continue
		}
		if _, ok := capabilities.EnabledCapabilities[c]; !ok {
			if !contains(capabilities.ImplicitlyEnabledCapabilities, c) {
				caps = append(caps, c)
			}
		}
	}
	sort.Sort(capabilitiesSort(caps))
	return caps
}

func contains(caps []configv1.ClusterVersionCapability, capability configv1.ClusterVersionCapability) bool {
	for _, c := range caps {
		if capability == c {
			return true
		}
	}
	return false
}

type capabilitiesSort []configv1.ClusterVersionCapability

func (caps capabilitiesSort) Len() int           { return len(caps) }
func (caps capabilitiesSort) Swap(i, j int)      { caps[i], caps[j] = caps[j], caps[i] }
func (caps capabilitiesSort) Less(i, j int) bool { return string(caps[i]) < string(caps[j]) }

// GetImplicitlyEnabledCapabilities iterates through each disabled manifest in the update payload.
// If the manifest is enabled in the current payload, the update manifest's capabilities
// are checked to see if any must be implicitly enabled.
// All capabilities requiring implicit enablement are returned.
func GetImplicitlyEnabledCapabilities(updatePayloadManifests []manifest.Manifest, currentPayloadManifests []manifest.Manifest,
	capabilities ClusterCapabilities) []configv1.ClusterVersionCapability {

	capabilitiesStatus := GetCapabilitiesStatus(capabilities)

	// Initialize so it contains existing implicitly enabled capabilities
	implicitlyEnabledCaps := capabilities.ImplicitlyEnabledCapabilities

	for _, updateManifest := range updatePayloadManifests {
		updateManErr := updateManifest.IncludeAllowUnknownCapabilities(nil, nil, nil, &capabilitiesStatus, nil, true)

		// update manifest is enabled, no need to check
		if updateManErr == nil {
			continue
		}
		for _, currentManifest := range currentPayloadManifests {
			if !updateManifest.SameResourceID(currentManifest) {
				continue
			}

			// current manifest is disabled, no need to check
			if err := currentManifest.IncludeAllowUnknownCapabilities(nil, nil, nil, &capabilitiesStatus, nil, true); err != nil {
				continue
			}
			caps := getImplicitlyEnabledCapabilities(currentManifest.GetManifestCapabilities(),
				updateManifest.GetManifestCapabilities(), capabilities)

			capStrings := make([]string, len(caps))
			for i, c := range caps {
				capStrings[i] = string(c)
				if !contains(implicitlyEnabledCaps, c) {
					implicitlyEnabledCaps = append(implicitlyEnabledCaps, c)
				}
			}
			klog.V(2).Infof("%s has changed and is now part of one or more disabled capabilities. The following capabilities will be implicitly enabled: %s",
				updateManifest.GetManifestResourceId(), strings.Join(capStrings, ", "))
		}
	}
	sort.Sort(capabilitiesSort(implicitlyEnabledCaps))
	return implicitlyEnabledCaps
}

// GetCapabilitiesStatus populates and returns ClusterVersion capabilities status from given capabilities.
func GetCapabilitiesStatus(capabilities ClusterCapabilities) configv1.ClusterVersionCapabilitiesStatus {
	var status configv1.ClusterVersionCapabilitiesStatus
	for k := range capabilities.EnabledCapabilities {
		status.EnabledCapabilities = append(status.EnabledCapabilities, k)
	}
	sort.Sort(capabilitiesSort(status.EnabledCapabilities))
	for k := range capabilities.KnownCapabilities {
		status.KnownCapabilities = append(status.KnownCapabilities, k)
	}
	sort.Sort(capabilitiesSort(status.KnownCapabilities))
	return status
}

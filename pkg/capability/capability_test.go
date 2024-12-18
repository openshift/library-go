package capability

import (
	"k8s.io/apimachinery/pkg/util/sets"
	"testing"

	"github.com/google/go-cmp/cmp"

	configv1 "github.com/openshift/api/config/v1"
)

func TestGetImplicitlyEnabledCapabilities(t *testing.T) {
	tests := []struct {
		name                string
		capabilities        sets.Set[configv1.ClusterVersionCapability]
		enabledCaps         sets.Set[configv1.ClusterVersionCapability]
		clusterCapabilities ClusterCapabilities
		expected            sets.Set[configv1.ClusterVersionCapability]
	}{
		{name: "implicitly enable capability",
			capabilities: sets.New[configv1.ClusterVersionCapability]("cap2"),
			enabledCaps:  sets.New[configv1.ClusterVersionCapability]("cap1", "cap3"),
			clusterCapabilities: ClusterCapabilities{
				Enabled: sets.New[configv1.ClusterVersionCapability]("cap1"),
			},
			expected: sets.New[configv1.ClusterVersionCapability]("cap2"),
		},
		{name: "no prior caps, implicitly enabled capability",
			capabilities: sets.New[configv1.ClusterVersionCapability]("cap2"),
			expected:     sets.New[configv1.ClusterVersionCapability]("cap2"),
		},
		{name: "multiple implicitly enable capability",
			capabilities: sets.New[configv1.ClusterVersionCapability]("cap4", "cap5", "cap6"),
			enabledCaps:  sets.New[configv1.ClusterVersionCapability]("cap1", "cap2", "cap3"),
			expected:     sets.New[configv1.ClusterVersionCapability]("cap4", "cap5", "cap6"),
		},
		{name: "no implicitly enable capability",
			enabledCaps:  sets.New[configv1.ClusterVersionCapability]("cap1", "cap3"),
			capabilities: sets.New[configv1.ClusterVersionCapability]("cap1"),
			clusterCapabilities: ClusterCapabilities{
				Enabled: sets.New[configv1.ClusterVersionCapability]("cap1"),
			},
		},
		{name: "prior cap, no updated caps, no implicitly enabled capability",
			enabledCaps: sets.New[configv1.ClusterVersionCapability]("cap1"),
		},
		{name: "no implicitly enable capability, already enabled",
			enabledCaps:  sets.New[configv1.ClusterVersionCapability]("cap1", "cap2"),
			capabilities: sets.New[configv1.ClusterVersionCapability]("cap2"),
			clusterCapabilities: ClusterCapabilities{
				Enabled: sets.New[configv1.ClusterVersionCapability]("cap1", "cap2"),
			},
		},
		{name: "no implicitly enable capability, new cap but already enabled",
			enabledCaps:  sets.New[configv1.ClusterVersionCapability]("cap1"),
			capabilities: sets.New[configv1.ClusterVersionCapability]("cap2"),
			clusterCapabilities: ClusterCapabilities{
				Enabled: sets.New[configv1.ClusterVersionCapability]("cap2"),
			},
		},
		{name: "no implicitly enable capability, already implicitly enabled",
			enabledCaps:  sets.New[configv1.ClusterVersionCapability]("cap1"),
			capabilities: sets.New[configv1.ClusterVersionCapability]("cap2"),
			clusterCapabilities: ClusterCapabilities{
				Enabled:           sets.New[configv1.ClusterVersionCapability]("cap2"),
				ImplicitlyEnabled: sets.New[configv1.ClusterVersionCapability]("cap2"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			caps := GetImplicitlyEnabledCapabilities(test.capabilities, test.enabledCaps, test.clusterCapabilities)
			if diff := cmp.Diff(test.expected, caps); diff != "" {
				t.Errorf("%s: Returned capacities differ from expected:\n%s", test.name, diff)
			}
		})
	}
}

func TestSetCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		config   *configv1.ClusterVersion
		others   sets.Set[configv1.ClusterVersionCapability]
		expected ClusterCapabilities
	}{
		{name: "capabilities nil",
			config: &configv1.ClusterVersion{},
			expected: ClusterCapabilities{
				Known:   sets.New[configv1.ClusterVersionCapability](configv1.KnownClusterVersionCapabilities...),
				Enabled: sets.New[configv1.ClusterVersionCapability](configv1.ClusterVersionCapabilitySets[configv1.ClusterVersionCapabilitySetCurrent]...),
			},
		},
		{name: "capabilities set not set",
			config: &configv1.ClusterVersion{
				Spec: configv1.ClusterVersionSpec{
					Capabilities: &configv1.ClusterVersionCapabilitiesSpec{},
				},
			},
			expected: ClusterCapabilities{
				Known:   sets.New[configv1.ClusterVersionCapability](configv1.KnownClusterVersionCapabilities...),
				Enabled: sets.New[configv1.ClusterVersionCapability](configv1.ClusterVersionCapabilitySets[configv1.ClusterVersionCapabilitySetCurrent]...),
			},
		},
		{name: "set capabilities None",
			config: &configv1.ClusterVersion{
				Spec: configv1.ClusterVersionSpec{
					Capabilities: &configv1.ClusterVersionCapabilitiesSpec{
						BaselineCapabilitySet: configv1.ClusterVersionCapabilitySetNone,
					},
				},
			},
			expected: ClusterCapabilities{
				Known: sets.New[configv1.ClusterVersionCapability](configv1.KnownClusterVersionCapabilities...),
			},
		},
		{name: "set capabilities 4_11",
			config: &configv1.ClusterVersion{
				Spec: configv1.ClusterVersionSpec{
					Capabilities: &configv1.ClusterVersionCapabilitiesSpec{
						BaselineCapabilitySet:         configv1.ClusterVersionCapabilitySet4_11,
						AdditionalEnabledCapabilities: []configv1.ClusterVersionCapability{},
					},
				},
			},
			expected: ClusterCapabilities{
				Known: sets.New[configv1.ClusterVersionCapability](configv1.KnownClusterVersionCapabilities...),
				Enabled: sets.New[configv1.ClusterVersionCapability](
					configv1.ClusterVersionCapabilityBaremetal,
					configv1.ClusterVersionCapabilityMarketplace,
					configv1.ClusterVersionCapabilityOpenShiftSamples,
					configv1.ClusterVersionCapabilityMachineAPI,
				),
			},
		},
		{name: "set capabilities vCurrent",
			config: &configv1.ClusterVersion{
				Spec: configv1.ClusterVersionSpec{
					Capabilities: &configv1.ClusterVersionCapabilitiesSpec{
						BaselineCapabilitySet:         configv1.ClusterVersionCapabilitySetCurrent,
						AdditionalEnabledCapabilities: []configv1.ClusterVersionCapability{},
					},
				},
			},
			expected: ClusterCapabilities{
				Known:   sets.New[configv1.ClusterVersionCapability](configv1.KnownClusterVersionCapabilities...),
				Enabled: sets.New[configv1.ClusterVersionCapability](configv1.ClusterVersionCapabilitySets[configv1.ClusterVersionCapabilitySetCurrent]...),
			},
		},
		{name: "set capabilities None with additional",
			config: &configv1.ClusterVersion{
				Spec: configv1.ClusterVersionSpec{
					Capabilities: &configv1.ClusterVersionCapabilitiesSpec{
						BaselineCapabilitySet:         configv1.ClusterVersionCapabilitySetNone,
						AdditionalEnabledCapabilities: []configv1.ClusterVersionCapability{"cap1", "cap2", "cap3"},
					},
				},
			},
			expected: ClusterCapabilities{
				Known:   sets.New[configv1.ClusterVersionCapability](configv1.KnownClusterVersionCapabilities...),
				Enabled: sets.New[configv1.ClusterVersionCapability]("cap1", "cap2", "cap3"),
			},
		},
		{name: "set capabilities 4_11 with additional",
			config: &configv1.ClusterVersion{
				Spec: configv1.ClusterVersionSpec{
					Capabilities: &configv1.ClusterVersionCapabilitiesSpec{
						BaselineCapabilitySet:         configv1.ClusterVersionCapabilitySet4_11,
						AdditionalEnabledCapabilities: []configv1.ClusterVersionCapability{"cap1", "cap2", "cap3"},
					},
				},
			},
			expected: ClusterCapabilities{
				Known: sets.New[configv1.ClusterVersionCapability](configv1.KnownClusterVersionCapabilities...),
				Enabled: sets.New[configv1.ClusterVersionCapability](
					configv1.ClusterVersionCapabilityBaremetal,
					configv1.ClusterVersionCapabilityMarketplace,
					configv1.ClusterVersionCapabilityOpenShiftSamples,
					configv1.ClusterVersionCapabilityMachineAPI,
					"cap1",
					"cap2",
					"cap3"),
			},
		},
		{name: "set capabilities 4_11 with additional and others",
			config: &configv1.ClusterVersion{
				Spec: configv1.ClusterVersionSpec{
					Capabilities: &configv1.ClusterVersionCapabilitiesSpec{
						BaselineCapabilitySet:         configv1.ClusterVersionCapabilitySet4_11,
						AdditionalEnabledCapabilities: []configv1.ClusterVersionCapability{"cap1", "cap2", "cap3"},
					},
				},
			},
			others: sets.New[configv1.ClusterVersionCapability](
				configv1.ClusterVersionCapabilityMachineAPI,
				"cap1",
				"cap-implicitly",
			),
			expected: ClusterCapabilities{
				Known: sets.New[configv1.ClusterVersionCapability](configv1.KnownClusterVersionCapabilities...),
				Enabled: sets.New[configv1.ClusterVersionCapability](
					configv1.ClusterVersionCapabilityBaremetal,
					configv1.ClusterVersionCapabilityMarketplace,
					configv1.ClusterVersionCapabilityOpenShiftSamples,
					configv1.ClusterVersionCapabilityMachineAPI,
					"cap1",
					"cap2",
					"cap3"),
				ImplicitlyEnabled: sets.New[configv1.ClusterVersionCapability]("cap-implicitly"),
			},
		},
	}
	for _, test := range tests {
		if test.name != "set capabilities 4_11 with additional and others" {
			continue
		}
		t.Run(test.name, func(t *testing.T) {
			caps := SetCapabilities(test.config, test.others)
			if diff := cmp.Diff(test.expected, caps); diff != "" {
				t.Errorf("%s: Returned capacities differ from expected:\n%s", test.name, diff)
			}
		})
	}
}

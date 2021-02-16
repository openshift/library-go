package cloudprovider

import (
	"fmt"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestIsCloudProviderExternal(t *testing.T) {
	cases := []struct {
		name        string
		platform    configv1.PlatformType
		featureGate *configv1.FeatureGate
		expected    bool
		expectedErr error
	}{{
		name:        "No FeatureGate, Platform: OpenStack",
		platform:    configv1.OpenStackPlatformType,
		featureGate: nil,
		expected:    false,
		expectedErr: nil,
	}, {
		name:     "FeatureSet: Unknown, Platform: OpenStack",
		platform: configv1.OpenStackPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.FeatureSet("Unknown"),
				},
			},
		},
		expected:    false,
		expectedErr: fmt.Errorf(".spec.featureSet \"Unknown\" not found"),
	}, {
		name:     "FeatureSet: TechPreviewNoUpgrade, Platform: OpenStack",
		platform: configv1.OpenStackPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.TechPreviewNoUpgrade,
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: LatencySensitive, Platform: OpenStack",
		platform: configv1.OpenStackPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.LatencySensitive,
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: IPv6DualStackNoUpgrade, Platform: OpenStack",
		platform: configv1.OpenStackPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.IPv6DualStackNoUpgrade,
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (No External Feature Gate), Platform: OpenStack",
		platform: configv1.OpenStackPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Enabled: []string{},
					},
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (With External Feature Gate Enabled), Platform: OpenStack",
		platform: configv1.OpenStackPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Enabled: []string{ExternalCloudProviderFeature},
					},
				},
			},
		},
		expected: true,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (With External Feature Gate Enabled & Disabled), Platform: OpenStack",
		platform: configv1.OpenStackPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Enabled:  []string{ExternalCloudProviderFeature},
						Disabled: []string{ExternalCloudProviderFeature},
					},
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (With External Feature Gate Disabled), Platform: OpenStack",
		platform: configv1.OpenStackPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Disabled: []string{ExternalCloudProviderFeature},
					},
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: AWS",
		platform: configv1.AWSPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Enabled: []string{ExternalCloudProviderFeature},
					},
				},
			},
		},
		expected: true,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: Azure",
		platform: configv1.AzurePlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Enabled: []string{ExternalCloudProviderFeature},
					},
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: BareMetal",
		platform: configv1.BareMetalPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Enabled: []string{ExternalCloudProviderFeature},
					},
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: Libvirt",
		platform: configv1.LibvirtPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Enabled: []string{ExternalCloudProviderFeature},
					},
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: GCP",
		platform: configv1.GCPPlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Enabled: []string{ExternalCloudProviderFeature},
					},
				},
			},
		},
		expected: false,
	}, {
		name:     "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: None",
		platform: configv1.NonePlatformType,
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.CustomNoUpgrade,
					CustomNoUpgrade: &configv1.CustomFeatureGates{
						Enabled: []string{ExternalCloudProviderFeature},
					},
				},
			},
		},
		expected: false,
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := IsCloudProviderExternal(c.platform, c.featureGate)
			if c.expectedErr != nil {
				if err == nil {
					t.Errorf("expected error: %v, but got no error", c.expectedErr)
				} else if c.expectedErr.Error() != err.Error() {
					t.Errorf("expected error: %v, got error: %v", c.expectedErr, err)
				}
			}
			if got != c.expected {
				t.Errorf("expect external: %v, got external: %v", c.expected, got)
			}
		})
	}
}

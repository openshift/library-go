package cloudprovider

import (
	"fmt"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestIsCloudProviderExternal(t *testing.T) {
	cases := []struct {
		name        string
		status      *configv1.PlatformStatus
		featureGate *configv1.FeatureGate
		expected    bool
		expectedErr error
	}{{
		name: "No FeatureGate, Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: nil,
		expected:    false,
		expectedErr: nil,
	}, {
		name: "FeatureSet: Unknown, Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
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
		name: "FeatureSet: TechPreviewNoUpgrade, Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.TechPreviewNoUpgrade,
				},
			},
		},
		expected: true,
	}, {
		name: "FeatureSet: LatencySensitive, Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.LatencySensitive,
				},
			},
		},
		expected: false,
	}, {
		name: "FeatureSet: IPv6DualStackNoUpgrade, Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.IPv6DualStackNoUpgrade,
				},
			},
		},
		expected: false,
	}, {
		name: "FeatureSet: CustomNoUpgrade (No External Feature Gate), Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
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
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Enabled), Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
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
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Enabled & Disabled), Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
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
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Disabled), Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
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
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: AWS",
		status: &configv1.PlatformStatus{
			Type: configv1.AWSPlatformType,
		},
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
		name: "No FeatureGate: Platform: AlibabaCloud",
		status: &configv1.PlatformStatus{
			Type: configv1.AlibabaCloudPlatformType,
		},
		featureGate: nil,
		expected:    true,
	}, {
		name: "No FeatureGate, Platform: IBMCloud",
		status: &configv1.PlatformStatus{
			Type: configv1.IBMCloudPlatformType,
		},
		featureGate: nil,
		expected:    true,
	}, {
		name: "No FeatureGate, Platform: PowerVS",
		status: &configv1.PlatformStatus{
			Type: configv1.PowerVSPlatformType,
		},
		featureGate: nil,
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: Azure",
		status: &configv1.PlatformStatus{
			Type: configv1.AzurePlatformType,
		},
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
		name: "Platform: Azure, CloudName: AzureStackHub",
		status: &configv1.PlatformStatus{
			Type: configv1.AzurePlatformType,
			Azure: &configv1.AzurePlatformStatus{
				CloudName: configv1.AzureStackCloud,
			},
		},
		expected: true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: BareMetal",
		status: &configv1.PlatformStatus{
			Type: configv1.BareMetalPlatformType,
		},
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
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: Libvirt",
		status: &configv1.PlatformStatus{
			Type: configv1.LibvirtPlatformType,
		},
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
		name: "No FeatureGate, Platform: GCP",
		status: &configv1.PlatformStatus{
			Type: configv1.GCPPlatformType,
		},
		featureGate: nil,
		expected:    false,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: GCP",
		status: &configv1.PlatformStatus{
			Type: configv1.GCPPlatformType,
		},
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
		name: "FeatureSet: TechPreviewNoUpgrade, Platform: GCP",
		status: &configv1.PlatformStatus{
			Type: configv1.GCPPlatformType,
		},
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.TechPreviewNoUpgrade,
				},
			},
		},
		expected: true,
	}, {
		name: "No FeatureGate, Platform: vSphere",
		status: &configv1.PlatformStatus{
			Type: configv1.VSpherePlatformType,
		},
		featureGate: nil,
		expected:    false,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: vSphere",
		status: &configv1.PlatformStatus{
			Type: configv1.VSpherePlatformType,
		},
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
		name: "FeatureSet: TechPreviewNoUpgrade, Platform: vSphere",
		status: &configv1.PlatformStatus{
			Type: configv1.VSpherePlatformType,
		},
		featureGate: &configv1.FeatureGate{
			Spec: configv1.FeatureGateSpec{
				FeatureGateSelection: configv1.FeatureGateSelection{
					FeatureSet: configv1.TechPreviewNoUpgrade,
				},
			},
		},
		expected: true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: None",
		status: &configv1.PlatformStatus{
			Type: configv1.NonePlatformType,
		},
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
		name:   "Platform status is empty",
		status: nil,
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
		expected:    false,
		expectedErr: fmt.Errorf("platformStatus is required"),
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := IsCloudProviderExternal(c.status, c.featureGate)
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

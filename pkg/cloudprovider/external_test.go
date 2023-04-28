package cloudprovider

import (
	"fmt"
	"testing"

	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	configv1 "github.com/openshift/api/config/v1"
)

func TestIsCloudProviderExternal(t *testing.T) {
	readyCh := make(chan struct{})
	close(readyCh)

	cases := []struct {
		name        string
		status      *configv1.PlatformStatus
		featureGate featuregates.FeatureGateAccess
		expected    bool
		expectedErr error
	}{{
		name: "No FeatureGate, Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		expected: true,
	}, {
		name: "FeatureSet: Unknown, Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, readyCh, fmt.Errorf("missing")),
		expected:    true,
	}, {
		name: "FeatureSet: TechPreviewNoUpgrade, Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, nil),
		expected:    true,
	}, {
		name: "FeatureSet: LatencySensitive, Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(nil, nil),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (No External Feature Gate), Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(nil, nil),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Enabled), Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, nil),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Enabled & Disabled), Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, []configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Disabled), Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: AWS",
		status: &configv1.PlatformStatus{
			Type: configv1.AWSPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, nil),
		expected:    true,
	}, {
		name: "No FeatureGate: Platform: AlibabaCloud",
		status: &configv1.PlatformStatus{
			Type: configv1.AlibabaCloudPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, readyCh, fmt.Errorf("missing")),
		expected:    true,
	}, {
		name: "No FeatureGate, Platform: IBMCloud",
		status: &configv1.PlatformStatus{
			Type: configv1.IBMCloudPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, readyCh, fmt.Errorf("missing")),
		expected:    true,
	}, {
		name: "No FeatureGate, Platform: Nutanix",
		status: &configv1.PlatformStatus{
			Type: configv1.NutanixPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, readyCh, fmt.Errorf("missing")),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Enabled), Platform: Nutanix",
		status: &configv1.PlatformStatus{
			Type: configv1.NutanixPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, nil),

		expected: true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Disabled), Platform: Nutanix",
		status: &configv1.PlatformStatus{
			Type: configv1.NutanixPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}),

		expected: true,
	}, {
		name: "No FeatureGate, Platform: PowerVS",
		status: &configv1.PlatformStatus{
			Type: configv1.PowerVSPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, readyCh, fmt.Errorf("missing")),
		expected:    true,
	}, {
		name: "No FeatureGate, Platform: Kubevirt",
		status: &configv1.PlatformStatus{
			Type: configv1.KubevirtPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, readyCh, fmt.Errorf("missing")),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: Azure",
		status: &configv1.PlatformStatus{
			Type: configv1.AzurePlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider, configv1.FeatureGateExternalCloudProviderAzure},
			[]configv1.FeatureGateName{},
		),
		expected: true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Azure), Platform: Azure",
		status: &configv1.PlatformStatus{
			Type: configv1.AzurePlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProviderAzure, configv1.FeatureGateExternalCloudProvider},
			[]configv1.FeatureGateName{},
		),
		expected: true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Enabled but External Feature Gate Azure Disabled), Platform: Azure",
		status: &configv1.PlatformStatus{
			Type: configv1.AzurePlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider},
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProviderAzure},
		),
		expected: true,
	}, {
		name: "Platform: Azure, CloudName: AzureStackHub",
		status: &configv1.PlatformStatus{
			Type: configv1.AzurePlatformType,
			Azure: &configv1.AzurePlatformStatus{
				CloudName: configv1.AzureStackCloud,
			},
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, readyCh, fmt.Errorf("missing")),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: BareMetal",
		status: &configv1.PlatformStatus{
			Type: configv1.BareMetalPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, nil),
		expected:    false,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: Libvirt",
		status: &configv1.PlatformStatus{
			Type: configv1.LibvirtPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, nil),

		expected: false,
	}, {
		name: "No FeatureGate, Platform: GCP",
		status: &configv1.PlatformStatus{
			Type: configv1.GCPPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, readyCh, fmt.Errorf("missing")),
		expected:    false,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: GCP",
		status: &configv1.PlatformStatus{
			Type: configv1.GCPPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider, configv1.FeatureGateExternalCloudProviderGCP},
			[]configv1.FeatureGateName{},
		),
		expected: true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate GCP), Platform: GCP",
		status: &configv1.PlatformStatus{
			Type: configv1.GCPPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider, configv1.FeatureGateExternalCloudProviderGCP},
			[]configv1.FeatureGateName{},
		),
		expected: true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate Enabled but External Feature Gate GCP Disabled), Platform: GCP",
		status: &configv1.PlatformStatus{
			Type: configv1.GCPPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider},
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProviderGCP},
		),
		expected: true,
	}, {
		name: "FeatureSet: TechPreviewNoUpgrade, Platform: GCP",
		status: &configv1.PlatformStatus{
			Type: configv1.GCPPlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider, configv1.FeatureGateExternalCloudProviderGCP},
			nil),
		expected: true,
	}, {
		name: "No FeatureGate, Platform: vSphere",
		status: &configv1.PlatformStatus{
			Type: configv1.VSpherePlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, readyCh, fmt.Errorf("missing")),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: vSphere",
		status: &configv1.PlatformStatus{
			Type: configv1.VSpherePlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess(
			[]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider},
			nil,
		),
		expected: true,
	}, {
		name: "FeatureSet: TechPreviewNoUpgrade, Platform: vSphere",
		status: &configv1.PlatformStatus{
			Type: configv1.VSpherePlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, nil),
		expected:    true,
	}, {
		name: "FeatureSet: CustomNoUpgrade (With External Feature Gate), Platform: None",
		status: &configv1.PlatformStatus{
			Type: configv1.NonePlatformType,
		},
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, nil),
		expected:    false,
	}, {
		name:        "Platform status is empty",
		status:      nil,
		featureGate: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{configv1.FeatureGateExternalCloudProvider}, nil),
		expected:    false,
		expectedErr: fmt.Errorf("platformStatus is required"),
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			featureGateAccessor := featuregates.NewHardcodedFeatureGateAccess(nil, nil)
			if c.featureGate != nil {
				featureGateAccessor = c.featureGate
			}
			got, err := IsCloudProviderExternal(c.status, featureGateAccessor)
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

package cloudprovider

import (
	"fmt"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestIsCloudProviderExternal(t *testing.T) {
	readyCh := make(chan struct{})
	close(readyCh)

	cases := []struct {
		name        string
		status      *configv1.PlatformStatus
		expected    bool
		expectedErr error
	}{{
		name: "Platform: OpenStack",
		status: &configv1.PlatformStatus{
			Type: configv1.OpenStackPlatformType,
		},
		expected: true,
	}, {
		name: "Platform: AWS",
		status: &configv1.PlatformStatus{
			Type: configv1.AWSPlatformType,
		},
		expected: true,
	}, {
		name: "Platform: AlibabaCloud",
		status: &configv1.PlatformStatus{
			Type: configv1.AlibabaCloudPlatformType,
		},
		expected: true,
	}, {
		name: "Platform: IBMCloud",
		status: &configv1.PlatformStatus{
			Type: configv1.IBMCloudPlatformType,
		},
		expected: true,
	}, {
		name: " Platform: Nutanix",
		status: &configv1.PlatformStatus{
			Type: configv1.NutanixPlatformType,
		},
		expected: true,
	}, {
		name: "Platform: External, CloudControllerManager.State = External",
		status: &configv1.PlatformStatus{
			Type: configv1.ExternalPlatformType,
			External: &configv1.ExternalPlatformStatus{
				CloudControllerManager: configv1.CloudControllerManagerStatus{
					State: configv1.CloudControllerManagerExternal,
				},
			},
		},
		expected: true,
	}, {
		name: "Platform: External, CloudControllerManager.State = None",
		status: &configv1.PlatformStatus{
			Type: configv1.ExternalPlatformType,
			External: &configv1.ExternalPlatformStatus{
				CloudControllerManager: configv1.CloudControllerManagerStatus{
					State: configv1.CloudControllerManagerNone,
				},
			},
		},
		expected: false,
	}, {
		name: "Platform: External, CloudControllerManager.State is empty",
		status: &configv1.PlatformStatus{
			Type:     configv1.ExternalPlatformType,
			External: &configv1.ExternalPlatformStatus{},
		},
		expected: false,
	}, {
		name: "Platform: External, ExternalPlatformSpec is nil",
		status: &configv1.PlatformStatus{
			Type:     configv1.ExternalPlatformType,
			External: nil,
		},
		expected: false,
	}, {
		name: "Platform: PowerVS",
		status: &configv1.PlatformStatus{
			Type: configv1.PowerVSPlatformType,
		},
		expected: true,
	}, {
		name: "Platform: Kubevirt",
		status: &configv1.PlatformStatus{
			Type: configv1.KubevirtPlatformType,
		},
		expected: true,
	}, {
		name: "Platform: Azure",
		status: &configv1.PlatformStatus{
			Type: configv1.AzurePlatformType,
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
		name: "Platform: BareMetal",
		status: &configv1.PlatformStatus{
			Type: configv1.BareMetalPlatformType,
		},
		expected: false,
	}, {
		name: "Platform: Libvirt",
		status: &configv1.PlatformStatus{
			Type: configv1.LibvirtPlatformType,
		},
		expected: false,
	}, {
		name: "Platform: GCP",
		status: &configv1.PlatformStatus{
			Type: configv1.GCPPlatformType,
		},
		expected: true,
	}, {
		name: "Platform: vSphere",
		status: &configv1.PlatformStatus{
			Type: configv1.VSpherePlatformType,
		},
		expected: true,
	}, {
		name: "Platform: None",
		status: &configv1.PlatformStatus{
			Type: configv1.NonePlatformType,
		},

		expected: false,
	}, {
		name:        "Platform status is empty",
		status:      nil,
		expected:    false,
		expectedErr: fmt.Errorf("platformStatus is required"),
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := IsCloudProviderExternal(c.status)
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

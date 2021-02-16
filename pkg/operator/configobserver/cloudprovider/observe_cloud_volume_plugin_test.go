package cloudprovider

import (
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/cloudprovider"
	"github.com/openshift/library-go/pkg/operator/events"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

func TestObserveCloudVolumePlugin(t *testing.T) {
	type Test struct {
		name        string
		platform    configv1.PlatformType
		fgSelection configv1.FeatureGateSelection
		expected    string
	}

	tests := []Test{{
		name:     "AWS external-cloud-volume-plugin should be set",
		platform: configv1.AWSPlatformType,
		expected: "aws",
		fgSelection: configv1.FeatureGateSelection{
			FeatureSet: configv1.CustomNoUpgrade,
			CustomNoUpgrade: &configv1.CustomFeatureGates{
				Enabled: []string{cloudprovider.ExternalCloudProviderFeature},
			},
		},
	}, {
		name:     "FeatureGate should be set for platform to become external",
		platform: configv1.AWSPlatformType,
	}, {
		name:     "OpenStack external-cloud-volume-plugin should be set",
		platform: configv1.OpenStackPlatformType,
		expected: "openstack",
		fgSelection: configv1.FeatureGateSelection{
			FeatureSet: configv1.CustomNoUpgrade,
			CustomNoUpgrade: &configv1.CustomFeatureGates{
				Enabled: []string{cloudprovider.ExternalCloudProviderFeature},
			},
		},
	}, {
		name:     "no external-cloud-volume-plugin for no cloud",
		platform: configv1.NonePlatformType,
		fgSelection: configv1.FeatureGateSelection{
			FeatureSet: configv1.CustomNoUpgrade,
			CustomNoUpgrade: &configv1.CustomFeatureGates{
				Enabled: []string{cloudprovider.ExternalCloudProviderFeature},
			},
		},
	}, {
		name:     "no external-cloud-volume-plugin for Azure",
		platform: configv1.AzurePlatformType,
		fgSelection: configv1.FeatureGateSelection{
			FeatureSet: configv1.CustomNoUpgrade,
			CustomNoUpgrade: &configv1.CustomFeatureGates{
				Enabled: []string{cloudprovider.ExternalCloudProviderFeature},
			},
		},
	}, {
		name:     "no external-cloud-volume-plugin for GCP",
		platform: configv1.GCPPlatformType,
		fgSelection: configv1.FeatureGateSelection{
			FeatureSet: configv1.CustomNoUpgrade,
			CustomNoUpgrade: &configv1.CustomFeatureGates{
				Enabled: []string{cloudprovider.ExternalCloudProviderFeature},
			},
		},
	}, {
		name:     "no external-cloud-volume-plugin for VSphere",
		platform: configv1.VSpherePlatformType,
		fgSelection: configv1.FeatureGateSelection{
			FeatureSet: configv1.CustomNoUpgrade,
			CustomNoUpgrade: &configv1.CustomFeatureGates{
				Enabled: []string{cloudprovider.ExternalCloudProviderFeature},
			},
		},
	},
	}
	for _, c := range tests {
		t.Run(string(c.platform), func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			fgIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := indexer.Add(&configv1.Infrastructure{ObjectMeta: v1.ObjectMeta{Name: "cluster"}, Status: configv1.InfrastructureStatus{Platform: c.platform}}); err != nil {
				t.Fatal(err.Error())
			}
			if err := fgIndexer.Add(&configv1.FeatureGate{
				ObjectMeta: v1.ObjectMeta{Name: "cluster"},
				Spec: configv1.FeatureGateSpec{
					FeatureGateSelection: c.fgSelection,
				}}); err != nil {
				t.Fatal(err.Error())
			}
			listers := FakeInfrastructureLister{
				InfrastructureLister_: configlistersv1.NewInfrastructureLister(indexer),
				ResourceSync:          &FakeResourceSyncer{},
				ConfigMapLister_:      &FakeConfigMapLister{},
				FeatureGateLister_:    configlistersv1.NewFeatureGateLister(fgIndexer),
			}
			result, errs := ObserveCloudVolumePlugin(listers, events.NewInMemoryRecorder("cloud-volume"), map[string]interface{}{})
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			cloudVolumePlugin, _, err := unstructured.NestedStringSlice(result, "extendedArguments", "external-cloud-volume-plugin")
			if err != nil {
				t.Fatal(err)
			}

			if strings.Join(cloudVolumePlugin, "") != c.expected {
				t.Errorf("expected --external-cloud-volume-plugin=%s, got %s", c.expected, cloudVolumePlugin)
			}
		})
	}
}

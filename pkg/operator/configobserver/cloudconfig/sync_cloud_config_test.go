package cloudprovider

import (
	"fmt"
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	corelisterv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

type FakeResourceSyncer struct {
	syncedDestinations []resourcesynccontroller.ResourceLocation
}

func (fakeSyncer *FakeResourceSyncer) SyncConfigMap(destination, source resourcesynccontroller.ResourceLocation) error {
	fakeSyncer.syncedDestinations = append(fakeSyncer.syncedDestinations, source)
	fakeSyncer.syncedDestinations = append(fakeSyncer.syncedDestinations, destination)
	return nil
}

func (fakeSyncer *FakeResourceSyncer) SyncSecret(destination, source resourcesynccontroller.ResourceLocation) error {
	return nil
}

type FakeInfrastructureLister struct {
	InfrastructureLister_ configlistersv1.InfrastructureLister
	ResourceSync          resourcesynccontroller.ResourceSyncer
	PreRunCachesSynced    []cache.InformerSynced
	ConfigMapLister_      corelisterv1.ConfigMapLister
	FeatureGateLister_    configlistersv1.FeatureGateLister
}

func (l FakeInfrastructureLister) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return l.ResourceSync
}

func (l FakeInfrastructureLister) InfrastructureLister() configlistersv1.InfrastructureLister {
	return l.InfrastructureLister_
}

func (l FakeInfrastructureLister) PreRunHasSynced() []cache.InformerSynced {
	return l.PreRunCachesSynced
}

func (l FakeInfrastructureLister) ConfigMapLister() corelisterv1.ConfigMapLister {
	return l.ConfigMapLister_
}

func (l FakeInfrastructureLister) FeatureGateLister() configlistersv1.FeatureGateLister {
	return l.FeatureGateLister_
}

type FakeInfraLister struct {
	err error
}

func (f *FakeInfraLister) List(_ labels.Selector) ([]*configv1.Infrastructure, error) {
	return nil, nil
}

func (f *FakeInfraLister) Get(_ string) (*configv1.Infrastructure, error) {
	return nil, f.err
}

func TestGetCloudProviderConfig(t *testing.T) {
	defaultCloudConfig := &corev1.ConfigMap{}
	defaultCloudConfig.SetName(machineSpecifiedConfig)
	defaultCloudConfig.SetNamespace(machineSpecifiedConfigNamespace)

	cases := []struct {
		platform                 configv1.PlatformType
		configRef                configv1.ConfigMapFileReference
		createDeafaultConfigMap  bool
		infrastructureFetchError error
		expectDestinations       []resourcesynccontroller.ResourceLocation
		expectErrs               bool
	}{{
		platform:                configv1.AzurePlatformType,
		createDeafaultConfigMap: true,
		expectDestinations: []resourcesynccontroller.ResourceLocation{{
			Namespace: "openshift-config-managed",
			Name:      "kube-cloud-config",
			Provider:  "azure",
		}, {
			Namespace: "test",
			Name:      "cloud-config",
			Provider:  "azure",
		}},
	}, {
		platform:                configv1.GCPPlatformType,
		createDeafaultConfigMap: true,
		expectDestinations: []resourcesynccontroller.ResourceLocation{{
			Namespace: "openshift-config-managed",
			Name:      "kube-cloud-config",
			Provider:  "gce",
		}, {
			Namespace: "test",
			Name:      "cloud-config",
			Provider:  "gce",
		}},
	}, {
		platform:                configv1.OpenStackPlatformType,
		createDeafaultConfigMap: true,
		expectDestinations: []resourcesynccontroller.ResourceLocation{{
			Namespace: "openshift-config-managed",
			Name:      "kube-cloud-config",
			Provider:  "openstack",
		}, {
			Namespace: "test",
			Name:      "cloud-config",
			Provider:  "openstack",
		}},
	}, {
		platform:                configv1.VSpherePlatformType,
		createDeafaultConfigMap: true,
		expectDestinations: []resourcesynccontroller.ResourceLocation{{
			Namespace: "openshift-config-managed",
			Name:      "kube-cloud-config",
			Provider:  "vsphere",
		}, {
			Namespace: "test",
			Name:      "cloud-config",
			Provider:  "vsphere",
		}},
	}, {
		platform:                configv1.BareMetalPlatformType,
		createDeafaultConfigMap: true,
	}, {
		platform:                configv1.LibvirtPlatformType,
		createDeafaultConfigMap: true,
	}, {
		platform:                "",
		createDeafaultConfigMap: true,
		expectErrs:              true,
	}, {
		platform: configv1.AzurePlatformType,
		configRef: configv1.ConfigMapFileReference{
			Name: "other-cloud-config",
			Key:  "test",
		},
		expectDestinations: []resourcesynccontroller.ResourceLocation{{
			Namespace: configNamespace,
			Name:      "other-cloud-config",
			Provider:  "azure",
		}, {
			Namespace: "test",
			Name:      "cloud-config",
			Provider:  "azure",
		}},
	}, {
		platform:                configv1.AzurePlatformType,
		createDeafaultConfigMap: true,
		configRef: configv1.ConfigMapFileReference{
			Name: "other-cloud-config",
			Key:  "test",
		},
		expectDestinations: []resourcesynccontroller.ResourceLocation{{
			Namespace: "openshift-config-managed",
			Name:      "kube-cloud-config",
			Provider:  "azure",
		}, {
			Namespace: "test",
			Name:      "cloud-config",
			Provider:  "azure",
		}},
	}, {
		platform:                 configv1.AWSPlatformType,
		infrastructureFetchError: fmt.Errorf("just some error"),
		expectErrs:               true,
	}, {
		platform:                 configv1.AWSPlatformType,
		infrastructureFetchError: errors.NewNotFound(schema.GroupResource{}, ""),
		expectErrs:               true,
	}}
	for _, c := range cases {
		t.Run(string(c.platform), func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			cloudConfigConfigMap := defaultCloudConfig.DeepCopy()
			if c.configRef != (configv1.ConfigMapFileReference{}) {
				cloudConfigConfigMap.SetName(c.configRef.Name)
			}
			if err := indexer.Add(cloudConfigConfigMap); err != nil {
				t.Fatal(err.Error())
			}
			if c.createDeafaultConfigMap {
				if err := indexer.Add(defaultCloudConfig); err != nil {
					t.Fatal(err.Error())
				}
			}
			infrastructure := &configv1.Infrastructure{ObjectMeta: v1.ObjectMeta{Name: "cluster"},
				Spec:   configv1.InfrastructureSpec{CloudConfig: c.configRef},
				Status: configv1.InfrastructureStatus{Platform: c.platform}}
			if err := indexer.Add(infrastructure); err != nil {
				t.Fatal(err.Error())
			}

			infraLister := configlistersv1.NewInfrastructureLister(indexer)
			if c.infrastructureFetchError != nil {
				infraLister = &FakeInfraLister{err: c.infrastructureFetchError}
			}

			syncer := &FakeResourceSyncer{
				syncedDestinations: []resourcesynccontroller.ResourceLocation{},
			}
			listers := FakeInfrastructureLister{
				ResourceSync:          syncer,
				ConfigMapLister_:      corelisterv1.NewConfigMapLister(indexer),
				InfrastructureLister_: infraLister,
			}
			cloudConfigSyncer := NewCloudConfigSyncer("test")
			config := map[string]interface{}{}
			updatedConfig, errs := cloudConfigSyncer(listers, events.NewInMemoryRecorder("cloud"), config)
			if errorsFound := len(errs) > 0; errorsFound != c.expectErrs {
				t.Errorf("got unexpected errors %+v", errs)
			}

			if !equality.Semantic.DeepEqual(syncer.syncedDestinations, c.expectDestinations) {
				t.Errorf("expected cloud config syncronized between %#v, got %#v", c.expectDestinations, syncer.syncedDestinations)
			}
			if !equality.Semantic.DeepEqual(updatedConfig, config) {
				t.Errorf("expected no changes in config flags %#v, got  %#v", config, updatedConfig)
			}
		})
	}
}

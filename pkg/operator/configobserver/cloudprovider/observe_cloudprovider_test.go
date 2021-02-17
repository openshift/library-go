package cloudprovider

import (
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	corelisterv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

type FakeResourceSyncer struct{}

func (fakeSyncer *FakeResourceSyncer) SyncConfigMap(destination, source resourcesynccontroller.ResourceLocation) error {
	return nil
}

func (fakeSyncer *FakeResourceSyncer) SyncSecret(destination, source resourcesynccontroller.ResourceLocation) error {
	return nil
}

type FakeConfigMapLister struct{}

func (fakeCMLister *FakeConfigMapLister) ConfigMaps(ns string) corelisterv1.ConfigMapNamespaceLister {
	return fakeCMLister
}

func (fakeCMLister *FakeConfigMapLister) List(selector labels.Selector) ([]*corev1.ConfigMap, error) {
	return nil, nil
}

func (fakeCMLister *FakeConfigMapLister) Get(cm string) (*corev1.ConfigMap, error) {
	return nil, errors.NewNotFound(schema.GroupResource{}, "")
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

func TestObserveCloudProviderNames(t *testing.T) {
	cases := []struct {
		platform           configv1.PlatformType
		expected           string
		cloudProviderCount int
	}{{
		platform:           configv1.AWSPlatformType,
		expected:           "aws",
		cloudProviderCount: 1,
	}, {
		platform:           configv1.AzurePlatformType,
		expected:           "azure",
		cloudProviderCount: 1,
	}, {
		platform:           configv1.BareMetalPlatformType,
		cloudProviderCount: 0,
	}, {
		platform:           configv1.LibvirtPlatformType,
		cloudProviderCount: 0,
	}, {
		platform:           configv1.OpenStackPlatformType,
		expected:           "openstack",
		cloudProviderCount: 1,
	}, {
		platform:           configv1.GCPPlatformType,
		expected:           "gce",
		cloudProviderCount: 1,
	}, {
		platform:           configv1.NonePlatformType,
		cloudProviderCount: 0,
	}, {
		platform:           "",
		cloudProviderCount: 0,
	}}
	for _, c := range cases {
		t.Run(string(c.platform), func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := indexer.Add(&configv1.Infrastructure{ObjectMeta: v1.ObjectMeta{Name: "cluster"}, Status: configv1.InfrastructureStatus{Platform: c.platform}}); err != nil {
				t.Fatal(err.Error())
			}
			listers := FakeInfrastructureLister{
				InfrastructureLister_: configlistersv1.NewInfrastructureLister(indexer),
				ResourceSync:          &FakeResourceSyncer{},
				ConfigMapLister_:      &FakeConfigMapLister{},
			}
			cloudProvidersPath := []string{"extendedArguments", "cloud-provider"}
			cloudProviderConfPath := []string{"extendedArguments", "cloud-config"}
			observerFunc := NewCloudProviderObserver("kube-controller-manager", cloudProvidersPath, cloudProviderConfPath)
			result, errs := observerFunc(listers, events.NewInMemoryRecorder("cloud"), map[string]interface{}{})
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			cloudProvider, _, err := unstructured.NestedSlice(result, "extendedArguments", "cloud-provider")
			if err != nil {
				t.Fatal(err)
			}
			if e, a := c.cloudProviderCount, len(cloudProvider); e != a {
				t.Fatalf("expected len(cloudProvider) == %d, got %d", e, a)
			}
			if c.cloudProviderCount > 0 {
				if e, a := c.expected, cloudProvider[0]; e != a {
					t.Errorf("expected cloud-provider=%s, got %s", e, a)
				}
			}
		})
	}
}

func TestGetCloudProviderConfig(t *testing.T) {
	defaultCloudConfig := &corev1.ConfigMap{}
	defaultCloudConfig.SetName(machineSpecifiedConfig)
	defaultCloudConfig.SetNamespace(machineSpecifiedConfigNamespace)

	cases := []struct {
		platform                configv1.PlatformType
		configRef               configv1.ConfigMapFileReference
		createDeafaultConfigMap bool
		expectedConfig          string
		expectErrs              []error
	}{{
		platform:       configv1.AWSPlatformType,
		expectedConfig: "/etc/kubernetes/static-pod-resources/configmaps/cloud-config/cloud.conf",
	}, {
		platform:       configv1.AzurePlatformType,
		expectedConfig: "/etc/kubernetes/static-pod-resources/configmaps/cloud-config/cloud.conf",
	}, {
		platform:       configv1.GCPPlatformType,
		expectedConfig: "/etc/kubernetes/static-pod-resources/configmaps/cloud-config/cloud.conf",
	}, {
		platform:       configv1.OpenStackPlatformType,
		expectedConfig: "/etc/kubernetes/static-pod-resources/configmaps/cloud-config/cloud.conf",
	}, {
		platform:       configv1.VSpherePlatformType,
		expectedConfig: "/etc/kubernetes/static-pod-resources/configmaps/cloud-config/cloud.conf",
	}, {
		platform:       configv1.BareMetalPlatformType,
		expectedConfig: "",
	}, {
		platform:       configv1.LibvirtPlatformType,
		expectedConfig: "",
	}, {
		platform:       "",
		expectedConfig: "",
	}, {
		platform: configv1.AWSPlatformType,
		configRef: configv1.ConfigMapFileReference{
			Name: "other-cloud-config",
			Key:  "test",
		},
		expectedConfig: "/etc/kubernetes/static-pod-resources/configmaps/cloud-config/test",
	}, {
		platform: configv1.AWSPlatformType,
		configRef: configv1.ConfigMapFileReference{
			Name: "other-cloud-config",
			Key:  "test",
		},
		createDeafaultConfigMap: true,
		expectedConfig:          "/etc/kubernetes/static-pod-resources/configmaps/cloud-config/cloud.conf",
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
			listers := FakeInfrastructureLister{
				ResourceSync:     &FakeResourceSyncer{},
				ConfigMapLister_: corelisterv1.NewConfigMapLister(indexer),
			}
			cloudObserver := &cloudProviderObserver{targetNamespaceName: "kube-controller-manager"}
			cloudProviderConfig, errs := cloudObserver.getCloudProviderConfig(listers, events.NewInMemoryRecorder("cloud"), infrastructure)
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			if cloudProviderConfig != c.expectedConfig {
				t.Fatalf("expected cloud-config == %s, got %s", c.expectedConfig, cloudProviderConfig)
			}
		})
	}
}

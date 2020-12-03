package etcd

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/mergepatch"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func TestObserveStorageURLsAndObserveStorageURLsToArguments(t *testing.T) {
	tests := []struct {
		name              string
		currentConfigFor  func(...string) map[string]interface{}
		fallback          fallBackObserverFn
		expectedConfigFor func(...string) map[string]interface{}
		expectErrors      bool
		endpoint          *v1.ConfigMap
	}{
		{
			name:              "ValidIPv4",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpoints(withAddress("10.0.0.1")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")),
		},
		{
			name:              "ValidIPv6",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpoints(withAddress("FE80:CD00:0000:0CDE:1257:0000:211E:729C")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://[fe80:cd00:0:cde:1257:0:211e:729c]:2379")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, useAPIServerArguments := range []bool{false, true} {
				indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
				listers := testLister{
					cmLister: corev1listers.NewConfigMapLister(indexer),
				}
				if tt.endpoint != nil {
					if err := indexer.Add(tt.endpoint); err != nil {
						t.Fatalf("error adding endpoint to store: %#v", err)
					}
				}

				actual := map[string]interface{}{}
				expected := map[string]interface{}{}
				errs := []error{}
				if useAPIServerArguments {
					actual, errs = ObserveStorageURLsToArguments(listers, events.NewInMemoryRecorder("test"), tt.currentConfigFor("apiServerArguments", "etcd-servers"))
					expected = tt.expectedConfigFor("apiServerArguments", "etcd-servers")
				} else {
					actual, errs = ObserveStorageURLs(listers, events.NewInMemoryRecorder("test"), tt.currentConfigFor("storageConfig", "urls"))
					expected = tt.expectedConfigFor("storageConfig", "urls")
				}
				if tt.expectErrors && len(errs) == 0 {
					t.Errorf("errors expectedConfigFor")
				}
				if !tt.expectErrors && len(errs) != 0 {
					t.Errorf("unexpected errors: %v", errs)
				}
				if !reflect.DeepEqual(actual, expected) {
					t.Errorf("ObserveStorageURLs() gotObservedConfig = %v, want %v", actual, expected)
				}
				if t.Failed() {
					t.Log("\n" + mergepatch.ToYAMLOrError(actual))
					for _, err := range errs {
						t.Log(err)
					}
				}
			}
		})
	}
}

func TestInnerObserveStorageURLs(t *testing.T) {
	tests := []struct {
		name              string
		currentConfigFor  func(...string) map[string]interface{}
		fallbackFor       func(...string) fallBackObserverFn
		expectedConfigFor func(...string) map[string]interface{}
		expectErrors      bool
		endpoint          *v1.ConfigMap
	}{
		{
			name:              "NoConfigMapSuccessfulFallback",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			fallbackFor:       fallbackFor(observedConfigFor(withStorageURLFor("https://10.0.0.1:2379"))),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")),
			expectErrors:      false,
		},
		{
			name:              "NoConfigMapFailedFallback",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			fallbackFor:       fallbackFor(observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")), fmt.Errorf("endpoint not found")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			expectErrors:      true,
		},
		{
			name:              "ValidIPv4",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpoints(withAddress("10.0.0.1"), withAddress("192.0.2.1")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379"), withStorageURLFor("https://192.0.2.1:2379")),
		},
		{
			name:             "InvalidIPv4",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpoints(
				withAddress("10.0.0.1"),
				withAddress("192.192.0.2.1"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")),
			expectErrors:      true,
		},
		{
			name:              "ValidIPv6",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpoints(withAddress("FE80:CD00:0000:0CDE:1257:0000:211E:729C"), withAddress("2001:0DB8:0000:0CDE:1257:0000:211E:729C")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://[2001:db8:0:cde:1257:0:211e:729c]:2379"), withStorageURLFor("https://[fe80:cd00:0:cde:1257:0:211e:729c]:2379")),
		},
		{
			name:             "InvalidIPv6",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpoints(
				withAddress("FE80:CD00:0000:0CDE:1257:0000:211E:729C"),
				withAddress("FE80:CD00:0000:0CDE:1257:0000:211E:729C:invalid"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://[fe80:cd00:0:cde:1257:0:211e:729c]:2379")),
			expectErrors:      true,
		},
		{
			name:              "ValidIPv4AsIPv6Literal",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpoints(withAddress("::ffff:a00:1")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")),
		},
		{
			name:             "IPv4AsIPv6Literal",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpoints(
				withAddress("FE80:CD00:0000:0CDE:1257:0000:211E:729C"),
				withAddress("::ffff:c000:201"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://192.0.2.1:2379"), withStorageURLFor("https://[fe80:cd00:0:cde:1257:0:211e:729c]:2379")),
		},
		{
			name:              "NoAddressesFound",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpoints(),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			expectErrors:      true,
		},
		{
			name:             "OnlyInvalidAddressesFound",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpoints(
				withAddress("0.192.0.2.1"),
				withAddress("::ffff:c000:201:invalid"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			expectErrors:      true,
		},
		{
			name:             "IgnoreBootstrap",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpoints(
				withBootstrap("10.0.0.2"),
				withAddress("10.0.0.1"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			listers := testLister{
				cmLister: corev1listers.NewConfigMapLister(indexer),
			}
			if tt.endpoint != nil {
				if err := indexer.Add(tt.endpoint); err != nil {
					t.Fatalf("error adding endpoint to store: %#v", err)
				}
			}
			storageConfigURLsPath := []string{"storageConfig", "urls"}
			if tt.fallbackFor == nil {
				tt.fallbackFor = fallbackFor(nil)
			}
			actual, errs := innerObserveStorageURLs(tt.fallbackFor(storageConfigURLsPath...), false, listers, events.NewInMemoryRecorder("test"), tt.currentConfigFor(storageConfigURLsPath...), storageConfigURLsPath)
			if tt.expectErrors && len(errs) == 0 {
				t.Errorf("errors expectedConfigFor")
			}
			if !tt.expectErrors && len(errs) != 0 {
				t.Errorf("unexpected errors: %v", errs)
			}

			expected := map[string]interface{}{}
			expected = tt.expectedConfigFor(storageConfigURLsPath...)
			if !reflect.DeepEqual(actual, expected) {
				t.Errorf("ObserveStorageURLs() gotObservedConfig = %v, want %v", actual, expected)
			}
			if t.Failed() {
				t.Log("\n" + mergepatch.ToYAMLOrError(actual))
				for _, err := range errs {
					t.Log(err)
				}
			}
		})
	}
}

func TestObserveStorageURLsFromOldEndPoint(t *testing.T) {
	tests := []struct {
		name              string
		currentConfigFor  func(...string) map[string]interface{}
		expectedConfigFor func(...string) map[string]interface{}
		expectErrors      bool
		endpoint          *v1.Endpoints
	}{
		{
			name:              "NoEtcdHosts",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			expectErrors:      true,
		},
		{
			name:              "ValidIPv4",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpointsOld(withAddressOld("test", "10.0.0.1")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")),
		},
		{
			name:             "InvalidIPv4",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpointsOld(
				withAddressOld("test-0", "10.0.0.1"),
				withAddressOld("test-1", "192.192.0.2.1"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")),
			expectErrors:      true,
		},
		{
			name:              "ValidIPv6",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpointsOld(withAddressOld("test", "FE80:CD00:0000:0CDE:1257:0000:211E:729C")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://[fe80:cd00:0:cde:1257:0:211e:729c]:2379")),
		},
		{
			name:             "InvalidIPv6",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpointsOld(
				withAddressOld("test-0", "FE80:CD00:0000:0CDE:1257:0000:211E:729C"),
				withAddressOld("test-1", "FE80:CD00:0000:0CDE:1257:0000:211E:729C:invalid"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://[fe80:cd00:0:cde:1257:0:211e:729c]:2379")),
			expectErrors:      true,
		},
		{
			name:             "FakeIPv4",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpointsOld(
				withAddressOld("test-0", "10.0.0.1"),
				withAddressOld("test-1", "192.0.2.1"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")),
		},
		{
			name:             "FakeIPv6",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpointsOld(
				withAddressOld("test-0", "FE80:CD00:0000:0CDE:1257:0000:211E:729C"),
				withAddressOld("test-1", "2001:0DB8:0000:0CDE:1257:0000:211E:729C"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://[fe80:cd00:0:cde:1257:0:211e:729c]:2379")),
		},
		{
			name:              "ValidIPv4AsIPv6Literal",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpointsOld(withAddressOld("test", "::ffff:a00:1")),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://10.0.0.1:2379")),
		},
		{
			name:             "FakeIPv4AsIPv6Literal",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpointsOld(
				withAddressOld("test-0", "FE80:CD00:0000:0CDE:1257:0000:211E:729C"),
				withAddressOld("test-1", "::ffff:c000:201"),
			),
			expectedConfigFor: observedConfigFor(withStorageURLFor("https://[fe80:cd00:0:cde:1257:0:211e:729c]:2379")),
		},
		{
			name:              "NoAddressesFound",
			currentConfigFor:  observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint:          endpointsOld(),
			expectedConfigFor: observedConfigFor(),
			expectErrors:      true,
		},
		{
			name:             "OnlyFakeAddressesFound",
			currentConfigFor: observedConfigFor(withStorageURLFor("https://previous.url:2379")),
			endpoint: endpointsOld(
				withAddressOld("test-0", "192.0.2.1"),
				withAddressOld("test-1", "::ffff:c000:201"),
			),
			expectedConfigFor: observedConfigFor(),
			expectErrors:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			lister := testLister{
				epLister: corev1listers.NewEndpointsLister(indexer),
			}
			if tt.endpoint != nil {
				if err := indexer.Add(tt.endpoint); err != nil {
					t.Fatalf("error adding endpoint to store: %#v", err)
				}
			}
			storageConfigURLsPath := []string{"storageConfig", "urls"}
			actual, errs := innerObserveStorageURLsFromOldEndPoint(lister, events.NewInMemoryRecorder("test"), tt.currentConfigFor(storageConfigURLsPath...), storageConfigURLsPath)
			if tt.expectErrors && len(errs) == 0 {
				t.Errorf("errors expectedConfigFor")
			}
			if !tt.expectErrors && len(errs) != 0 {
				t.Errorf("unexpected errors: %v", errs)
			}
			expected := map[string]interface{}{}
			expected = tt.expectedConfigFor(storageConfigURLsPath...)
			if !reflect.DeepEqual(actual, expected) {
				t.Errorf("ObserveStorageURLs() gotObservedConfig = %v, want %v", actual, expected)
			}
			if t.Failed() {
				t.Log("\n" + mergepatch.ToYAMLOrError(actual))
				for _, err := range errs {
					t.Log(err)
				}
			}
		})
	}
}

func observedConfigFor(configs ...func(map[string]interface{}, ...string)) func(...string) map[string]interface{} {
	return func(fields ...string) map[string]interface{} {
		observedConfig := map[string]interface{}{}
		for _, config := range configs {
			config(observedConfig, fields...)
		}
		return observedConfig
	}
}

func withStorageURLFor(url string) func(map[string]interface{}, ...string) {
	return func(observedConfig map[string]interface{}, fields ...string) {
		urls, _, _ := unstructured.NestedStringSlice(observedConfig, fields...)
		urls = append(urls, url)
		_ = unstructured.SetNestedStringSlice(observedConfig, urls, fields...)
	}
}

func endpoints(configs ...func(endpoints *v1.ConfigMap)) *v1.ConfigMap {
	endpoints := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "etcd-endpoints",
			Namespace: "openshift-etcd",
		},
		Data: map[string]string{},
	}
	for _, config := range configs {
		config(endpoints)
	}
	return endpoints
}

func withBootstrap(ip string) func(*v1.ConfigMap) {
	return func(endpoints *v1.ConfigMap) {
		if endpoints.Annotations == nil {
			endpoints.Annotations = map[string]string{}
		}
		endpoints.Annotations["alpha.installer.openshift.io/etcd-bootstrap"] = ip
	}
}

func withAddress(ip string) func(*v1.ConfigMap) {
	return func(endpoints *v1.ConfigMap) {
		endpoints.Data[base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(ip))] = ip
	}
}

func fallbackFor(observedFn func(...string) map[string]interface{}, errs ...error) func(...string) fallBackObserverFn {
	return func(fields ...string) fallBackObserverFn {
		return func(genericListers configobserver.Listers, recorder events.Recorder, currentConfig map[string]interface{}, storageConfigURLsPath []string) (map[string]interface{}, []error) {
			return observedFn(fields...), errs
		}
	}
}

func endpointsOld(configs ...func(endpoints *v1.Endpoints)) *v1.Endpoints {
	endpoints := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "host-etcd-2",
			Namespace: "openshift-etcd",
			Annotations: map[string]string{
				"alpha.installer.openshift.io/dns-suffix": "foo.bar",
			},
		},
		Subsets: []v1.EndpointSubset{{Addresses: []v1.EndpointAddress{}}},
	}
	for _, config := range configs {
		config(endpoints)
	}
	return endpoints
}

func withAddressOld(hostname, ip string) func(*v1.Endpoints) {
	return func(endpoints *v1.Endpoints) {
		endpoints.Subsets[0].Addresses = append(endpoints.Subsets[0].Addresses, v1.EndpointAddress{
			Hostname: hostname,
			IP:       ip,
		})
	}
}

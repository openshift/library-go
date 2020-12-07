package etcd

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	EtcdEndpointNamespace = "openshift-etcd"
	etcdEndpointName      = "etcd-endpoints"

	// EtcdEndpointName points to the old host-etcd-2 endpoint applicable for clusters prior to 4.5
	EtcdEndpointName = "host-etcd-2"
)

var (
	OldStorageConfigURLsPath = []string{"storageConfig", "urls"}
	StorageConfigURLsPath    = []string{"apiServerArguments", StorageConfigURLsKey}

	StorageConfigURLsKey = "etcd-servers"
)

type fallBackObserverFn func(genericListers configobserver.Listers, recorder events.Recorder, currentConfig map[string]interface{}, storageConfigURLsPath []string) (map[string]interface{}, []error)

// ObserveStorageURLs observes the storage config URLs and sets storageConfig field in the observerConfig under OldStorageConfigURLsPath.
// If there is a problem observing the current storage config URLs, then the previously observed storage config URLs will be re-used.
// This function always adds a localhost endpoint to the list of etcd servers.
func ObserveStorageURLsWithAlwaysLocal(genericListers configobserver.Listers, recorder events.Recorder, currentConfig map[string]interface{}) (map[string]interface{}, []error) {
	return innerObserveStorageURLs(nil, true, genericListers, recorder, currentConfig, OldStorageConfigURLsPath)
}

// ObserveStorageURLs observes the storage config URLs and sets storageConfig field in the observerConfig under StorageConfigURLsPath.
// If there is a problem observing the current storage config URLs, then the previously observed storage config URLs will be re-used.
// This function always adds a localhost endpoint to the list of etcd servers.
func ObserveStorageURLsToArgumentsWithAlwaysLocal(genericListers configobserver.Listers, recorder events.Recorder, currentConfig map[string]interface{}) (map[string]interface{}, []error) {
	return innerObserveStorageURLs(nil, true, genericListers, recorder, currentConfig, StorageConfigURLsPath)
}

// ObserveStorageURLs observes the storage config URLs and sets storageConfig field in the observerConfig under OldStorageConfigURLsPath.
// If there is a problem observing the current storage config URLs, then the previously observed storage config URLs will be re-used.
func ObserveStorageURLs(genericListers configobserver.Listers, recorder events.Recorder, currentConfig map[string]interface{}) (map[string]interface{}, []error) {
	return innerObserveStorageURLs(innerObserveStorageURLsFromOldEndPoint, false, genericListers, recorder, currentConfig, OldStorageConfigURLsPath)
}

// ObserveStorageURLs observes the storage config URLs and sets storageConfig field in the observerConfig under StorageConfigURLsPath.
// If there is a problem observing the current storage config URLs, then the previously observed storage config URLs will be re-used.
func ObserveStorageURLsToArguments(genericListers configobserver.Listers, recorder events.Recorder, currentConfig map[string]interface{}) (map[string]interface{}, []error) {
	return innerObserveStorageURLs(innerObserveStorageURLsFromOldEndPoint, false, genericListers, recorder, currentConfig, StorageConfigURLsPath)
}

func innerObserveStorageURLs(fallbackObserver fallBackObserverFn, alwaysAppendLocalhost bool, genericListers configobserver.Listers, recorder events.Recorder, currentConfig map[string]interface{}, storageConfigURLsPath []string) (ret map[string]interface{}, _ []error) {
	defer func() {
		ret = configobserver.Pruned(ret, storageConfigURLsPath)
	}()

	lister := genericListers.(ConfigMapLister)
	var errs []error

	previouslyObservedConfig := map[string]interface{}{}
	currentEtcdURLs, found, err := unstructured.NestedStringSlice(currentConfig, storageConfigURLsPath...)
	if err != nil {
		errs = append(errs, err)
	}
	if found {
		if err := unstructured.SetNestedStringSlice(previouslyObservedConfig, currentEtcdURLs, storageConfigURLsPath...); err != nil {
			errs = append(errs, err)
		}
	}

	var etcdURLs []string
	etcdEndpoints, err := lister.ConfigMapLister().ConfigMaps(EtcdEndpointNamespace).Get(etcdEndpointName)
	if errors.IsNotFound(err) && fallbackObserver != nil {
		// In clusters prior to 4.5, fall back to reading the old host-etcd-2 endpoint
		// resource, if possible. In 4.6 we can assume consumers have been updated to
		// use the configmap, delete the fallback code, and throw an error if the
		// configmap doesn't exist.
		observedConfig, fallbackErrors := fallbackObserver(genericListers, recorder, currentConfig, storageConfigURLsPath)
		if len(fallbackErrors) > 0 {
			errs = append(errs, fallbackErrors...)
			return previouslyObservedConfig, append(errs, fmt.Errorf("configmap %s/%s not found, and fallback observer failed", EtcdEndpointNamespace, etcdEndpointName))
		}
		return observedConfig, errs
	}
	if err != nil {
		recorder.Warningf("ObserveStorageFailed", "Error getting %s/%s configmap: %v", EtcdEndpointNamespace, etcdEndpointName, err)
		return previouslyObservedConfig, append(errs, err)
	}

	// note: etcd bootstrap should never be added to the in-cluster kube-apiserver
	// this can result in some early pods crashlooping, but ensures that we never contact the bootstrap machine from
	// the in-cluster kube-apiserver so we can safely teardown out of order.

	for k := range etcdEndpoints.Data {
		address := etcdEndpoints.Data[k]
		ip := net.ParseIP(address)
		if ip == nil {
			ipErr := fmt.Errorf("configmaps/%s in the %s namespace: %v is not a valid IP address", etcdEndpointName, EtcdEndpointNamespace, address)
			errs = append(errs, ipErr)
			continue
		}
		// use the canonical representation of the ip address (not original input) when constructing the url
		if ip.To4() != nil {
			etcdURLs = append(etcdURLs, fmt.Sprintf("https://%s:2379", ip))
		} else {
			etcdURLs = append(etcdURLs, fmt.Sprintf("https://[%s]:2379", ip))
		}
	}

	if len(etcdURLs) == 0 {
		emptyURLErr := fmt.Errorf("configmaps %s/%s: no etcd endpoint addresses found", EtcdEndpointNamespace, etcdEndpointName)
		recorder.Warning("ObserveStorageFailed", emptyURLErr.Error())
		errs = append(errs, emptyURLErr)
		if !alwaysAppendLocalhost {
			return previouslyObservedConfig, errs
		}
	}

	if alwaysAppendLocalhost {
		etcdURLs = append(etcdURLs, "https://localhost:2379")
	}

	sort.Strings(etcdURLs)

	observedConfig := map[string]interface{}{}
	if err := unstructured.SetNestedStringSlice(observedConfig, etcdURLs, storageConfigURLsPath...); err != nil {
		return previouslyObservedConfig, append(errs, err)
	}

	if !reflect.DeepEqual(currentEtcdURLs, etcdURLs) {
		recorder.Eventf("ObserveStorageUpdated", "Updated storage urls to %s", strings.Join(etcdURLs, ","))
	}

	return observedConfig, errs
}

// innerObserveStorageURLsFromOldEndPoint observes the storage URL config.
func innerObserveStorageURLsFromOldEndPoint(genericListers configobserver.Listers, recorder events.Recorder, currentConfig map[string]interface{}, storageConfigURLsPath []string) (map[string]interface{}, []error) {
	lister := genericListers.(EndpointsLister)
	var errs []error

	previouslyObservedConfig := map[string]interface{}{}
	currentEtcdURLs, _, err := unstructured.NestedStringSlice(currentConfig, storageConfigURLsPath...)
	if err != nil {
		errs = append(errs, err)
	}
	if len(currentEtcdURLs) > 0 {
		if err := unstructured.SetNestedStringSlice(previouslyObservedConfig, currentEtcdURLs, storageConfigURLsPath...); err != nil {
			errs = append(errs, err)
		}
	}

	observedConfig := map[string]interface{}{}

	var etcdURLs sort.StringSlice
	etcdEndpoints, err := lister.EndpointsLister().Endpoints(EtcdEndpointNamespace).Get(EtcdEndpointName)
	if errors.IsNotFound(err) {
		recorder.Warningf("ObserveStorageFailed", "Required endpoints/%s in the %s namespace not found.", EtcdEndpointName, EtcdEndpointNamespace)
		errs = append(errs, fmt.Errorf("endpoints/%s in the %s namespace: not found", EtcdEndpointName, EtcdEndpointNamespace))
		return previouslyObservedConfig, errs
	}
	if err != nil {
		recorder.Warningf("ObserveStorageFailed", "Error getting endpoints/%s in the %s namespace: %v", EtcdEndpointName, EtcdEndpointNamespace, err)
		errs = append(errs, err)
		return previouslyObservedConfig, errs
	}

	for subsetIndex, subset := range etcdEndpoints.Subsets {
		for addressIndex, address := range subset.Addresses {
			ip := net.ParseIP(address.IP)
			if ip == nil {
				ipErr := fmt.Errorf("endpoints/%s in the %s namespace: subsets[%v]addresses[%v].IP is not a valid IP address", EtcdEndpointName, EtcdEndpointNamespace, subsetIndex, addressIndex)
				errs = append(errs, ipErr)
				continue
			}
			// skip placeholder ip addresses used in previous versions where the hostname was used instead
			if strings.HasPrefix(ip.String(), "192.0.2.") || strings.HasPrefix(ip.String(), "2001:db8:") {
				// not considered an error
				continue
			}
			// use the canonical representation of the ip address (not original input) when constructing the url
			if ip.To4() != nil {
				etcdURLs = append(etcdURLs, fmt.Sprintf("https://%s:2379", ip))
			} else {
				etcdURLs = append(etcdURLs, fmt.Sprintf("https://[%s]:2379", ip))
			}
		}
	}

	// do not add empty storage urls slice to observed config, we don't want override defaults with an empty slice
	if len(etcdURLs) > 0 {
		etcdURLs.Sort()
		if err := unstructured.SetNestedStringSlice(observedConfig, etcdURLs, storageConfigURLsPath...); err != nil {
			errs = append(errs, err)
			return previouslyObservedConfig, errs
		}
	} else {
		err := fmt.Errorf("endpoints/%s in the %s namespace: no etcd endpoint addresses found, falling back to default etcd service", EtcdEndpointName, EtcdEndpointNamespace)
		recorder.Warningf("ObserveStorageFallback", err.Error())
		errs = append(errs, err)
	}

	if !reflect.DeepEqual(currentEtcdURLs, []string(etcdURLs)) {
		recorder.Eventf("ObserveStorageUpdated", "Updated storage urls to %s", strings.Join(etcdURLs, ","))
	}

	return observedConfig, errs
}

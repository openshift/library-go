package csiconfigobservercontroller

import (
	"strings"

	"k8s.io/client-go/tools/cache"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	libgoapiserver "github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/proxy"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// ProxyConfigPath returns the path for the observed proxy config. This is a
// function to avoid exposing a slice that could potentially be appended.
func ProxyConfigPath() []string {
	return []string{"targetcsiconfig", "proxy"}
}

// CipherSuitesPath returns the path for the observed TLS cipher suites. This
// is a function to avoid exposing a slice that could potentially be appended.
func CipherSuitesPath() []string {
	return []string{"targetcsiconfig", "servingInfo", "cipherSuites"}
}

// MinTLSVersionPath the path for the observed minimum TLS version. This
// is a function to avoid exposing a slice that could potentially be appended.
func MinTLSVersionPath() []string {
	return []string{"targetcsiconfig", "servingInfo", "minTLSVersion"}
}

// Listers implement the configobserver.Listers interface.
type Listers struct {
	ProxyLister_     configlistersv1.ProxyLister
	APIServerLister_ configlistersv1.APIServerLister

	ResourceSync       resourcesynccontroller.ResourceSyncer
	PreRunCachesSynced []cache.InformerSynced
}

func (l Listers) ProxyLister() configlistersv1.ProxyLister {
	return l.ProxyLister_
}

func (l Listers) APIServerLister() configlistersv1.APIServerLister {
	return l.APIServerLister_
}

func (l Listers) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return l.ResourceSync
}

func (l Listers) PreRunHasSynced() []cache.InformerSynced {
	return l.PreRunCachesSynced
}

// CISConfigObserverController watches information that's relevant to CSI driver operators.
// For now it only observes proxy information, (through the proxy.config.openshift.io/cluster
// object), but more will be added.
type CSIConfigObserverController struct {
	factory.Controller
}

// NewCSIConfigObserverController returns a new CSIConfigObserverController.
func NewCSIConfigObserverController(
	name string,
	operatorClient v1helpers.OperatorClient,
	configinformers configinformers.SharedInformerFactory,
	eventRecorder events.Recorder,
) *CSIConfigObserverController {
	informers := []factory.Informer{
		operatorClient.Informer(),
		configinformers.Config().V1().Proxies().Informer(),
	}

	c := &CSIConfigObserverController{
		Controller: configobserver.NewConfigObserver(
			operatorClient,
			eventRecorder.WithComponentSuffix("csi-config-observer-controller-"+strings.ToLower(name)),
			Listers{
				APIServerLister_: configinformers.Config().V1().APIServers().Lister(),
				ProxyLister_:     configinformers.Config().V1().Proxies().Lister(),
				PreRunCachesSynced: append([]cache.InformerSynced{},
					operatorClient.Informer().HasSynced,
					configinformers.Config().V1().Proxies().Informer().HasSynced,
					configinformers.Config().V1().APIServers().Informer().HasSynced,
				),
			},
			informers,
			proxy.NewProxyObserveFunc(ProxyConfigPath()),
			observeTLSSecurityProfile,
		),
	}

	return c
}

func observeTLSSecurityProfile(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	return libgoapiserver.ObserveTLSSecurityProfileWithPaths(genericListers, recorder, existingConfig, MinTLSVersionPath(), CipherSuitesPath())
}

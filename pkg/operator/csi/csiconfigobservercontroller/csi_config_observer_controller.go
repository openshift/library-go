package csiconfigobservercontroller

import (
	"strings"

	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/openshift/api/features"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	libgoapiserver "github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
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

// CurvePreferencesPath returns the path for the observed TLS group (curve)
// preferences. The values are stored as group names ([]string) matching the
// TLSGroup constants from openshift/api. This is a function to avoid exposing a
// slice that could potentially be appended.
func CurvePreferencesPath() []string {
	return []string{"targetcsiconfig", "servingInfo", "curvePreferences"}
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
	return newCSIConfigObserverController(name, operatorClient, configinformers, eventRecorder, observeTLSSecurityProfile, nil, nil)
}

// NewCSIConfigObserverControllerWithFeatureGates is like
// NewCSIConfigObserverController but also observes the TLS group (curve)
// preferences from TLSSecurityProfile. The observation is gated on the
// TLSGroupPreferences feature gate: curvePreferences are only written to the
// observed config when the gate is enabled. This matters because the TLSProfiles
// table in openshift/api bakes non-empty Groups into the predefined profiles
// (Old/Intermediate/Modern), and OCPSTRAT-3145 requires curves not be restricted
// before the feature is GA.
func NewCSIConfigObserverControllerWithFeatureGates(
	name string,
	operatorClient v1helpers.OperatorClient,
	configinformers configinformers.SharedInformerFactory,
	eventRecorder events.Recorder,
	featureGateAccess featuregates.FeatureGateAccess,
) *CSIConfigObserverController {
	observer := &tlsSecurityProfileObserver{featureGateAccess: featureGateAccess}
	// Watch the FeatureGates informer so the observer re-syncs once the initial
	// feature gates are observed (or when they change), rather than waiting for
	// the periodic resync to pick up curvePreferences.
	extraInformers := []factory.Informer{configinformers.Config().V1().FeatureGates().Informer()}
	extraCachesSynced := []cache.InformerSynced{configinformers.Config().V1().FeatureGates().Informer().HasSynced}
	return newCSIConfigObserverController(name, operatorClient, configinformers, eventRecorder, observer.observeTLSSecurityProfile, extraInformers, extraCachesSynced)
}

func newCSIConfigObserverController(
	name string,
	operatorClient v1helpers.OperatorClient,
	configinformers configinformers.SharedInformerFactory,
	eventRecorder events.Recorder,
	tlsSecurityProfileObserveFunc configobserver.ObserveConfigFunc,
	extraInformers []factory.Informer,
	extraCachesSynced []cache.InformerSynced,
) *CSIConfigObserverController {
	informers := append([]factory.Informer{
		operatorClient.Informer(),
		configinformers.Config().V1().Proxies().Informer(),
	}, extraInformers...)

	cachesSynced := append([]cache.InformerSynced{
		operatorClient.Informer().HasSynced,
		configinformers.Config().V1().Proxies().Informer().HasSynced,
		configinformers.Config().V1().APIServers().Informer().HasSynced,
	}, extraCachesSynced...)

	c := &CSIConfigObserverController{
		Controller: configobserver.NewConfigObserver(
			name,
			operatorClient,
			eventRecorder.WithComponentSuffix("csi-config-observer-controller-"+strings.ToLower(name)),
			Listers{
				APIServerLister_:   configinformers.Config().V1().APIServers().Lister(),
				ProxyLister_:       configinformers.Config().V1().Proxies().Lister(),
				PreRunCachesSynced: cachesSynced,
			},
			informers,
			proxy.NewProxyObserveFunc(ProxyConfigPath()),
			tlsSecurityProfileObserveFunc,
		),
	}

	return c
}

func observeTLSSecurityProfile(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	return libgoapiserver.ObserveTLSSecurityProfileWithPaths(genericListers, recorder, existingConfig, MinTLSVersionPath(), CipherSuitesPath())
}

// tlsSecurityProfileObserver observes the minimum TLS version, cipher suites and
// — when the TLSGroupPreferences feature gate is enabled — the TLS group (curve)
// preferences.
type tlsSecurityProfileObserver struct {
	featureGateAccess featuregates.FeatureGateAccess
}

// observeTLSSecurityProfile observes the TLS min version and cipher suites, and
// additionally the group (curve) preferences when TLSGroupPreferences is
// enabled. When the gate is disabled (or the initial feature gates have not been
// observed yet) the curvePreferences path is left unobserved, so it is dropped
// from the merged observed config rather than leaking the groups baked into the
// predefined profiles.
func (o *tlsSecurityProfileObserver) observeTLSSecurityProfile(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	// groupsPath stays nil unless the gate is observed AND enabled. A nil
	// groupsPath makes ObserveTLSSecurityProfileWithGroupPaths skip the curve
	// observation entirely (identical to not observing groups at all).
	var groupsPath []string
	switch {
	case !o.featureGateAccess.AreInitialFeatureGatesObserved():
		klog.V(4).Infof("initial feature gates not observed yet; not observing TLS curvePreferences")
	default:
		featureGates, err := o.featureGateAccess.CurrentFeatureGates()
		if err != nil {
			klog.V(2).Infof("could not read current feature gates (%v); not observing TLS curvePreferences", err)
		} else if featureGates.Enabled(features.FeatureGateTLSGroupPreferences) {
			groupsPath = CurvePreferencesPath()
		}
	}
	return libgoapiserver.ObserveTLSSecurityProfileWithGroupPaths(genericListers, recorder, existingConfig, MinTLSVersionPath(), CipherSuitesPath(), groupsPath)
}

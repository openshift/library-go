package customroute

import (
	"context"
	"fmt"
	"net/url"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	configsetterv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/retry"

	"github.com/openshift/library-go/pkg/certs"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/pkg/route/routecomponenthelpers"
)

type customRouteController struct {
	destSecret     types.NamespacedName
	componentRoute types.NamespacedName
	ingressLister  configlistersv1.IngressLister
	ingressClient  configsetterv1.IngressInterface
	routeLister    routev1lister.RouteLister
	routeClient    routeclient.RouteInterface
	secretLister   corev1listers.SecretLister
	resourceSyncer resourcesynccontroller.ResourceSyncer
	operatorClient v1helpers.OperatorClient
	routeAssetFunc resourceapply.AssetFunc
	routeAssetName string
	consumingUsers []configv1.ConsumingUser
}

// NewCustomRouteController creates a new controller for custom CA for Routes.
func NewCustomRouteController(
	componentRouteNamespace string,
	componentRouteName string,
	destSecretNamespace string,
	destSecretName string,
	routeAssetFunc resourceapply.AssetFunc,
	routeAssetName string,
	consumingUsers []configv1.ConsumingUser,
	ingressInformer configinformers.IngressInformer,
	ingressClient configsetterv1.IngressInterface,
	routeInformer routeinformer.RouteInformer,
	routeClient routeclient.RouteInterface,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	operatorClient v1helpers.OperatorClient,
	eventRecorder events.Recorder,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
) factory.Controller {
	controller := &customRouteController{
		destSecret: types.NamespacedName{
			Namespace: destSecretNamespace,
			Name:      destSecretName,
		},
		componentRoute: types.NamespacedName{
			Namespace: componentRouteNamespace,
			Name:      componentRouteName,
		},
		routeAssetFunc: routeAssetFunc,
		routeAssetName: routeAssetName,
		consumingUsers: consumingUsers,
		ingressLister:  ingressInformer.Lister(),
		ingressClient:  ingressClient,
		routeLister:    routeInformer.Lister(),
		routeClient:    routeClient,
		secretLister:   kubeInformersForNamespaces.SecretLister(),
		operatorClient: operatorClient,
		resourceSyncer: resourceSyncer,
	}

	return factory.New().
		WithInformers(
			ingressInformer.Informer(),
			routeInformer.Informer(),
			kubeInformersForNamespaces.InformersFor("openshift-config").Core().V1().Secrets().Informer(),
			kubeInformersForNamespaces.InformersFor(destSecretNamespace).Core().V1().Secrets().Informer(),
		).
		WithSyncDegradedOnError(operatorClient).
		WithSync(controller.sync).
		ResyncEvery(time.Minute).
		ToController("CustomRouteController", eventRecorder.WithComponentSuffix("custom-route-controller"))
}

func (c *customRouteController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	ingressConfig, err := c.ingressLister.Get("cluster")
	if err != nil {
		return err
	}

	ingressConfigCopy := ingressConfig.DeepCopy()

	route, errors := c.syncResources(ctx, syncCtx, ingressConfigCopy)
	return c.updateIngressConfigStatus(ctx, ingressConfigCopy, errors, route)
}

// syncResources reads the configured route from assets, applies it to the cluster,
// and synchronizes the secret of the underlying custom component route to the configured destination.
// It will always return a route.
func (c *customRouteController) syncResources(ctx context.Context, syncCtx factory.SyncContext, ingressConfig *configv1.Ingress) (*routev1.Route, []error) {
	route, secretName, errors := c.getRouteAndSecretName(ingressConfig)
	if errors != nil {
		return route, errors
	}

	if _, _, err := resourceapply.ApplyRoute(ctx, c.routeClient, syncCtx.Recorder(), route); err != nil {
		return route, []error{err}
	}

	if err := c.syncSecret(secretName); err != nil {
		return route, []error{err}
	}

	return route, []error{}
}

func mustAsset(fn resourceapply.AssetFunc, name string) []byte {
	a, err := fn(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}
	return a
}

// getRouteAndSecretName reads the route from the given asset function and executes basic validation on it.
// Even if validation fails, the route will always be returned.
func (c *customRouteController) getRouteAndSecretName(ingressConfig *configv1.Ingress) (*routev1.Route, string, []error) {
	route := resourceread.ReadRouteV1OrDie(mustAsset(c.routeAssetFunc, c.routeAssetName))
	// set defaults
	route.Spec.Host = route.ObjectMeta.Name + "." + ingressConfig.Spec.Domain // mimic the behavior of subdomain
	secretName := ""

	// check if a user is overriding route defaults
	if componentRoute := routecomponenthelpers.GetComponentRouteSpec(ingressConfig, route.ObjectMeta.Namespace, route.ObjectMeta.Name); componentRoute != nil {
		var errs []error
		// Check if the provided secret is valid
		secretName = componentRoute.ServingCertKeyPairSecret.Name
		if err := c.validateCustomTLSSecret(secretName); err != nil {
			errs = append(errs, err)
		}

		// Check if the provided hostname is valid
		hostname := string(componentRoute.Hostname)
		if _, err := url.Parse(hostname); err != nil {
			errs = append(errs, err)
		}

		if errs != nil {
			return route, "", errs
		}

		route.Spec.Host = hostname
	}

	return route, secretName, nil
}

func (c *customRouteController) validateCustomTLSSecret(secretName string) error {
	if len(secretName) != 0 {
		secret, err := c.secretLister.Secrets("openshift-config").Get(secretName)
		if err != nil {
			return err
		}

		var errors []error
		privateKeyData, ok := secret.Data[corev1.TLSPrivateKeyKey]
		if !ok {
			errors = append(errors, fmt.Errorf("custom route secret must include key %s", corev1.TLSPrivateKeyKey))
		} else {
			errors = append(errors, certs.ValidatePrivateKeyFormat(privateKeyData)...)
		}

		certData, ok := secret.Data[corev1.TLSCertKey]
		if !ok {
			errors = append(errors, fmt.Errorf("custom route secret must include key %s", corev1.TLSCertKey))
		} else {
			errors = append(errors, certs.ValidateServerCertValidity(certData)...)
		}

		if len(errors) != 0 {
			return fmt.Errorf("error validating secret %s/%s: %v", "openshift-config", secretName, errors)
		}
	}
	return nil
}

func (c *customRouteController) updateIngressConfigStatus(ctx context.Context, ingressConfig *configv1.Ingress, customRouteErrors []error, route *routev1.Route) error {
	componentRoute := &configv1.ComponentRouteStatus{
		Namespace:        c.componentRoute.Namespace,
		Name:             c.componentRoute.Name,
		DefaultHostname:  configv1.Hostname(route.ObjectMeta.Name + "." + ingressConfig.Spec.Domain),
		CurrentHostnames: []configv1.Hostname{configv1.Hostname(route.Spec.Host)},
		ConsumingUsers:   c.consumingUsers,
		RelatedObjects: []configv1.ObjectReference{
			{
				Group:     routev1.GroupName,
				Resource:  "routes",
				Name:      route.ObjectMeta.Name,
				Namespace: route.ObjectMeta.Namespace,
			},
		},
	}
	conditions := checkErrorsConfiguringCustomRoute(customRouteErrors)
	if conditions == nil {
		conditions = checkIngressURI(ingressConfig, route)
		if conditions == nil {
			conditions = checkRouteAvailablity(c.secretLister, ingressConfig, route)
		}
	}
	componentRoute.Conditions = ensureDefaultConditions(conditions)
	_, err := c.updateComponentRouteStatus(ctx, componentRoute)
	return err
}

func (c *customRouteController) syncSecret(secretName string) error {
	source := resourcesynccontroller.ResourceLocation{}
	if secretName != "" {
		source = resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: secretName}
	}

	destination := resourcesynccontroller.ResourceLocation{Namespace: c.destSecret.Namespace, Name: c.destSecret.Name}

	return c.resourceSyncer.SyncSecret(destination, source)
}

// updateComponentRouteStatus searches the entries of the ingress.status.componentRoutes array for a componentRoute with a matching namespace and name.
// If a matching componentRoute is found, the two objects are compared minus any of the conditions.lastTransactionTime entries. If all the fields
// match, the entry is updated.
// If no matching componentRoute is found, the entry is appended to the list.
// true is returned if the status of the ingress.config.openshift.io/cluster is updated.
func (c *customRouteController) updateComponentRouteStatus(ctx context.Context, componentRoute *configv1.ComponentRouteStatus) (bool, error) {
	// Override the timestamps
	now := metav1.Now()

	// Create a copy for comparison and remove transaction times
	componentRouteCopy := componentRoute.DeepCopy()
	setLastTransactionTime(componentRouteCopy, now)

	updated := false
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		ingressConfig, err := c.ingressClient.Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			return err
		}

		existingComponentRoute := routecomponenthelpers.GetComponentRouteStatus(ingressConfig, componentRoute.Namespace, componentRoute.Name)
		if existingComponentRoute != nil {
			// Create a copy for comparison and remove transaction times
			existingComponentRouteCopy := existingComponentRoute.DeepCopy()
			setLastTransactionTime(existingComponentRouteCopy, now)

			// Check if an update is needed
			if equality.Semantic.DeepEqual(componentRouteCopy, existingComponentRouteCopy) {
				return nil
			}
			*existingComponentRoute = *componentRoute
		} else {
			ingressConfig.Status.ComponentRoutes = append(ingressConfig.Status.ComponentRoutes, *componentRoute)
		}

		_, err = c.ingressClient.UpdateStatus(ctx, ingressConfig, metav1.UpdateOptions{})
		updated = err == nil
		return err
	})

	return updated, err
}

func setLastTransactionTime(componentRoute *configv1.ComponentRouteStatus, now metav1.Time) {
	for i := range componentRoute.Conditions {
		componentRoute.Conditions[i].LastTransitionTime = now
	}
}

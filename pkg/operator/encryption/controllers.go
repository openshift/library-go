package encryption

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers/migrators"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptionconfig"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"

	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"

	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
)

type runner interface {
	Run(ctx context.Context, workers int)
}

func NewControllers(
	component string,
	unsupportedConfigPrefix []string,
	provider controllers.Provider,
	deployer statemachine.Deployer,
	migrator migrators.Migrator,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	apiServerInformer configv1informers.APIServerInformer,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	secretsClient corev1.SecretsGetter,
	eventRecorder events.Recorder,
	resourceSyncer *resourcesynccontroller.ResourceSyncController,
) (*Controllers, error) {
	// avoid using the CachedSecretGetter as we need strong guarantees that our encryptionSecretSelector works
	// otherwise we could see secrets from a different component (which will break our keyID invariants)
	// this is fine in terms of performance since these controllers will be idle most of the time
	// TODO: update the eventHandlers used by the controllers to ignore components that do not match their own
	encryptionSecretSelector := metav1.ListOptions{LabelSelector: secrets.EncryptionKeySecretsLabel + "=" + component}

	encryptionEnabledChecker, err := newEncryptionEnabledPrecondition(apiServerInformer.Lister(), kubeInformersForNamespaces, encryptionSecretSelector.LabelSelector, component)
	if err != nil {
		return nil, err
	}

	// for testing resourceSyncer might be nil
	if resourceSyncer != nil {
		if err := resourceSyncer.SyncSecretConditionally(
			resourcesynccontroller.ResourceLocation{Namespace: component, Name: encryptionconfig.EncryptionConfSecretName},
			resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: fmt.Sprintf("%s-%s", encryptionconfig.EncryptionConfSecretName, component)},
			encryptionEnabledChecker.PreconditionFulfilled,
		); err != nil {
			return nil, err
		}
	}

	return &Controllers{
		controllers: []runner{
			controllers.NewKeyController(
				component,
				unsupportedConfigPrefix,
				provider,
				deployer,
				encryptionEnabledChecker.PreconditionFulfilled,
				operatorClient,
				apiServerClient,
				apiServerInformer,
				kubeInformersForNamespaces,
				secretsClient,
				encryptionSecretSelector,
				eventRecorder,
			),
			controllers.NewStateController(
				component,
				provider,
				deployer,
				encryptionEnabledChecker.PreconditionFulfilled,
				operatorClient,
				apiServerInformer,
				kubeInformersForNamespaces,
				secretsClient,
				encryptionSecretSelector,
				eventRecorder,
			),
			controllers.NewPruneController(
				component,
				provider,
				deployer,
				encryptionEnabledChecker.PreconditionFulfilled,
				operatorClient,
				apiServerInformer,
				kubeInformersForNamespaces,
				secretsClient,
				encryptionSecretSelector,
				eventRecorder,
			),
			controllers.NewMigrationController(
				component,
				provider,
				deployer,
				encryptionEnabledChecker.PreconditionFulfilled,
				migrator,
				operatorClient,
				apiServerInformer,
				kubeInformersForNamespaces,
				secretsClient,
				encryptionSecretSelector,
				eventRecorder,
			),
			controllers.NewConditionController(
				component,
				provider,
				deployer,
				encryptionEnabledChecker.PreconditionFulfilled,
				operatorClient,
				apiServerInformer,
				kubeInformersForNamespaces,
				secretsClient,
				encryptionSecretSelector,
				eventRecorder,
			),
		},
	}, nil
}

type Controllers struct {
	controllers []runner
}

func (c *Controllers) Run(ctx context.Context, workers int) {
	for _, controller := range c.controllers {
		con := controller // capture range variable
		go con.Run(ctx, workers)
	}
	<-ctx.Done()
}

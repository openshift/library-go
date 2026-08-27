package controllers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

// EncryptionConfigurationComputer computes the encryption configuration secret
// passed to the KMS preflight deployer right before it creates a new deployment.
type EncryptionConfigurationComputer interface {
	ComputeEncryptionConfiguration(ctx context.Context, kmsPluginConfig *configv1.KMSPluginConfig) (*corev1.Secret, error)
}

// encryptionConfigurationComputer is the default EncryptionConfigurationComputer.
// It derives the encryption configuration the preflight workload should run with by applying
// the same key-planning and config-computation path as the key and state controllers.
type encryptionConfigurationComputer struct {
	instanceName             string
	unsupportedConfigPrefix  []string
	provider                 Provider
	encryptionDeployer       statemachine.Deployer
	secretsClient            corev1client.SecretsGetter
	configMapsClient         corev1client.ConfigMapsGetter
	apiServerClient          configv1client.APIServerInterface
	operatorClient           operatorv1helpers.OperatorClient
	encryptionSecretSelector metav1.ListOptions
}

var _ EncryptionConfigurationComputer = (*encryptionConfigurationComputer)(nil)

func NewEncryptionConfigurationComputer(
	instanceName string,
	unsupportedConfigPrefix []string,
	provider Provider,
	encryptionDeployer statemachine.Deployer,
	secretsClient corev1client.SecretsGetter,
	configMapsClient corev1client.ConfigMapsGetter,
	apiServerClient configv1client.APIServerInterface,
	operatorClient operatorv1helpers.OperatorClient,
	encryptionSecretSelector metav1.ListOptions,
) EncryptionConfigurationComputer {
	return &encryptionConfigurationComputer{
		instanceName:             instanceName,
		unsupportedConfigPrefix:  unsupportedConfigPrefix,
		provider:                 provider,
		encryptionDeployer:       encryptionDeployer,
		secretsClient:            secretsClient,
		configMapsClient:         configMapsClient,
		apiServerClient:          apiServerClient,
		operatorClient:           operatorClient,
		encryptionSecretSelector: encryptionSecretSelector,
	}
}

func (c *encryptionConfigurationComputer) ComputeEncryptionConfiguration(ctx context.Context, kmsPluginConfig *configv1.KMSPluginConfig) (*corev1.Secret, error) {
	// ListKeysWhileProgressing=true so preflight can still list keys and compute a plan even when there
	// is no convergence yet. The key controller sets this to false to avoid extra Lists during rollout.
	planner := NewEncryptionPlanner(c.instanceName, c.unsupportedConfigPrefix, c.encryptionDeployer, c.secretsClient, c.configMapsClient, c.apiServerClient, c.operatorClient, c.encryptionSecretSelector)
	snap, err := planner.Load(ctx, c.provider.EncryptedGRs(), LoadOptions{
		ListKeysWhileProgressing: true,
		KMSPluginConfig:          kmsPluginConfig,
	})
	if err != nil {
		return nil, err
	}
	if snap.CurrentMode != "" && snap.CurrentMode != state.KMS {
		return nil, fmt.Errorf("preflight encryption config computation requires KMS mode, got %q", snap.CurrentMode)
	}

	plan, err := planner.PlanNextKey(snap)
	if err != nil {
		return nil, err
	}

	var plannedKey *PlannedEncryptionKey
	if plan.Needed {
		plannedKey, err = planner.MaterializeKey(ctx, snap, plan)
		if err != nil {
			return nil, err
		}
	}

	result, err := planner.ComputeConfig(&snap.State, plannedKey)
	if err != nil {
		return nil, err
	}
	if result.EncryptionSecret == nil {
		return nil, fmt.Errorf("no encryption key secrets available to compute preflight encryption config")
	}

	return result.EncryptionSecret, nil
}

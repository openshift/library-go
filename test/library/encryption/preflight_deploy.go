package encryption

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/preflight"
)

const (
	preflightDeployConfigHash = "e2e-preflight-drift"
	// PreflightDeployCallTimeout is the KMS gRPC call timeout used by preflight e2e Deploy.
	PreflightDeployCallTimeout  = 10 * time.Second
	preflightKMSSocketEndpoint  = "unix:///var/run/kmsplugin/kms.sock"
	preflightStatusPollInterval = 5 * time.Second
	preflightStatusPollTimeout  = 5 * time.Minute
	openshiftConfigNS           = "openshift-config"
)

// PreflightDeployScenario configures a real-cluster Deploy() check against a live
// operand namespace. The operand namespace must already have preflight RBAC.
//
// BasicScenario.Namespace is the operand namespace (Deploy target).
// BasicScenario.LabelSelector is reserved for a follow-up operand pod drift check.
type PreflightDeployScenario struct {
	BasicScenario
	// CreateDeployerFunc builds the deployer (image, command, static-pod mode).
	CreateDeployerFunc func(ctx context.Context, t testing.TB, clientSet ClientSet) *preflight.PodPreflightDeployer
	// CreateEncryptionConfigFunc builds the encryption-config Secret Deploy mounts.
	// Use VaultPreflightEncryptionConfigSecret for Vault.
	CreateEncryptionConfigFunc func(ctx context.Context, t testing.TB, clientSet ClientSet, namespace string, plugin configv1.KMSPluginConfig) *corev1.Secret
	// AssertDeployFunc validates the deployed preflight pod. Use AssertPreflightDeploy.
	AssertDeployFunc func(ctx context.Context, t testing.TB, clientSet ClientSet, namespace string, deployer *preflight.PodPreflightDeployer)
	// EncryptionProvider supplies KMS plugin config and optional Setup (e.g. AppRole
	// secret). Prefer kms.DefaultVaultEncryptionProvider so references resolve.
	EncryptionProvider EncryptionProvider
}

// TestPreflightDeployAndPodMatchesOperand deploys a preflight pod into the operand
// namespace and runs AssertDeployFunc against it.
func TestPreflightDeployAndPodMatchesOperand(ctx context.Context, t testing.TB, scenario PreflightDeployScenario) {
	t.Helper()
	require.NotEmpty(t, scenario.Namespace)
	require.NotNil(t, scenario.CreateDeployerFunc)
	require.NotNil(t, scenario.CreateEncryptionConfigFunc)
	require.NotNil(t, scenario.AssertDeployFunc)
	require.Equal(t, configv1.EncryptionTypeKMS, scenario.EncryptionProvider.Type)
	require.NotEmpty(t, scenario.EncryptionProvider.KMS.Type)

	if scenario.EncryptionProvider.Setup != nil {
		scenario.EncryptionProvider.Setup(ctx, t)
	}

	clientSet := GetClients(t)
	deployer := scenario.CreateDeployerFunc(ctx, t, clientSet)
	require.NotNil(t, deployer)

	secret := scenario.CreateEncryptionConfigFunc(ctx, t, clientSet, scenario.Namespace, scenario.EncryptionProvider.KMS)
	require.NotNil(t, secret)

	t.Cleanup(func() {
		if err := deployer.Cleanup(context.Background()); err != nil {
			t.Errorf("preflight Cleanup: %v", err)
		}
	})

	require.NoError(t, deployer.Deploy(ctx, preflightDeployConfigHash, secret))
	scenario.AssertDeployFunc(ctx, t, clientSet, scenario.Namespace, deployer)
}

// AssertPreflightDeploy waits for checker pod conditions and validates Deploy side effects
// (check container, plugin init container, config-hash / result / KEK-ID conditions).
func AssertPreflightDeploy(ctx context.Context, t testing.TB, clientSet ClientSet, namespace string, deployer *preflight.PodPreflightDeployer) {
	t.Helper()
	require.NotNil(t, deployer)
	require.NotEmpty(t, namespace)

	preflightPod, err := clientSet.Kube.CoreV1().Pods(namespace).Get(ctx, preflight.PodName, metav1.GetOptions{})
	require.NoError(t, err, "preflight pod %s/%s", namespace, preflight.PodName)

	require.Len(t, preflightPod.Spec.Containers, 1)
	require.Equal(t, preflight.CheckContainerName, preflightPod.Spec.Containers[0].Name)
	require.NotEmpty(t, preflightPod.Spec.InitContainers, "expected KMS plugin init container")

	var status corev1.PodStatus
	err = wait.PollUntilContextTimeout(ctx, preflightStatusPollInterval, preflightStatusPollTimeout, true, func(ctx context.Context) (bool, error) {
		var statusErr error
		status, statusErr = deployer.Status(ctx)
		if statusErr != nil {
			return false, statusErr
		}
		if status.Phase == corev1.PodFailed {
			return false, fmt.Errorf("preflight pod failed: reason=%q message=%q", status.Reason, status.Message)
		}
		return controllers.FindPodCondition(status.Conditions, controllers.KMSPreflightResultPodCondition) != nil, nil
	})
	require.NoError(t, err, "waiting for KMSPreflightResult condition")

	hashCond := requirePodCondition(t, status.Conditions, controllers.KMSPreflightConfigHashPodCondition, corev1.ConditionTrue)
	require.Equal(t, preflightDeployConfigHash, hashCond.Message)

	resultCond := requirePodCondition(t, status.Conditions, controllers.KMSPreflightResultPodCondition, corev1.ConditionTrue)
	require.Equal(t, "Succeeded", resultCond.Reason)

	kekCond := requirePodCondition(t, status.Conditions, controllers.KMSPreflightKEKIDPodCondition, corev1.ConditionTrue)
	require.NotEmpty(t, kekCond.Message, "KEK ID")
}

func requirePodCondition(t testing.TB, conditions []corev1.PodCondition, condType corev1.PodConditionType, wantStatus corev1.ConditionStatus) *corev1.PodCondition {
	t.Helper()
	cond := controllers.FindPodCondition(conditions, condType)
	require.NotNil(t, cond, "missing %s condition", condType)
	require.Equal(t, wantStatus, cond.Status, "condition %s: %s", condType, cond.Message)
	return cond
}

// OperatorImageFromDeployment returns the image of containerName from the named
// Deployment. Used by preflight e2e to run the same operator binary the cluster
// is already running, without requiring OPERATOR_IMAGE.
func OperatorImageFromDeployment(ctx context.Context, t testing.TB, namespace, deploymentName, containerName string) string {
	t.Helper()
	clientSet := GetClients(t)
	deploy, err := clientSet.Kube.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	require.NoError(t, err, "get operator deployment %s/%s", namespace, deploymentName)
	for _, c := range deploy.Spec.Template.Spec.Containers {
		if c.Name == containerName {
			require.NotEmpty(t, c.Image, "operator container %q image must not be empty", containerName)
			return c.Image
		}
	}
	require.FailNow(t, fmt.Sprintf("container %q not found in deployment %s/%s", containerName, namespace, deploymentName))
	return ""
}

// TODO(thomas): this should go away once we have an official mapping function between plugin config and transient encryption config
func VaultPreflightEncryptionConfigSecret(ctx context.Context, t testing.TB, clientSet ClientSet, namespace string, plugin configv1.KMSPluginConfig) *corev1.Secret {
	t.Helper()
	require.Equal(t, configv1.VaultKMSProvider, plugin.Type, "preflight deploy e2e currently supports Vault only")
	require.Equal(t, configv1.VaultAuthenticationTypeAppRole, plugin.Vault.Authentication.Type)

	secretName := plugin.Vault.Authentication.AppRole.Secret.Name
	require.NotEmpty(t, secretName, "Vault AppRole secret name")
	refSecret, err := clientSet.Kube.CoreV1().Secrets(openshiftConfigNS).Get(ctx, secretName, metav1.GetOptions{})
	require.NoError(t, err, "referenced AppRole secret %s/%s", openshiftConfigNS, secretName)

	var secretData encryptiondata.KMSPluginsReferenceData
	for _, key := range []string{"role-id", "secret-id"} {
		v, ok := refSecret.Data[key]
		require.True(t, ok, "secret %s/%s missing key %q", openshiftConfigNS, secretName, key)
		require.NoError(t, secretData.SetFromRawKey("1", secretName+"_"+key, v))
	}

	var configMapData encryptiondata.KMSPluginsReferenceData
	if cmName := plugin.Vault.TLS.CABundle.Name; cmName != "" {
		refCM, err := clientSet.Kube.CoreV1().ConfigMaps(openshiftConfigNS).Get(ctx, cmName, metav1.GetOptions{})
		require.NoError(t, err, "referenced CA ConfigMap %s/%s", openshiftConfigNS, cmName)
		v, ok := refCM.Data["ca-bundle.crt"]
		require.True(t, ok, "configmap %s/%s missing key ca-bundle.crt", openshiftConfigNS, cmName)
		require.NoError(t, configMapData.SetFromRawKey("1", cmName+"_ca-bundle.crt", []byte(v)))
	}

	config := &encryptiondata.Config{
		Encryption: &apiserverconfigv1.EncryptionConfiguration{
			TypeMeta: metav1.TypeMeta{Kind: "EncryptionConfiguration", APIVersion: "apiserver.config.k8s.io/v1"},
			Resources: []apiserverconfigv1.ResourceConfiguration{{
				Resources: []string{"secrets"},
				Providers: []apiserverconfigv1.ProviderConfiguration{
					{KMS: &apiserverconfigv1.KMSConfiguration{
						APIVersion: "v2",
						Name:       "1_secrets",
						Endpoint:   preflightKMSSocketEndpoint,
						Timeout:    &metav1.Duration{Duration: PreflightDeployCallTimeout},
					}},
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
				},
			}},
		},
		KMSPlugins: map[string]configv1.KMSPluginConfig{
			"1": plugin,
		},
		KMSPluginsSecretData:    secretData,
		KMSPluginsConfigMapData: configMapData,
	}
	secret, err := encryptiondata.ToSecret(namespace, preflight.EncryptionConfigSecretName, config)
	require.NoError(t, err)
	return secret
}

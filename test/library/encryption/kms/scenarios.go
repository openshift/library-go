package kms

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/preflight"
	"github.com/openshift/library-go/pkg/operator/events"
	library "github.com/openshift/library-go/test/library/encryption"
)

const (
	globalMachineSpecifiedConfigNamespace = "openshift-config-managed"
	kubeAPIServerComponent                = "openshift-kube-apiserver"
	kubeAPIServerOperatorNamespace        = "openshift-kube-apiserver-operator"
	oauthAPIServerComponent               = "openshift-oauth-apiserver"
	authenticationOperatorNamespace       = "openshift-authentication-operator"
	openshiftAPIServerComponent           = "openshift-apiserver"
	openshiftAPIServerOperatorNamespace   = "openshift-apiserver-operator"
)

func encryptionComponentLabelSelector(component string) string {
	return "encryption.apiserver.operator.openshift.io/component=" + component
}

// EncryptionTurnOnAndOffScenarios returns ready-to-use KAS/Auth/OAS on/off scenarios.
//
// Provider handling: on/off tests toggle a single encryption mode (KMS on, identity off),
// so only the KAS scenario sets EncryptionProvider. Auth and OAS omit it because
// APIServer.spec.encryption is cluster-wide — TestEncryptionTurnOnAndOff reads the one
// non-empty provider and applies it for every operator in parallel.
//
// The provider is built here (not passed in) because Vault KMS setup requires ctx and t.
func EncryptionTurnOnAndOffScenarios(ctx context.Context, t testing.TB) []library.OnOffScenario {
	provider := DefaultVaultEncryptionProvider(ctx, t)
	return []library.OnOffScenario{
		kasOnOffScenario(provider),
		authOnOffScenario(ctx),
		oasOnOffScenario(ctx),
	}
}

// EncryptionProvidersMigrationScenarios returns ready-to-use KAS/Auth/OAS migration scenarios.
//
// Provider handling: migration tests step through multiple encryption modes, so only
// the KAS scenario sets EncryptionProviders (a shuffled KMS + AES sequence). Auth and
// OAS omit it for the same cluster-wide reason as on/off — TestEncryptionProvidersMigration
// reads the one non-empty list and drives every operator through the same steps.
//
// The provider list is built here (not passed in): Vault KMS needs ctx/t, and the list
// is shuffled with a random AES provider (AESGCM or AESCBC) so callers get a complete
// ready-to-run scenario.
func EncryptionProvidersMigrationScenarios(ctx context.Context, t testing.TB) []library.ProvidersMigrationScenario {
	providers := library.ShuffleEncryptionProviders([]library.EncryptionProvider{
		DefaultVaultEncryptionProvider(ctx, t),
		library.SupportedStaticEncryptionProviders[rand.IntN(len(library.SupportedStaticEncryptionProviders))],
	})
	return []library.ProvidersMigrationScenario{
		kasProvidersMigrationScenario(providers),
		authProvidersMigrationScenario(ctx),
		oasProvidersMigrationScenario(ctx),
	}
}

// EncryptionKMSToKMSMigrationScenarios returns ready-to-use KAS/Auth/OAS migration scenarios
// that migrate between two distinct KMS providers (default and secondary Vault instances).
//
// Provider handling matches EncryptionProvidersMigrationScenarios: only the KAS scenario sets
// EncryptionProviders. Each operator verifies its well-known resource is encrypted and that the
// active KMS write key prefix matches the last-migrated key in the encryption config.
func EncryptionKMSToKMSMigrationScenarios(ctx context.Context, t testing.TB) []library.ProvidersMigrationScenario {
	providers := library.ShuffleEncryptionProviders([]library.EncryptionProvider{
		DefaultVaultEncryptionProvider(ctx, t),
		SecondaryVaultEncryptionProvider(ctx, t),
	})
	return []library.ProvidersMigrationScenario{
		kasKMSToKMSMigrationScenario(providers),
		authKMSToKMSMigrationScenario(ctx),
		oasKMSToKMSMigrationScenario(ctx),
	}
}

// PreflightDeployScenario returns a ready-to-use KAS preflight deploy scenario that runs the
// cluster-kube-apiserver-operator kms-preflight command against a live kube-apiserver operand.
func PreflightDeployScenario(ctx context.Context, t testing.TB) library.PreflightDeployScenario {
	return library.PreflightDeployScenario{
		BasicScenario: library.BasicScenario{
			// Preflight deploys into the operand namespace because the scenario validates the
			// actual workload pod wiring there, unlike migration scenarios that operate on the
			// rendered encryption config.
			Namespace:     kubeAPIServerComponent,
			LabelSelector: "apiserver=true",
		},
		CreateDeployerFunc: func(ctx context.Context, t testing.TB, cs library.ClientSet) *preflight.PodPreflightDeployer {
			image := library.OperatorImageFromDeployment(ctx, t,
				kubeAPIServerOperatorNamespace, "kube-apiserver-operator", "kube-apiserver-operator")
			recorder := events.NewInMemoryRecorder("kms-preflight-e2e", clock.RealClock{})
			return preflight.NewStaticPodPreflightDeployer(
				kubeAPIServerComponent, cs.Kube.CoreV1(), cs.Kube.RbacV1(),
				recorder, image, []string{"cluster-kube-apiserver-operator", "kms-preflight"}, library.PreflightDeployCallTimeout,
			)
		},
		CreateEncryptionConfigFunc: library.VaultPreflightEncryptionConfigSecret,
		AssertDeployFunc:           library.AssertPreflightDeploy,
		EncryptionProvider:         DefaultVaultEncryptionProvider(ctx, t),
	}
}

// EncryptionInPlaceUpdateScenarios returns ready-to-use in-place field-update scenarios.
//
// Provider handling matches the on/off and migration builders: only the KAS scenario sets the
// providers (the cluster-wide APIServer config and the shared VaultKMSConfig CR). The updated
// provider changes only the plugin image, so the operator refreshes the existing key in place
// without minting a new key or re-encrypting.
func EncryptionInPlaceUpdateScenarios(ctx context.Context, t testing.TB) []library.InPlaceUpdateScenario {
	updateImage := resolveVaultKMSPluginImageUpdate(t)
	return []library.InPlaceUpdateScenario{
		kasInPlaceUpdateScenario(ctx, t, updateImage),
		authInPlaceUpdateScenario(ctx, updateImage),
		oasInPlaceUpdateScenario(ctx, updateImage),
	}
}

// EncryptionRotationScenarios returns ready-to-use KAS/Auth/OAS remote-key rotation scenarios.
// Only KAS supplies the shared provider and Vault rotation callback. Each operator
// waits for its own migration and verifies its resource was re-encrypted.
func EncryptionRotationScenarios(ctx context.Context, t testing.TB) []library.RotationScenario {
	return []library.RotationScenario{
		kasRotationScenario(ctx, t),
		authRotationScenario(ctx),
		oasRotationScenario(ctx),
	}
}

func kasRotationScenario(ctx context.Context, t testing.TB) library.RotationScenario {
	return library.RotationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(kubeAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", kubeAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               kubeAPIServerOperatorNamespace,
			TargetGRs:                       library.WellKnownKASTargetGRs,
			AssertFunc:                      library.AssertWellKnownSecretsAndConfigMaps,
		},
		ResourceName:                "SecretOfLife",
		CreateResourceFunc:          library.CreateAndStoreWellKnownSecretOfLife,
		GetRawResourceFunc:          library.GetRawWellKnownSecretOfLife,
		EncryptionProvider:          DefaultVaultEncryptionProvider(ctx, t),
		ForceRotationFunc:           ForceVaultKeyRotation(),
		WaitForRotationCompleteFunc: library.WaitForKMSRemoteKeyRotationComplete(),
	}
}

func authRotationScenario(ctx context.Context) library.RotationScenario {
	return library.RotationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(oauthAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", oauthAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               authenticationOperatorNamespace,
			TargetGRs:                       library.WellKnownAuthTargetGRs,
			AssertFunc:                      library.AssertWellKnownTokens,
		},
		ResourceName: "TokenOfLife",
		CreateResourceFunc: func(t testing.TB, clientSet library.ClientSet, _ string) runtime.Object {
			return library.CreateAndStoreWellKnownTokenOfLife(ctx, t, clientSet)
		},
		GetRawResourceFunc: func(t testing.TB, clientSet library.ClientSet, _ string) string {
			return library.GetRawWellKnownTokenOfLife(t, clientSet)
		},
		WaitForRotationCompleteFunc: library.WaitForKMSRemoteKeyRotationComplete(),
	}
}

func oasRotationScenario(ctx context.Context) library.RotationScenario {
	return library.RotationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(openshiftAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", openshiftAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               openshiftAPIServerOperatorNamespace,
			TargetGRs:                       library.WellKnownOASTargetGRs,
			AssertFunc:                      library.AssertWellKnownRoutes,
		},
		ResourceName: "RouteOfLife",
		CreateResourceFunc: func(t testing.TB, clientSet library.ClientSet, ns string) runtime.Object {
			return library.CreateAndStoreWellKnownRouteOfLife(ctx, t, clientSet, ns)
		},
		GetRawResourceFunc:          library.GetRawWellKnownRouteOfLife,
		WaitForRotationCompleteFunc: library.WaitForKMSRemoteKeyRotationComplete(),
	}
}

// assertKMSInPlaceUpdate asserts the operator applied the in-place image update: the write key Secret
// carries updateImage, and the operand (operandNamespace) rolled out a new revision whose KMS plugin
// sidecar runs that image.
func assertKMSInPlaceUpdate(ctx context.Context, operandNamespace, updateImage string) func(testing.TB, library.ClientSet, library.EncryptionKeyMeta) {
	return func(t testing.TB, clientSet library.ClientSet, keyMeta library.EncryptionKeyMeta) {
		library.AssertKMSKeyPluginImage(t, clientSet, globalMachineSpecifiedConfigNamespace, keyMeta.Name, updateImage)
		library.AssertKMSPluginImageRolledOut(ctx, t, clientSet, operandNamespace, keyMeta.Name, updateImage)
	}
}

func kasInPlaceUpdateScenario(ctx context.Context, t testing.TB, updateImage string) library.InPlaceUpdateScenario {
	return library.InPlaceUpdateScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(kubeAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", kubeAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               kubeAPIServerOperatorNamespace,
			TargetGRs:                       library.WellKnownKASTargetGRs,
			AssertFunc:                      library.AssertWellKnownSecretsAndConfigMaps,
		},
		CreateResourceFunc:          library.CreateAndStoreWellKnownSecretOfLife,
		AssertResourceEncryptedFunc: library.AssertWellKnownSecretOfLifeEncrypted,
		ResourceFunc:                library.WellKnownSecretOfLife,
		ResourceName:                "SecretOfLife",
		// Cluster-wide APIServer config + shared VaultKMSConfig CR — only KAS sets these.
		EncryptionProvider: DefaultVaultEncryptionProvider(ctx, t),
		UpdatedEncryptionProviders: []library.EncryptionProvider{
			UpdatedVaultEncryptionProvider(ctx, t, ""),
			UpdatedVaultEncryptionProvider(ctx, t, "vault-approle-rotated"),
		},
		AssertInPlaceUpdateFunc: assertKMSInPlaceUpdate(ctx, kubeAPIServerComponent, updateImage),
	}
}

func authInPlaceUpdateScenario(ctx context.Context, updateImage string) library.InPlaceUpdateScenario {
	return library.InPlaceUpdateScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(oauthAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", oauthAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               authenticationOperatorNamespace,
			TargetGRs:                       library.WellKnownAuthTargetGRs,
			AssertFunc:                      library.AssertWellKnownTokens,
		},
		CreateResourceFunc: func(t testing.TB, clientSet library.ClientSet, _ string) runtime.Object {
			return library.CreateAndStoreWellKnownTokenOfLife(ctx, t, clientSet)
		},
		AssertResourceEncryptedFunc: library.AssertWellKnownTokenOfLifeEncrypted,
		ResourceFunc:                library.WellKnownTokenOfLife,
		ResourceName:                "TokenOfLife",
		AssertInPlaceUpdateFunc:     assertKMSInPlaceUpdate(ctx, oauthAPIServerComponent, updateImage),
	}
}

func oasInPlaceUpdateScenario(ctx context.Context, updateImage string) library.InPlaceUpdateScenario {
	return library.InPlaceUpdateScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(openshiftAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", openshiftAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               openshiftAPIServerOperatorNamespace,
			TargetGRs:                       library.WellKnownOASTargetGRs,
			AssertFunc:                      library.AssertWellKnownRoutes,
		},
		CreateResourceFunc: func(t testing.TB, clientSet library.ClientSet, ns string) runtime.Object {
			return library.CreateAndStoreWellKnownRouteOfLife(ctx, t, clientSet, ns)
		},
		AssertResourceEncryptedFunc: library.AssertWellKnownRouteOfLifeEncrypted,
		ResourceFunc:                library.WellKnownRouteOfLife,
		ResourceName:                "RouteOfLife",
		AssertInPlaceUpdateFunc:     assertKMSInPlaceUpdate(ctx, openshiftAPIServerComponent, updateImage),
	}
}

// KMSPreflightLifecycleScenarios returns KAS/Auth/OAS lifecycle scenarios.
// Only KAS supplies the cluster-wide providers, matching the on/off scenarios.
// Every operator verifies invalid configurations, recovery, and the in-place update.
func KMSPreflightLifecycleScenarios(ctx context.Context, t testing.TB) []library.KMSPreflightLifecycleScenario {
	t.Helper()
	updateImage := resolveVaultKMSPluginImageUpdate(t)
	invalidAddress := InvalidVaultEncryptionProvider(ctx, t, "https://127.0.0.1:1", "", false)
	invalidImage := InvalidVaultEncryptionProvider(ctx, t, "", "quay.io/openshifttest/vault-kube-kms@sha256:0000000000000000000000000000000000000000000000000000000000000000", false)
	invalidAuth := InvalidVaultEncryptionProvider(ctx, t, "", "", true)
	inPlaceScenarios := []library.InPlaceUpdateScenario{
		kasInPlaceUpdateScenario(ctx, t, updateImage),
		authInPlaceUpdateScenario(ctx, updateImage),
		oasInPlaceUpdateScenario(ctx, updateImage),
	}
	scenarios := make([]library.KMSPreflightLifecycleScenario, 0, len(inPlaceScenarios))
	for _, scenario := range inPlaceScenarios {
		scenarios = append(scenarios, library.KMSPreflightLifecycleScenario{
			InPlaceUpdateScenario: scenario,
			InvalidConfigs: []library.KMSPreflightNegativeScenario{
				{Name: "invalid-vault-address", AssertFailedFunc: library.AssertKMSPreflightCheckerFailedForOperator},
				{Name: "invalid-image", AssertFailedFunc: library.AssertKMSPreflightDegradedForOperator},
				{Name: "invalid-auth", AssertFailedFunc: library.AssertKMSPreflightCheckerFailedForOperator},
			},
		})
	}
	scenarios[0].InvalidConfigs[0].InvalidProvider = invalidAddress
	scenarios[0].InvalidConfigs[1].InvalidProvider = invalidImage
	scenarios[0].InvalidConfigs[2].InvalidProvider = invalidAuth
	return scenarios
}

func kasOnOffScenario(provider library.EncryptionProvider) library.OnOffScenario {
	return library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(kubeAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", kubeAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               kubeAPIServerOperatorNamespace,
			TargetGRs:                       library.WellKnownKASTargetGRs,
			AssertFunc:                      library.AssertWellKnownSecretsAndConfigMaps,
		},
		CreateResourceFunc:             library.CreateAndStoreWellKnownSecretOfLife,
		AssertResourceEncryptedFunc:    library.AssertWellKnownSecretOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: library.AssertWellKnownSecretOfLifeNotEncrypted,
		ResourceFunc:                   library.WellKnownSecretOfLife,
		ResourceName:                   "SecretOfLife",
		// Cluster-wide APIServer config — only KAS sets this; Auth/OAS omit it.
		// EncryptionProvider sets cluster-wide APIServer encryption for on/off tests.
		// When multiple operators run together, set it on exactly one scenario.
		EncryptionProvider: provider,
	}
}

func authOnOffScenario(ctx context.Context) library.OnOffScenario {
	return library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(oauthAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", oauthAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               authenticationOperatorNamespace,
			TargetGRs:                       library.WellKnownAuthTargetGRs,
			AssertFunc:                      library.AssertWellKnownTokens,
		},
		CreateResourceFunc: func(t testing.TB, clientSet library.ClientSet, _ string) runtime.Object {
			return library.CreateAndStoreWellKnownTokenOfLife(ctx, t, clientSet)
		},
		AssertResourceEncryptedFunc:    library.AssertWellKnownTokenOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: library.AssertWellKnownTokenOfLifeNotEncrypted,
		ResourceFunc:                   library.WellKnownTokenOfLife,
		ResourceName:                   "TokenOfLife",
	}
}

func oasOnOffScenario(ctx context.Context) library.OnOffScenario {
	return library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(openshiftAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", openshiftAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               openshiftAPIServerOperatorNamespace,
			TargetGRs:                       library.WellKnownOASTargetGRs,
			AssertFunc:                      library.AssertWellKnownRoutes,
		},
		CreateResourceFunc: func(t testing.TB, clientSet library.ClientSet, ns string) runtime.Object {
			return library.CreateAndStoreWellKnownRouteOfLife(ctx, t, clientSet, ns)
		},
		AssertResourceEncryptedFunc:    library.AssertWellKnownRouteOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: library.AssertWellKnownRouteOfLifeNotEncrypted,
		ResourceFunc:                   library.WellKnownRouteOfLife,
		ResourceName:                   "RouteOfLife",
	}
}

func kasProvidersMigrationScenario(providers []library.EncryptionProvider) library.ProvidersMigrationScenario {
	return library.ProvidersMigrationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(kubeAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", kubeAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               kubeAPIServerOperatorNamespace,
			TargetGRs:                       library.WellKnownKASTargetGRs,
			AssertFunc:                      library.AssertWellKnownSecretsAndConfigMaps,
		},
		CreateResourceFunc:             library.CreateAndStoreWellKnownSecretOfLife,
		AssertResourceEncryptedFunc:    library.AssertWellKnownSecretOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: library.AssertWellKnownSecretOfLifeNotEncrypted,
		ResourceFunc:                   library.WellKnownSecretOfLife,
		ResourceName:                   "SecretOfLife",
		// Cluster-wide APIServer config — only KAS sets this; Auth/OAS omit it.
		// EncryptionProvider sets cluster-wide APIServer encryption for provider migration tests.
		// When multiple operators run together, set it on exactly one scenario.
		EncryptionProviders: providers,
	}
}

func authProvidersMigrationScenario(ctx context.Context) library.ProvidersMigrationScenario {
	return library.ProvidersMigrationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(oauthAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", oauthAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               authenticationOperatorNamespace,
			TargetGRs:                       library.WellKnownAuthTargetGRs,
			AssertFunc:                      library.AssertWellKnownTokens,
		},
		CreateResourceFunc: func(t testing.TB, clientSet library.ClientSet, _ string) runtime.Object {
			return library.CreateAndStoreWellKnownTokenOfLife(ctx, t, clientSet)
		},
		AssertResourceEncryptedFunc:    library.AssertWellKnownTokenOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: library.AssertWellKnownTokenOfLifeNotEncrypted,
		ResourceFunc:                   library.WellKnownTokenOfLife,
		ResourceName:                   "TokenOfLife",
	}
}

func oasProvidersMigrationScenario(ctx context.Context) library.ProvidersMigrationScenario {
	return library.ProvidersMigrationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       globalMachineSpecifiedConfigNamespace,
			LabelSelector:                   encryptionComponentLabelSelector(openshiftAPIServerComponent),
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", openshiftAPIServerComponent),
			EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
			OperatorNamespace:               openshiftAPIServerOperatorNamespace,
			TargetGRs:                       library.WellKnownOASTargetGRs,
			AssertFunc:                      library.AssertWellKnownRoutes,
		},
		CreateResourceFunc: func(t testing.TB, clientSet library.ClientSet, ns string) runtime.Object {
			return library.CreateAndStoreWellKnownRouteOfLife(ctx, t, clientSet, ns)
		},
		AssertResourceEncryptedFunc:    library.AssertWellKnownRouteOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: library.AssertWellKnownRouteOfLifeNotEncrypted,
		ResourceFunc:                   library.WellKnownRouteOfLife,
		ResourceName:                   "RouteOfLife",
	}
}

func assertKMSHealth(ctx context.Context, t testing.TB, clientSet library.ClientSet, operatorNamespace string) {
	t.Helper()
	library.AssertKMSHealthReports(ctx, t, clientSet, operatorNamespace)
	library.AssertOperatorConditions(ctx, t, clientSet, operatorNamespace,
		operatorv1.OperatorCondition{Type: "KMSHealthDegraded", Status: operatorv1.ConditionFalse, Reason: "AsExpected"},
		operatorv1.OperatorCondition{Type: "KMSHealthProgressing", Status: operatorv1.ConditionFalse, Reason: "AsExpected"},
	)
}

func kasKMSToKMSMigrationScenario(providers []library.EncryptionProvider) library.ProvidersMigrationScenario {
	scenario := kasProvidersMigrationScenario(providers)
	scenario.AssertConditionsFunc = assertKMSHealth
	scenario.AssertResourceEncryptedFunc = func(t testing.TB, clientSet library.ClientSet, resource runtime.Object) {
		library.AssertWellKnownSecretOfLifeEncrypted(t, clientSet, resource)
		library.AssertWellKnownSecretOfLifeEncryptedWithKMS(t, clientSet,
			globalMachineSpecifiedConfigNamespace,
			encryptionComponentLabelSelector(kubeAPIServerComponent),
			resource)
	}
	return scenario
}

func authKMSToKMSMigrationScenario(ctx context.Context) library.ProvidersMigrationScenario {
	scenario := authProvidersMigrationScenario(ctx)
	scenario.AssertConditionsFunc = assertKMSHealth
	scenario.AssertResourceEncryptedFunc = func(t testing.TB, clientSet library.ClientSet, resource runtime.Object) {
		library.AssertWellKnownTokenOfLifeEncrypted(t, clientSet, resource)
		library.AssertWellKnownTokenOfLifeEncryptedWithKMS(t, clientSet,
			globalMachineSpecifiedConfigNamespace,
			encryptionComponentLabelSelector(oauthAPIServerComponent),
			resource)
	}
	return scenario
}

func oasKMSToKMSMigrationScenario(ctx context.Context) library.ProvidersMigrationScenario {
	scenario := oasProvidersMigrationScenario(ctx)
	scenario.AssertConditionsFunc = assertKMSHealth
	scenario.AssertResourceEncryptedFunc = func(t testing.TB, clientSet library.ClientSet, resource runtime.Object) {
		library.AssertWellKnownRouteOfLifeEncrypted(t, clientSet, resource)
		library.AssertWellKnownRouteOfLifeEncryptedWithKMS(t, clientSet,
			globalMachineSpecifiedConfigNamespace,
			encryptionComponentLabelSelector(openshiftAPIServerComponent),
			resource)
	}
	return scenario
}

package kms

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

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

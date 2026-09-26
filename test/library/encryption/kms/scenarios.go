package kms

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/clock"

	configv1 "github.com/openshift/api/config/v1"
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

// KMSPreflightNegativeScenario configures a negative KMS preflight test.
// Prefer this over library.TestEncryptionType for invalid configs (those wait on migration).
type KMSPreflightNegativeScenario struct {
	library.BasicScenario
	Name            string // log label
	InvalidProvider library.EncryptionProvider
}

// TestKMSPreflightNegative applies each invalid provider and asserts preflight failure for
// that config (not a stale Degraded from a prior case). After all cases it restores
// encryption.type=identity so the cluster is not left Degraded.
func TestKMSPreflightNegative(ctx context.Context, t testing.TB, scenarios ...KMSPreflightNegativeScenario) {
	t.Helper()
	require.NotEmpty(t, scenarios)

	e := library.NewE(t, library.PrintEventsOnFailure(kubeAPIServerOperatorNamespace))
	clients := library.GetClients(e)
	t.Cleanup(func() { restoreIdentityAndWait(context.Background(), e, clients) })

	for _, scenario := range scenarios {
		if scenario.Name != "" {
			t.Logf("=== STEP: %s ===", scenario.Name)
		}
		// Baseline may be empty when this test runs first (identity, no keys yet).
		// WaitForNoNewEncryptionKey handles that and still fails if a key is created.
		baseline, err := library.GetLastKeyMeta(e, clients.Kube, scenario.Namespace, scenario.LabelSelector)
		require.NoError(e, err)

		previous, err := library.ReadKMSPreflightForOperator(ctx, e, clients, scenario.OperatorNamespace)
		require.NoError(e, err)

		scenario.InvalidProvider.Setup(ctx, e)
		library.ApplyEncryption(ctx, e, scenario.InvalidProvider.APIServerEncryption)
		library.AssertKMSPreflightFailedForOperator(ctx, e, clients, scenario.OperatorNamespace, previous)
		library.WaitForNoNewEncryptionKey(e, clients.Kube, baseline, scenario.Namespace, scenario.LabelSelector)
	}
}

func restoreIdentityAndWait(ctx context.Context, t testing.TB, clients library.ClientSet) {
	t.Helper()
	cleanupCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	library.ApplyEncryption(cleanupCtx, t, configv1.APIServerEncryption{Type: configv1.EncryptionTypeIdentity})
	apiServer, err := clients.ApiServerConfig.Get(cleanupCtx, "cluster", metav1.GetOptions{})
	if err != nil {
		t.Errorf("failed to read APIServer after identity restore: %v", err)
		return
	}
	if apiServer.Spec.Encryption.Type != configv1.EncryptionTypeIdentity && apiServer.Spec.Encryption.Type != "" {
		t.Errorf("expected identity encryption after cleanup, got type=%q", apiServer.Spec.Encryption.Type)
		return
	}
	library.WaitForKMSPreflightNotDegradedForOperator(cleanupCtx, t, clients, kubeAPIServerOperatorNamespace)
}

// VaultNegativeCase is a caller-defined invalid Vault config for preflight negative tests.
type VaultNegativeCase struct {
	Name   string
	Mutate func(*unstructured.Unstructured)                                   // optional VaultKMSConfig overrides
	Setup  func(ctx context.Context, t testing.TB, clients library.ClientSet) // optional prereqs (e.g. invalid AppRole secret)
}

// KMSPreflightNegativeScenarios builds ready-to-use KAS negative scenarios from caller-supplied
// cases. Unlike EncryptionTurnOnAndOffScenarios this is KAS-only (encryption is cluster-wide;
// one operator is enough to exercise invalid preflight).
//
//	librarykms.TestKMSPreflightNegative(ctx, t, librarykms.KMSPreflightNegativeScenarios(ctx, t,
//		librarykms.VaultNegativeCase{Name: "bad-vault-address", Mutate: func(vault *unstructured.Unstructured) {
//			_ = unstructured.SetNestedField(vault.Object, "https://192.0.2.1:8200", "spec", "vaultAddress")
//		}},
//		librarykms.VaultNegativeCase{Name: "bad-plugin-image", Mutate: func(vault *unstructured.Unstructured) {
//			_ = unstructured.SetNestedField(vault.Object, "quay.io/example@sha256:0000", "status", "kmsPluginImage")
//		}},
//	)...)
func KMSPreflightNegativeScenarios(ctx context.Context, t testing.TB, cases ...VaultNegativeCase) []KMSPreflightNegativeScenario {
	t.Helper()
	basic := library.BasicScenario{
		Namespace:                       globalMachineSpecifiedConfigNamespace,
		LabelSelector:                   encryptionComponentLabelSelector(kubeAPIServerComponent),
		EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-%s", kubeAPIServerComponent),
		EncryptionConfigSecretNamespace: globalMachineSpecifiedConfigNamespace,
		OperatorNamespace:               kubeAPIServerOperatorNamespace,
		TargetGRs:                       library.WellKnownKASTargetGRs,
		AssertFunc:                      library.AssertWellKnownSecretsAndConfigMaps,
	}
	out := make([]KMSPreflightNegativeScenario, 0, len(cases))
	for _, c := range cases {
		provider := VaultEncryptionProvider(ctx, t, c.Mutate)
		require.NotNil(t, provider.Setup, "VaultEncryptionProvider must set Setup")
		if c.Setup != nil {
			baseSetup := provider.Setup
			setup := c.Setup
			provider.Setup = func(ctx context.Context, t testing.TB) {
				t.Helper()
				baseSetup(ctx, t)
				setup(ctx, t, library.GetClients(t))
			}
		}
		out = append(out, KMSPreflightNegativeScenario{
			Name:            c.Name,
			BasicScenario:   basic,
			InvalidProvider: provider,
		})
	}
	return out
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

func kasKMSToKMSMigrationScenario(providers []library.EncryptionProvider) library.ProvidersMigrationScenario {
	scenario := kasProvidersMigrationScenario(providers)
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
	scenario.AssertResourceEncryptedFunc = func(t testing.TB, clientSet library.ClientSet, resource runtime.Object) {
		library.AssertWellKnownRouteOfLifeEncrypted(t, clientSet, resource)
		library.AssertWellKnownRouteOfLifeEncryptedWithKMS(t, clientSet,
			globalMachineSpecifiedConfigNamespace,
			encryptionComponentLabelSelector(openshiftAPIServerComponent),
			resource)
	}
	return scenario
}

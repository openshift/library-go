package encryption

import (
	"context"
	"fmt"
	mathrand "math/rand/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1 "github.com/openshift/api/config/v1"
)

type BasicScenario struct {
	Namespace                       string
	LabelSelector                   string
	EncryptionConfigSecretName      string
	EncryptionConfigSecretNamespace string
	OperatorNamespace               string
	TargetGRs                       []schema.GroupResource
	AssertFunc                      func(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string)
}

// EncryptionProvider pairs an encryption config with an optional setup function
// that ensures prerequisites (secrets, credentials, infrastructure) are in place.
type EncryptionProvider struct {
	configv1.APIServerEncryption
	// Setup is called once before the provider is first used. May be nil.
	Setup func(ctx context.Context, t testing.TB)
}

func TestEncryptionTypeIdentity(ctx context.Context, t testing.TB, scenario BasicScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(ctx, e, EncryptionProvider{APIServerEncryption: configv1.APIServerEncryption{Type: configv1.EncryptionTypeIdentity}}, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, configv1.EncryptionTypeIdentity, scenario.Namespace, scenario.LabelSelector)
}

func TestEncryptionTypeUnset(ctx context.Context, t testing.TB, scenario BasicScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(ctx, e, EncryptionProvider{}, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, configv1.EncryptionTypeIdentity, scenario.Namespace, scenario.LabelSelector)
}

func resolveProvider(t testing.TB, defaultType configv1.EncryptionType, providers []EncryptionProvider) EncryptionProvider {
	t.Helper()
	if len(providers) > 1 {
		t.Fatalf("expected at most one provider, got %d", len(providers))
	}
	if len(providers) == 1 {
		return providers[0]
	}
	return EncryptionProvider{APIServerEncryption: configv1.APIServerEncryption{Type: defaultType}}
}

func TestEncryptionTypeAESCBC(ctx context.Context, t testing.TB, scenario BasicScenario, providers ...EncryptionProvider) {
	provider := resolveProvider(t, configv1.EncryptionTypeAESCBC, providers)
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(ctx, e, provider, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, provider.Type, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
}

func TestEncryptionTypeAESGCM(ctx context.Context, t testing.TB, scenario BasicScenario, providers ...EncryptionProvider) {
	provider := resolveProvider(t, configv1.EncryptionTypeAESGCM, providers)
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(ctx, e, provider, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, provider.Type, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
}

func TestEncryptionTypeKMS(ctx context.Context, t testing.TB, scenario BasicScenario, providers ...EncryptionProvider) {
	provider := resolveProvider(t, configv1.EncryptionTypeKMS, providers)
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(ctx, e, provider, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, provider.Type, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
}

func TestEncryptionType(ctx context.Context, t testing.TB, scenario BasicScenario, provider EncryptionProvider) {
	switch provider.Type {
	case configv1.EncryptionTypeAESCBC:
		TestEncryptionTypeAESCBC(ctx, t, scenario, provider)
	case configv1.EncryptionTypeAESGCM:
		TestEncryptionTypeAESGCM(ctx, t, scenario, provider)
	case configv1.EncryptionTypeKMS:
		TestEncryptionTypeKMS(ctx, t, scenario, provider)
	case configv1.EncryptionTypeIdentity, "":
		TestEncryptionTypeIdentity(ctx, t, scenario)
	default:
		t.Fatalf("Unknown encryption type: %s", provider.Type)
	}
}

type OnOffScenario struct {
	BasicScenario
	CreateResourceFunc             func(t testing.TB, clientSet ClientSet, namespace string) runtime.Object
	AssertResourceEncryptedFunc    func(t testing.TB, clientSet ClientSet, resource runtime.Object)
	AssertResourceNotEncryptedFunc func(t testing.TB, clientSet ClientSet, resource runtime.Object)
	ResourceFunc                   func(t testing.TB, namespace string) runtime.Object
	ResourceName                   string
	EncryptionProvider             EncryptionProvider
}

type testStep struct {
	name     string
	testFunc func(testing.TB)
}

func TestEncryptionTurnOnAndOff(ctx context.Context, t testing.TB, scenario OnOffScenario) {
	scenarios := []testStep{
		{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.CreateResourceFunc(e, GetClients(e), scenario.Namespace)
		}},
		{name: fmt.Sprintf("On%s", strings.ToUpper(string(scenario.EncryptionProvider.Type))), testFunc: func(t testing.TB) { TestEncryptionType(ctx, t, scenario.BasicScenario, scenario.EncryptionProvider) }},
		{name: fmt.Sprintf("Assert%sEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: "OffIdentity", testFunc: func(t testing.TB) { TestEncryptionTypeIdentity(ctx, t, scenario.BasicScenario) }},
		{name: fmt.Sprintf("Assert%sNotEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: fmt.Sprintf("On%sSecond", strings.ToUpper(string(scenario.EncryptionProvider.Type))), testFunc: func(t testing.TB) { TestEncryptionType(ctx, t, scenario.BasicScenario, scenario.EncryptionProvider) }},
		{name: fmt.Sprintf("Assert%sEncryptedSecond", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: "OffIdentitySecond", testFunc: func(t testing.TB) { TestEncryptionTypeIdentity(ctx, t, scenario.BasicScenario) }},
		{name: fmt.Sprintf("Assert%sNotEncryptedSecond", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
	}

	// run scenarios
	for _, testScenario := range scenarios {
		t.Logf("=== STEP: %s ===", testScenario.name)
		testScenario.testFunc(t)
		if t.Failed() {
			t.Errorf("stopping the test as %q scenario failed", testScenario.name)
			return
		}
	}
}

// ProvidersMigrationScenario defines a test scenario for migrating encryption
// between multiple providers.
//
// See TestEncryptionProvidersMigration for more details.
type ProvidersMigrationScenario struct {
	BasicScenario
	CreateResourceFunc             func(t testing.TB, clientSet ClientSet, namespace string) runtime.Object
	AssertResourceEncryptedFunc    func(t testing.TB, clientSet ClientSet, resource runtime.Object)
	AssertResourceNotEncryptedFunc func(t testing.TB, clientSet ClientSet, resource runtime.Object)
	ResourceFunc                   func(t testing.TB, namespace string) runtime.Object
	ResourceName                   string
	// EncryptionProviders is the list of encryption providers to migrate through.
	// The test will migrate through each provider in order, then always end by
	// switching to identity (off) to verify the resource is re-written unencrypted.
	EncryptionProviders []EncryptionProvider
}

// ShuffleEncryptionProviders returns a new slice with the providers in random order,
// leaving the original slice unchanged. Use this to test different migration orderings.
func ShuffleEncryptionProviders(providers []EncryptionProvider) []EncryptionProvider {
	shuffled := make([]EncryptionProvider, len(providers))
	copy(shuffled, providers)
	mathrand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled
}

// TestEncryptionProvidersMigration tests migration between given encryption providers.
// It creates a resource, migrates through each provider,
// verifies the resource is encrypted after each migration, and finally
// switches to identity (off).
func TestEncryptionProvidersMigration(ctx context.Context, t testing.TB, scenario ProvidersMigrationScenario) {
	if len(scenario.EncryptionProviders) < 2 {
		t.Fatalf("ProvidersMigrationScenario requires at least 2 encryption providers, got %d", len(scenario.EncryptionProviders))
	}

	for _, provider := range scenario.EncryptionProviders {
		if provider.Type == configv1.EncryptionTypeIdentity || provider.Type == "" {
			t.Fatalf("Unsupported encryption provider %q passed", provider.Type)
		}
	}

	// step 1: create the resource
	scenarios := []testStep{
		{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.CreateResourceFunc(e, GetClients(e), scenario.Namespace)
		}},
	}

	// step 2: migrate through each provider in sequence
	for i, provider := range scenario.EncryptionProviders {
		prefix := "EncryptWith"
		if i > 0 {
			prefix = "MigrateTo"
		}
		scenarios = append(scenarios,
			testStep{name: fmt.Sprintf("%s%s", prefix, strings.ToUpper(string(provider.Type))), testFunc: func(t testing.TB) {
				TestEncryptionType(ctx, t, scenario.BasicScenario, provider)
			}},
			testStep{name: fmt.Sprintf("Assert%sEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
				e := NewE(t)
				scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
			}},
		)
	}

	// step 3: switch to identity (off) to verify the resource is re-written unencrypted
	scenarios = append(scenarios, testStep{name: fmt.Sprintf("OffIdentityAndAssert%sNotEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
		TestEncryptionTypeIdentity(ctx, t, scenario.BasicScenario)
		e := NewE(t)
		scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
	}})

	// run scenarios
	for _, testScenario := range scenarios {
		t.Logf("=== STEP: %s ===", testScenario.name)
		testScenario.testFunc(t)
		if t.Failed() {
			t.Errorf("stopping the test as %q scenario failed", testScenario.name)
			return
		}
	}
}

type RotationScenario struct {
	BasicScenario
	CreateResourceFunc          func(t testing.TB, clientSet ClientSet, namespace string) runtime.Object
	GetRawResourceFunc          func(t testing.TB, clientSet ClientSet, namespace string) string
	EncryptionProvider          EncryptionProvider
	ForceRotationFunc           ForceRotationFunc
	WaitForRotationCompleteFunc WaitForRotationCompleteFunc
}

// TestEncryptionRotation encrypts data, forces a provider-specific key rotation, waits for
// re-migration to complete, and verifies the resource was re-encrypted with different content.
func TestEncryptionRotation(ctx context.Context, t testing.TB, scenario RotationScenario) {
	// test data
	ns := scenario.Namespace
	labelSelector := scenario.LabelSelector

	// step 1: create the desired resource
	e := NewE(t)
	clientSet := GetClients(e)
	scenario.CreateResourceFunc(e, clientSet, ns)

	// step 2: run provided encryption scenario
	TestEncryptionType(ctx, t, scenario.BasicScenario, scenario.EncryptionProvider)

	// step 3: take samples
	rawEncryptedResourceWithKey1 := scenario.GetRawResourceFunc(e, clientSet, ns)

	// step 4: force key rotation and wait for migration to complete
	lastMigratedKeyMeta, err := GetLastKeyMeta(t, clientSet.Kube, ns, labelSelector)
	require.NoError(e, err)
	t.Logf("Forcing key rotation for %q encryption", scenario.EncryptionProvider.Type)
	scenario.ForceRotationFunc(e, ctx)

	t.Logf("Waiting for rotation migration to complete")
	scenario.WaitForRotationCompleteFunc(e, clientSet, lastMigratedKeyMeta, scenario.BasicScenario)

	scenario.AssertFunc(e, clientSet, scenario.EncryptionProvider.Type, ns, labelSelector)

	// step 5: verify if the provided resource was encrypted with a different key (step 2 vs step 4)
	rawEncryptedResourceWithKey2 := scenario.GetRawResourceFunc(e, clientSet, ns)
	if rawEncryptedResourceWithKey1 == rawEncryptedResourceWithKey2 {
		t.Errorf("expected the resource to have different content after a key rotation,\ncontentBeforeRotation %s\ncontentAfterRotation %s", rawEncryptedResourceWithKey1, rawEncryptedResourceWithKey2)
	}

	// TODO: assert conditions - operator and encryption migration controller must report status as active not progressing, and not failing for all scenarios
}

// ApplyEncryption applies the given encryption config to apiserver/cluster
// without waiting for completion.
func ApplyEncryption(ctx context.Context, t testing.TB, encryption configv1.APIServerEncryption) {
	t.Helper()
	cs := GetClients(t)
	apiServer, err := cs.ApiServerConfig.Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)
	apiServer.Spec.Encryption = encryption
	_, err = cs.ApiServerConfig.Update(ctx, apiServer, metav1.UpdateOptions{})
	require.NoError(t, err)
	t.Logf("Applied encryption config (type=%s)", encryption.Type)
}

type KMSInvalidEncryptionRecoveryScenario struct {
	BasicScenario
	InvalidProvider EncryptionProvider
	ValidProvider   EncryptionProvider
	WaitForStuck    func(ctx context.Context, t testing.TB)
}

// TestInvalidEncryptionRecovery validates recovery from an invalid encryption config:
//  1. Apply invalid config — operator stuck (e.g. ImagePullBackOff, connection timeout)
//  2. Switch to AESCBC — verify no new encryption key is created (revisions stuck)
//  3. Apply valid config — verify recovery and successful encryption
func TestKMSInvalidEncryptionRecovery(ctx context.Context, t testing.TB, scenario KMSInvalidEncryptionRecoveryScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := GetClients(e)

	require.NotNil(t, scenario.InvalidProvider.Setup, "InvalidProvider.Setup must not be nil")
	require.NotNil(t, scenario.ValidProvider.Setup, "ValidProvider.Setup must not be nil")
	require.Equal(t, configv1.EncryptionTypeKMS, scenario.InvalidProvider.Type, "InvalidProvider must use KMS encryption type")
	require.Equal(t, configv1.EncryptionTypeKMS, scenario.ValidProvider.Type, "ValidProvider must use KMS encryption type")

	steps := []testStep{
		{name: "ApplyInvalidConfig", testFunc: func(t testing.TB) {
			scenario.InvalidProvider.Setup(ctx, t)
			ApplyEncryption(ctx, t, scenario.InvalidProvider.APIServerEncryption)
		}},
		{name: "WaitForStuck", testFunc: func(t testing.TB) {
			scenario.WaitForStuck(ctx, t)
		}},
		{name: "SwitchToAESCBCAndVerifyNoNewKey", testFunc: func(t testing.TB) {
			prevKeyMeta, err := GetLastKeyMeta(t, clientSet.Kube,
				scenario.Namespace, scenario.LabelSelector)
			require.NoError(t, err)
			ApplyEncryption(ctx, t, configv1.APIServerEncryption{Type: configv1.EncryptionTypeAESCBC})
			WaitForNoNewEncryptionKey(t, clientSet.Kube, prevKeyMeta,
				scenario.Namespace, scenario.LabelSelector)
		}},
		{name: "ApplyValidConfigAndVerifyRecovery", testFunc: func(t testing.TB) {
			scenario.ValidProvider.Setup(ctx, t)
			prevKeyMeta, err := GetLastKeyMeta(t, clientSet.Kube,
				scenario.Namespace, scenario.LabelSelector)
			require.NoError(t, err)
			ApplyEncryption(ctx, t, scenario.ValidProvider.APIServerEncryption)
			WaitForCurrentKeyMigrated(t, clientSet.Kube, prevKeyMeta,
				scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
			scenario.AssertFunc(t, clientSet, scenario.ValidProvider.Type,
				scenario.Namespace, scenario.LabelSelector)
		}},
	}

	for _, step := range steps {
		t.Logf("=== STEP: %s ===", step.name)
		step.testFunc(e)
		if t.Failed() {
			t.Errorf("stopping the test as %q step failed", step.name)
			return
		}
	}
}

// KMSInPlaceUpdateScenario tests that updating an in-place KMS config field
// (e.g. kmsPluginImage) takes effect without creating a new encryption key.
// The caller supplies Provider (initial valid config) and UpdatedProvider (same config
// with one in-place field changed).
type KMSInPlaceUpdateScenario struct {
	BasicScenario
	Provider        EncryptionProvider
	UpdatedProvider EncryptionProvider
	// WaitForPropagation is called after the in-place update to verify the change
	// took effect. Receives the current encryption key so callers can match pod
	// container names to the active key. Same pattern as WaitForStuck in
	// KMSInvalidEncryptionRecoveryScenario.
	WaitForPropagation func(ctx context.Context, t testing.TB, keyMeta EncryptionKeyMeta)
}

// TestKMSInPlaceUpdate validates in-place KMS config field updates:
//  1. Apply valid provider and verify migration
//  2. Update in-place field and verify no new encryption key is created
//  3. WaitForPropagation — caller verifies the change took effect
func TestKMSInPlaceUpdate(ctx context.Context, t testing.TB, scenario KMSInPlaceUpdateScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := GetClients(e)

	require.NotNil(t, scenario.Provider.Setup, "Provider.Setup must not be nil")
	require.NotNil(t, scenario.UpdatedProvider.Setup, "UpdatedProvider.Setup must not be nil")
	require.NotNil(t, scenario.WaitForPropagation, "WaitForPropagation must not be nil")
	require.Equal(t, configv1.EncryptionTypeKMS, scenario.Provider.Type, "Provider must use KMS encryption type")
	require.Equal(t, configv1.EncryptionTypeKMS, scenario.UpdatedProvider.Type, "UpdatedProvider must use KMS encryption type")

	steps := []testStep{
		{name: "ApplyValidProviderAndVerifyMigration", testFunc: func(t testing.TB) {
			SetAndWaitForEncryptionType(ctx, t, scenario.Provider, scenario.TargetGRs,
				scenario.Namespace, scenario.LabelSelector)
			scenario.AssertFunc(t, clientSet, scenario.Provider.Type,
				scenario.Namespace, scenario.LabelSelector)
		}},
		{name: "UpdateInPlaceField", testFunc: func(t testing.TB) {
			keyMeta, err := GetLastKeyMeta(t, clientSet.Kube,
				scenario.Namespace, scenario.LabelSelector)
			require.NoError(t, err)
			scenario.UpdatedProvider.Setup(ctx, t)
			ApplyEncryption(ctx, t, scenario.UpdatedProvider.APIServerEncryption)
			WaitForNoNewEncryptionKey(t, clientSet.Kube, keyMeta,
				scenario.Namespace, scenario.LabelSelector)
		}},
		{name: "WaitForPropagation", testFunc: func(t testing.TB) {
			keyMeta, err := GetLastKeyMeta(t, clientSet.Kube,
				scenario.Namespace, scenario.LabelSelector)
			require.NoError(t, err)
			scenario.WaitForPropagation(ctx, t, keyMeta)
		}},
	}

	for _, step := range steps {
		t.Logf("=== STEP: %s ===", step.name)
		step.testFunc(e)
		if t.Failed() {
			t.Errorf("stopping the test as %q step failed", step.name)
			return
		}
	}
}

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

func TestEncryptionTurnOnAndOff(ctx context.Context, t testing.TB, onOffScenarios ...OnOffScenario) {
	if len(onOffScenarios) == 0 {
		t.Fatalf("TestEncryptionTurnOnAndOff requires at least one scenario")
	}

	// Only one scenario should provide EncryptionProvider (shared cluster-wide APIServer config).
	var providers []EncryptionProvider
	for _, scenario := range onOffScenarios {
		if scenario.EncryptionProvider.Type != "" {
			providers = append(providers, scenario.EncryptionProvider)
		}
	}
	if len(providers) != 1 {
		t.Fatalf("TestEncryptionTurnOnAndOff requires exactly one EncryptionProvider, got %d", len(providers))
	}
	provider := providers[0]

	var (
		createSteps                   []testStep
		onSteps                       []testStep
		assertEncryptedSteps          []testStep
		offSteps                      []testStep
		assertNotEncryptedSteps       []testStep
		onStepsSecond                 []testStep
		assertEncryptedStepsSecond    []testStep
		offStepsSecond                []testStep
		assertNotEncryptedStepsSecond []testStep
	)
	for _, scenario := range onOffScenarios {
		createSteps = append(createSteps, testStep{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.CreateResourceFunc(e, GetClients(e), scenario.Namespace)
		}})
		onSteps = append(onSteps, testStep{name: fmt.Sprintf("On%s%s", strings.ToUpper(string(provider.Type)), scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionType(ctx, t, scenario.BasicScenario, provider)
		}})
		assertEncryptedSteps = append(assertEncryptedSteps, testStep{name: fmt.Sprintf("Assert%sEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}})
		offSteps = append(offSteps, testStep{name: fmt.Sprintf("OffIdentity%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionTypeIdentity(ctx, t, scenario.BasicScenario)
		}})
		assertNotEncryptedSteps = append(assertNotEncryptedSteps, testStep{name: fmt.Sprintf("Assert%sNotEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}})
		onStepsSecond = append(onStepsSecond, testStep{name: fmt.Sprintf("On%s%sSecond", strings.ToUpper(string(provider.Type)), scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionType(ctx, t, scenario.BasicScenario, provider)
		}})
		assertEncryptedStepsSecond = append(assertEncryptedStepsSecond, testStep{name: fmt.Sprintf("Assert%sEncryptedSecond", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}})
		offStepsSecond = append(offStepsSecond, testStep{name: fmt.Sprintf("OffIdentitySecond%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionTypeIdentity(ctx, t, scenario.BasicScenario)
		}})
		assertNotEncryptedStepsSecond = append(assertNotEncryptedStepsSecond, testStep{name: fmt.Sprintf("Assert%sNotEncryptedSecond", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}})
	}

	scenarios := []testStep{
		inParallel(createSteps...),
		inParallel(onSteps...),
		inParallel(assertEncryptedSteps...),
		inParallel(offSteps...),
		inParallel(assertNotEncryptedSteps...),
		inParallel(onStepsSecond...),
		inParallel(assertEncryptedStepsSecond...),
		inParallel(offStepsSecond...),
		inParallel(assertNotEncryptedStepsSecond...),
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
// Pass one scenario for a single operator, or multiple scenarios to run
// KAS/Auth/OAS migration together. Only one scenario should provide EncryptionProviders.
func TestEncryptionProvidersMigration(ctx context.Context, t testing.TB, migrationScenarios ...ProvidersMigrationScenario) {
	if len(migrationScenarios) == 0 {
		t.Fatalf("TestEncryptionProvidersMigration requires at least one scenario")
	}

	var providerScenario *ProvidersMigrationScenario
	for i := range migrationScenarios {
		if len(migrationScenarios[i].EncryptionProviders) == 0 {
			continue
		}
		if providerScenario != nil {
			t.Fatalf("only one scenario may provide EncryptionProviders, got %q and %q",
				providerScenario.ResourceName, migrationScenarios[i].ResourceName)
		}
		providerScenario = &migrationScenarios[i]
	}
	if providerScenario == nil {
		t.Fatalf("one scenario must provide EncryptionProviders")
	}

	providers := providerScenario.EncryptionProviders
	if len(providers) < 2 {
		t.Fatalf("ProvidersMigrationScenario requires at least 2 encryption providers, got %d", len(providers))
	}

	for _, provider := range providers {
		if provider.Type == configv1.EncryptionTypeIdentity || provider.Type == "" {
			t.Fatalf("Unsupported encryption provider %q passed", provider.Type)
		}
	}

	// step 1: create the resource
	var createSteps []testStep
	for _, scenario := range migrationScenarios {
		createSteps = append(createSteps, testStep{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.CreateResourceFunc(e, GetClients(e), scenario.Namespace)
		}})
	}
	scenarios := []testStep{inParallel(createSteps...)}

	// step 2: migrate through each provider in sequence
	for i, provider := range providers {
		prefix := "EncryptWith"
		if i > 0 {
			prefix = "MigrateTo"
		}

		var migrateSteps []testStep
		for _, scenario := range migrationScenarios {
			migrateSteps = append(migrateSteps, testStep{
				name: fmt.Sprintf("%s%s%s", prefix, strings.ToUpper(string(provider.Type)), scenario.ResourceName),
				testFunc: func(t testing.TB) {
					TestEncryptionType(ctx, t, scenario.BasicScenario, provider)
				},
			})
		}

		var assertSteps []testStep
		for _, scenario := range migrationScenarios {
			assertSteps = append(assertSteps, testStep{
				name: fmt.Sprintf("Assert%s%sEncrypted", strings.ToUpper(string(provider.Type)), scenario.ResourceName),
				testFunc: func(t testing.TB) {
					e := NewE(t)
					scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
				},
			})
		}

		scenarios = append(scenarios, inParallel(migrateSteps...), inParallel(assertSteps...))
	}

	// step 3: switch to identity (off) to verify the resource is re-written unencrypted
	var offSteps []testStep
	for _, scenario := range migrationScenarios {
		offSteps = append(offSteps, testStep{name: fmt.Sprintf("OffIdentityAndAssert%sNotEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionTypeIdentity(ctx, t, scenario.BasicScenario)
			e := NewE(t)
			scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}})
	}
	scenarios = append(scenarios, inParallel(offSteps...))

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

// InPlaceUpdateScenario tests that updating a config field that does not affect
// the encryption key (e.g. KMS plugin image) takes effect without creating a
// new encryption key and without disrupting existing encrypted resources.
type InPlaceUpdateScenario struct {
	BasicScenario
	CreateResourceFunc          func(t testing.TB, clientSet ClientSet, namespace string) runtime.Object
	AssertResourceEncryptedFunc func(t testing.TB, clientSet ClientSet, resource runtime.Object)
	ResourceFunc                func(t testing.TB, namespace string) runtime.Object
	ResourceName                string
	EncryptionProvider          EncryptionProvider
	UpdatedEncryptionProvider   EncryptionProvider
	AssertInPlaceUpdateFunc     func(t testing.TB, clientSet ClientSet, keyMeta EncryptionKeyMeta)
}

// TestInPlaceUpdate validates in-place config field updates:
//  1. Create the resource
//  2. Encrypt with the initial provider and verify migration
//  3. Assert the resource is encrypted
//  4. Apply updated provider and verify no new encryption key is created
//  5. Assert the resource remains encrypted after the update
//  6. AssertInPlaceUpdateFunc — caller verifies the change took effect
func TestInPlaceUpdate(ctx context.Context, t testing.TB, scenario InPlaceUpdateScenario) {
	steps := []testStep{
		{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.CreateResourceFunc(e, GetClients(e), scenario.Namespace)
		}},
		{name: fmt.Sprintf("EncryptWith%s", strings.ToUpper(string(scenario.EncryptionProvider.Type))), testFunc: func(t testing.TB) {
			TestEncryptionType(ctx, t, scenario.BasicScenario, scenario.EncryptionProvider)
		}},
		{name: fmt.Sprintf("Assert%sEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: "ApplyInPlaceUpdate", testFunc: func(t testing.TB) {
			e := NewE(t)
			clientSet := GetClients(e)
			keyMeta, err := GetLastKeyMeta(e, clientSet.Kube,
				scenario.Namespace, scenario.LabelSelector)
			require.NoError(e, err)
			if scenario.UpdatedEncryptionProvider.Setup != nil {
				scenario.UpdatedEncryptionProvider.Setup(ctx, e)
			}
			ApplyEncryption(ctx, e, scenario.UpdatedEncryptionProvider.APIServerEncryption)
			WaitForNoNewEncryptionKey(e, clientSet.Kube, keyMeta,
				scenario.Namespace, scenario.LabelSelector)
		}},
		{name: fmt.Sprintf("Assert%sEncryptedAfterUpdate", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: fmt.Sprintf("AssertInPlaceUpdate%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			clientSet := GetClients(e)
			keyMeta, err := GetLastKeyMeta(e, clientSet.Kube,
				scenario.Namespace, scenario.LabelSelector)
			require.NoError(e, err)
			scenario.AssertInPlaceUpdateFunc(e, clientSet, keyMeta)
		}},
	}

	for _, step := range steps {
		t.Logf("=== STEP: %s ===", step.name)
		step.testFunc(t)
		if t.Failed() {
			t.Errorf("stopping the test as %q step failed", step.name)
			return
		}
	}
}

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
	operatorv1 "github.com/openshift/api/operator/v1"
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

// KMSPreflightNegativeScenario follows the OnOffScenario pattern: each scenario
// embeds BasicScenario for the operator and carries the invalid provider.
// AssertFailedFunc lets the caller distinguish preflight result=Failed (checker
// reached the KMS but the check failed) from Degraded-only (image pull, deploy
// error).
type KMSPreflightNegativeScenario struct {
	BasicScenario
	Name            string
	InvalidProvider EncryptionProvider
	// AssertFailedFunc asserts the expected failure path: Degraded-only (e.g. bad
	// image) or result=Failed (e.g. bad address).
	AssertFailedFunc func(ctx context.Context, t testing.TB, clientSet ClientSet, operatorNamespace string, previous operatorv1.KMSPreflightCheck)
}

// KMSPreflightLifecycleScenario exercises the full KMS preflight lifecycle:
//
//  1. For each invalid config: apply → assert preflight failure + no new key
//     (identity between invalid configs; last invalid recovers directly to valid KMS)
//  2. Valid KMS config → recover encryption (new key) → assert encrypted
//  3. In-place field update → assert no new key → assert still encrypted → assert update
//  4. Identity (cleanup)
//
// It embeds InPlaceUpdateScenario for the valid-encrypt + in-place steps and adds
// InvalidConfigs for the preflight-negative portion.
type KMSPreflightLifecycleScenario struct {
	InPlaceUpdateScenario
	// InvalidConfigs holds one or more invalid KMS provider configs to test.
	// Each entry is tested in sequence with an identity reset between them
	// (except after the last, which recovers directly to the valid KMS provider).
	InvalidConfigs []KMSPreflightNegativeScenario
}

// TestKMSPreflightLifecycle tests invalid KMS configurations with identity recovery
// between them, then valid encryption, an in-place update, and a final identity reset.
// One scenario supplies the cluster-wide providers; all scenarios verify their operators.
func TestKMSPreflightLifecycle(ctx context.Context, t testing.TB, scenarios ...KMSPreflightLifecycleScenario) {
	t.Helper()
	require.NotEmpty(t, scenarios, "TestKMSPreflightLifecycle requires at least one scenario")

	numInvalid := len(scenarios[0].InvalidConfigs)
	require.NotZero(t, numInvalid, "KMSPreflightLifecycleScenario requires at least one InvalidConfig")

	var inPlaceScenarios []InPlaceUpdateScenario
	var provider EncryptionProvider
	var revertSteps, cleanupSteps []testStep
	for _, scenario := range scenarios {
		require.Len(t, scenario.InvalidConfigs, numInvalid, "all scenarios must have the same number of InvalidConfigs")
		inPlaceScenarios = append(inPlaceScenarios, scenario.InPlaceUpdateScenario)
		if scenario.EncryptionProvider.Type != "" {
			provider = scenario.EncryptionProvider
		}
		revertSteps = append(revertSteps, testStep{name: fmt.Sprintf("RevertToIdentity%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionTypeIdentity(ctx, t, scenario.BasicScenario)
		}})
		cleanupSteps = append(cleanupSteps, testStep{name: fmt.Sprintf("CleanupIdentity%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionTypeIdentity(context.Background(), t, scenario.BasicScenario)
		}})
	}

	createStep, updateSteps := inPlaceUpdateTestSteps(ctx, t, inPlaceScenarios...)
	require.Equal(t, configv1.EncryptionTypeKMS, provider.Type, "preflight lifecycle requires a KMS provider")

	e := NewE(t, PrintEventsOnFailure(scenarios[0].OperatorNamespace))
	clients := GetClients(e)

	apiServer, err := clients.ApiServerConfig.Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(e, err)
	require.Truef(e, apiServer.Spec.Encryption.Type == "" || apiServer.Spec.Encryption.Type == configv1.EncryptionTypeIdentity,
		"expected encryption off at start, got type=%q", apiServer.Spec.Encryption.Type)

	steps := []testStep{createStep}
	for idx := 0; idx < numInvalid; idx++ {
		batch := make([]KMSPreflightNegativeScenario, 0, len(scenarios))
		for _, scenario := range scenarios {
			invalid := scenario.InvalidConfigs[idx]
			invalid.BasicScenario = scenario.BasicScenario
			batch = append(batch, invalid)
		}
		name, invalidProvider := resolveKMSPreflightNegativeBatch(t, batch)
		var snapshotSteps, assertFailureSteps []testStep
		for _, scenario := range batch {
			require.NotNilf(t, scenario.AssertFailedFunc, "KMS preflight negative scenario %q for %s requires AssertFailedFunc", scenario.Name, scenario.OperatorNamespace)
			snapshot, assertFailure := kmsPreflightNegativeSteps(ctx, clients, name, scenario)
			snapshotSteps = append(snapshotSteps, snapshot)
			assertFailureSteps = append(assertFailureSteps, assertFailure)
		}
		steps = append(steps,
			inParallel(snapshotSteps...),
			testStep{name: fmt.Sprintf("Apply %s", name), testFunc: func(t testing.TB) {
				if invalidProvider.Setup != nil {
					invalidProvider.Setup(ctx, t)
				}
				ApplyEncryption(ctx, t, invalidProvider.APIServerEncryption)
			}},
			inParallel(assertFailureSteps...),
		)
		if idx < numInvalid-1 {
			steps = append(steps, inParallel(revertSteps...))
		}
	}

	// Snapshot every operator and start capturing before the shared valid setup
	// can trigger recovery. The APIServer KMS reference is already configured,
	// so SetAndWaitForEncryptionType would otherwise skip provider.Setup.
	var prepareSteps, encryptSteps []testStep
	for _, scenario := range scenarios {
		var previousKey EncryptionKeyMeta
		var assertPreflight func(testing.TB, ClientSet)
		prepareSteps = append(prepareSteps, testStep{name: fmt.Sprintf("PrepareKMSRecovery%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
			clientSet := GetClients(e)
			var err error
			previousKey, err = GetLastKeyMeta(e, clientSet.Kube, scenario.Namespace, scenario.LabelSelector)
			require.NoError(e, err)
			previousPreflight, err := ReadKMSPreflightForOperator(ctx, e, clientSet, scenario.OperatorNamespace)
			require.NoError(e, err)
			operandNamespace := operandNamespaceForOperator(scenario.OperatorNamespace)
			require.NotEmpty(e, operandNamespace)
			capturedPod, stopCapture := StartCapturingLatestPreflightPod(ctx, e, clientSet, operandNamespace)
			t.Cleanup(stopCapture)
			assertPreflight = func(t testing.TB, clientSet ClientSet) {
				stopCapture()
				AssertKMSPreflight(ctx, t, clientSet, scenario.OperatorNamespace, operandNamespace, previousPreflight, capturedPod.Load())
			}
		}})
		encryptSteps = append(encryptSteps, testStep{name: fmt.Sprintf("RecoverKMSEncryption%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
			clientSet := GetClients(e)
			WaitForNextMigratedKey(e, clientSet.Kube, previousKey, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
			scenario.AssertFunc(e, clientSet, provider.Type, scenario.Namespace, scenario.LabelSelector)
			AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
			assertPreflight(e, clientSet)
		}})
	}
	steps = append(steps,
		inParallel(prepareSteps...),
		testStep{name: "ApplyValidKMSConfig", testFunc: func(t testing.TB) {
			if provider.Setup != nil {
				provider.Setup(ctx, t)
			}
			ApplyEncryption(ctx, t, provider.APIServerEncryption)
		}},
		inParallel(encryptSteps...),
	)
	// Recovery replaces the builder's first step (initial encryption). Reuse
	// its remaining assertions, in-place update, and final identity reset.
	steps = append(steps, updateSteps[1:]...)

	// Always restore identity even if a step fails and returns early, so later
	// encryption tests still see encryption-off at start.
	t.Cleanup(func() {
		inParallel(cleanupSteps...).testFunc(e)
	})

	for _, step := range steps {
		t.Logf("=== STEP: %s ===", step.name)
		step.testFunc(e)
		if t.Failed() {
			t.Errorf("stopping the test as %q step failed", step.name)
			return
		}
	}
}

// resolveKMSPreflightNegativeBatch requires all scenarios in a batch to share Name and
// exactly one InvalidProvider (cluster-wide APIServer encryption), matching OnOffScenario.
func resolveKMSPreflightNegativeBatch(t testing.TB, scenarios []KMSPreflightNegativeScenario) (string, EncryptionProvider) {
	t.Helper()
	require.NotEmpty(t, scenarios)
	name := scenarios[0].Name
	require.NotEmptyf(t, name, "KMS preflight negative batch must set Name")

	var providers []EncryptionProvider
	for _, s := range scenarios {
		require.Equalf(t, name, s.Name, "all scenarios in a batch must share Name %q, got %q for %s", name, s.Name, s.OperatorNamespace)
		if s.InvalidProvider.Type != "" || s.InvalidProvider.Setup != nil {
			providers = append(providers, s.InvalidProvider)
		}
	}
	if len(providers) != 1 {
		t.Fatalf("batch %q requires exactly one InvalidProvider, got %d", name, len(providers))
	}
	return name, providers[0]
}

// kmsPreflightNegativeSteps returns a snapshot step (key + preflight baseline) and an assert
// step (failure + no new key). The assert step closes over values written by the snapshot
// step, so snapshot must run before assert for the same scenario.
func kmsPreflightNegativeSteps(ctx context.Context, clients ClientSet, name string, scenario KMSPreflightNegativeScenario) (testStep, testStep) {
	var baseline EncryptionKeyMeta
	var previousPreflight operatorv1.KMSPreflightCheck

	snapshotStep := testStep{
		name: fmt.Sprintf("Snapshot %s for %s", name, scenario.OperatorNamespace),
		testFunc: func(t testing.TB) {
			var err error
			baseline, err = GetLastKeyMeta(t, clients.Kube, scenario.Namespace, scenario.LabelSelector)
			require.NoError(t, err)
			previousPreflight, err = ReadKMSPreflightForOperator(ctx, t, clients, scenario.OperatorNamespace)
			require.NoError(t, err)
		},
	}
	assertFailureStep := testStep{
		name: fmt.Sprintf("Assert %s for %s", name, scenario.OperatorNamespace),
		testFunc: func(t testing.TB) {
			scenario.AssertFailedFunc(ctx, t, clients, scenario.OperatorNamespace, previousPreflight)
			WaitForNoNewEncryptionKey(t, clients.Kube, baseline, scenario.Namespace, scenario.LabelSelector)
		},
	}

	return snapshotStep, assertFailureStep
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
	// Snapshot preflight before applying the new config so the assertion can confirm a fresh
	// preflight ran for it (the remote key id advances when the config genuinely changes).
	previousPreflightStatus, err := ReadKMSPreflightForOperator(ctx, e, GetClients(e), scenario.OperatorNamespace)
	require.NoError(e, err)
	operandNamespace := operandNamespaceForOperator(scenario.OperatorNamespace)
	require.NotEmpty(e, operandNamespace, "no operand namespace known for operator namespace %q", scenario.OperatorNamespace)
	// Capture the preflight pod as the operator creates it; on success the operator reaps it,
	// so it cannot be fetched live afterwards for the PodSpec drift check below.
	capturedPreflightPod, stopCapture := StartCapturingLatestPreflightPod(ctx, e, GetClients(e), operandNamespace)
	defer stopCapture()
	clientSet := SetAndWaitForEncryptionType(ctx, e, provider, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	stopCapture() // preflight has run; join the watch before reading the capture
	scenario.AssertFunc(e, clientSet, provider.Type, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
	AssertKMSPreflight(ctx, e, clientSet, scenario.OperatorNamespace, operandNamespace, previousPreflightStatus, capturedPreflightPod.Load())
}

// operandNamespaceForOperator maps a control-plane operator namespace to the operand
// namespace where it runs its apiserver and KMS preflight pods.
func operandNamespaceForOperator(operatorNamespace string) string {
	switch operatorNamespace {
	case "openshift-kube-apiserver-operator":
		return "openshift-kube-apiserver"
	case "openshift-apiserver-operator":
		return "openshift-apiserver"
	case "openshift-authentication-operator":
		return "openshift-oauth-apiserver"
	default:
		return ""
	}
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
	ResourceName                string
	CreateResourceFunc          func(t testing.TB, clientSet ClientSet, namespace string) runtime.Object
	GetRawResourceFunc          func(t testing.TB, clientSet ClientSet, namespace string) string
	EncryptionProvider          EncryptionProvider
	ForceRotationFunc           ForceRotationFunc
	WaitForRotationCompleteFunc WaitForRotationCompleteFunc
}

// TestEncryptionRotation encrypts data, forces a provider-specific key rotation, waits for
// re-migration to complete, verifies the resource was re-encrypted with different content,
// and reverts to identity so the cluster is left in a clean state for the next test.
// Pass multiple scenarios to verify operators in parallel. Exactly one scenario
// supplies EncryptionProvider and exactly one supplies ForceRotationFunc for the
// shared rotation; every scenario supplies its own completion wait and assertions.
func TestEncryptionRotation(ctx context.Context, t testing.TB, scenarios ...RotationScenario) {
	t.Helper()
	steps := rotationTestSteps(ctx, t, scenarios...)
	for _, step := range steps {
		t.Logf("=== STEP: %s ===", step.name)
		step.testFunc(t)
		if t.Failed() {
			t.Errorf("stopping the test as %q step failed", step.name)
			return
		}
	}

	// TODO: assert conditions - operator and encryption migration controller must report status as active not progressing, and not failing for all scenarios
}

func rotationTestSteps(ctx context.Context, t testing.TB, scenarios ...RotationScenario) []testStep {
	t.Helper()
	if len(scenarios) == 0 {
		t.Fatalf("TestEncryptionRotation requires at least one scenario")
	}

	var providers []EncryptionProvider
	var rotations []ForceRotationFunc
	for _, scenario := range scenarios {
		if scenario.EncryptionProvider.Type != "" {
			providers = append(providers, scenario.EncryptionProvider)
		}
		if scenario.ForceRotationFunc != nil {
			rotations = append(rotations, scenario.ForceRotationFunc)
		}
	}
	if len(providers) != 1 || len(rotations) != 1 {
		t.Fatalf("TestEncryptionRotation requires exactly one EncryptionProvider and one ForceRotationFunc, got %d and %d", len(providers), len(rotations))
	}
	provider := providers[0]
	forceRotation := rotations[0]

	var createSteps, encryptSteps, baselineSteps, waitSteps, assertSteps, revertSteps []testStep
	for _, scenario := range scenarios {
		// Each scenario owns its baseline and ciphertext sample. All baselines are
		// recorded before the shared rotation can change any operator's key.
		var baseline EncryptionKeyMeta
		var rawEncryptedResourceWithKey1 string
		createSteps = append(createSteps, testStep{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.CreateResourceFunc(e, GetClients(e), scenario.Namespace)
		}})
		encryptSteps = append(encryptSteps, testStep{name: fmt.Sprintf("EncryptWith%s%s", strings.ToUpper(string(provider.Type)), scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionType(ctx, t, scenario.BasicScenario, provider)
		}})
		baselineSteps = append(baselineSteps, testStep{name: fmt.Sprintf("RecordKeyBaseline%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			clientSet := GetClients(e)
			rawEncryptedResourceWithKey1 = scenario.GetRawResourceFunc(e, clientSet, scenario.Namespace)
			keyMeta, err := GetLastKeyMeta(e, clientSet.Kube, scenario.Namespace, scenario.LabelSelector)
			require.NoError(e, err)
			baseline = keyMeta
		}})
		waitSteps = append(waitSteps, testStep{name: fmt.Sprintf("WaitForRotation%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.WaitForRotationCompleteFunc(e, GetClients(e), baseline, scenario.BasicScenario)
		}})
		assertSteps = append(assertSteps, testStep{name: fmt.Sprintf("Assert%sReencrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			clientSet := GetClients(e)
			scenario.AssertFunc(e, clientSet, provider.Type, scenario.Namespace, scenario.LabelSelector)
			rawEncryptedResourceWithKey2 := scenario.GetRawResourceFunc(e, clientSet, scenario.Namespace)
			if rawEncryptedResourceWithKey1 == rawEncryptedResourceWithKey2 {
				t.Errorf("expected the resource to have different content after a key rotation,\ncontentBeforeRotation %s\ncontentAfterRotation %s", rawEncryptedResourceWithKey1, rawEncryptedResourceWithKey2)
			}
		}})
		revertSteps = append(revertSteps, testStep{name: fmt.Sprintf("RevertToIdentity%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionTypeIdentity(ctx, t, scenario.BasicScenario)
		}})
	}

	return []testStep{
		inParallel(createSteps...),
		inParallel(encryptSteps...),
		inParallel(baselineSteps...),
		{name: "ForceKeyRotation", testFunc: func(t testing.TB) {
			forceRotation(NewE(t), ctx)
		}},
		inParallel(waitSteps...),
		inParallel(assertSteps...),
		inParallel(revertSteps...),
	}
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
//  4. Record each operator's current key baseline
//  5. Apply the update to the plugin CRD once (not the APIServer config)
//  6. Verify no new key is created for any operator
//  7. Assert the resource remains encrypted after the update
//  8. AssertInPlaceUpdateFunc — caller verifies the change took effect
//  9. Revert to identity so the cluster is left in a clean state for the next test
//
// Pass one scenario for a single operator, or multiple scenarios to run KAS/Auth/OAS together in
// parallel. Only one scenario should set EncryptionProvider/UpdatedEncryptionProvider (the shared
// cluster-wide APIServer config + plugin CRD).
//
// The update mutates only the plugin CRD (via UpdatedEncryptionProvider.Setup): the provider
// configuration lives on the referenced VaultKMSConfig CR, and APIServer.spec.encryption.kms only
// references it by name, so an in-place field change must not touch the APIServer config. The
// operator reconciles the change on resync. Because every operator shares that one CR, the baselines
// are recorded before the single shared update is applied, so the no-new-key check cannot miss a key
// minted by the update.
func TestInPlaceUpdate(ctx context.Context, t testing.TB, scenarios ...InPlaceUpdateScenario) {
	t.Helper()
	createStep, updateSteps := inPlaceUpdateTestSteps(ctx, t, scenarios...)
	steps := append([]testStep{createStep}, updateSteps...)

	for _, step := range steps {
		t.Logf("=== STEP: %s ===", step.name)
		step.testFunc(t)
		if t.Failed() {
			t.Errorf("stopping the test as %q step failed", step.name)
			return
		}
	}
}

// inPlaceUpdateTestSteps separates resource creation from encryption so lifecycle
// tests can insert preflight checks before enabling encryption.
func inPlaceUpdateTestSteps(ctx context.Context, t testing.TB, scenarios ...InPlaceUpdateScenario) (testStep, []testStep) {
	t.Helper()
	if len(scenarios) == 0 {
		t.Fatalf("TestInPlaceUpdate requires at least one scenario")
	}

	var providers, updatedProviders []EncryptionProvider
	for _, scenario := range scenarios {
		if scenario.EncryptionProvider.Type != "" {
			providers = append(providers, scenario.EncryptionProvider)
		}
		if scenario.UpdatedEncryptionProvider.Type != "" {
			updatedProviders = append(updatedProviders, scenario.UpdatedEncryptionProvider)
		}
	}
	if len(providers) != 1 || len(updatedProviders) != 1 {
		t.Fatalf("TestInPlaceUpdate requires exactly one EncryptionProvider and one UpdatedEncryptionProvider, got %d and %d", len(providers), len(updatedProviders))
	}
	provider := providers[0]
	updatedProvider := updatedProviders[0]

	var createSteps, encryptSteps, assertEncryptedSteps, baselineSteps, waitSteps, assertAfterSteps, assertInPlaceSteps, revertSteps []testStep
	for _, scenario := range scenarios {
		// baseline is captured before the shared update and read by the wait step. Each iteration owns
		// its own baseline variable, so the parallel baseline and wait phases never race.
		var baseline EncryptionKeyMeta
		createSteps = append(createSteps, testStep{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.CreateResourceFunc(e, GetClients(e), scenario.Namespace)
		}})
		encryptSteps = append(encryptSteps, testStep{name: fmt.Sprintf("EncryptWith%s%s", strings.ToUpper(string(provider.Type)), scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionType(ctx, t, scenario.BasicScenario, provider)
		}})
		assertEncryptedSteps = append(assertEncryptedSteps, testStep{name: fmt.Sprintf("Assert%sEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}})
		baselineSteps = append(baselineSteps, testStep{name: fmt.Sprintf("RecordKeyBaseline%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			keyMeta, err := GetLastKeyMeta(e, GetClients(e).Kube, scenario.Namespace, scenario.LabelSelector)
			require.NoError(e, err)
			baseline = keyMeta
		}})
		waitSteps = append(waitSteps, testStep{name: fmt.Sprintf("WaitNoNewKey%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			WaitForNoNewEncryptionKey(e, GetClients(e).Kube, baseline, scenario.Namespace, scenario.LabelSelector)
		}})
		assertAfterSteps = append(assertAfterSteps, testStep{name: fmt.Sprintf("Assert%sEncryptedAfterUpdate", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}})
		assertInPlaceSteps = append(assertInPlaceSteps, testStep{name: fmt.Sprintf("AssertInPlaceUpdate%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			clientSet := GetClients(e)
			keyMeta, err := GetLastKeyMeta(e, clientSet.Kube, scenario.Namespace, scenario.LabelSelector)
			require.NoError(e, err)
			scenario.AssertInPlaceUpdateFunc(e, clientSet, keyMeta)
		}})
		revertSteps = append(revertSteps, testStep{name: fmt.Sprintf("RevertToIdentity%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			TestEncryptionTypeIdentity(ctx, t, scenario.BasicScenario)
		}})
	}

	// Apply the shared plugin-CRD update once, after every baseline is recorded, so no baseline can
	// include a key minted by the update. The APIServer encryption config is not touched.
	applyInPlaceUpdate := testStep{name: "ApplyInPlaceUpdate", testFunc: func(t testing.TB) {
		if updatedProvider.Setup != nil {
			updatedProvider.Setup(ctx, NewE(t))
		}
	}}

	// The configuration is cluster-wide, but migration completes independently for
	// each operator. Wait for every scenario before the next test starts.
	return inParallel(createSteps...), []testStep{
		inParallel(encryptSteps...),
		inParallel(assertEncryptedSteps...),
		inParallel(baselineSteps...),
		applyInPlaceUpdate,
		inParallel(waitSteps...),
		inParallel(assertAfterSteps...),
		inParallel(assertInPlaceSteps...),
		inParallel(revertSteps...),
	}
}

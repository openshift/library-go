package encryption

import (
	"fmt"
	mathrand "math/rand/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"

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
	Setup func(t testing.TB)
}

func TestEncryptionTypeIdentity(t testing.TB, scenario BasicScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, EncryptionProvider{APIServerEncryption: configv1.APIServerEncryption{Type: configv1.EncryptionTypeIdentity}}, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, configv1.EncryptionTypeIdentity, scenario.Namespace, scenario.LabelSelector)
}

func TestEncryptionTypeUnset(t testing.TB, scenario BasicScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, EncryptionProvider{}, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
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

func TestEncryptionTypeAESCBC(t testing.TB, scenario BasicScenario, providers ...EncryptionProvider) {
	provider := resolveProvider(t, configv1.EncryptionTypeAESCBC, providers)
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, provider, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, provider.Type, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
}

func TestEncryptionTypeAESGCM(t testing.TB, scenario BasicScenario, providers ...EncryptionProvider) {
	provider := resolveProvider(t, configv1.EncryptionTypeAESGCM, providers)
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, provider, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, provider.Type, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
}

func TestEncryptionTypeKMS(t testing.TB, scenario BasicScenario, providers ...EncryptionProvider) {
	provider := resolveProvider(t, configv1.EncryptionTypeKMS, providers)
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, provider, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, provider.Type, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
}

func TestEncryptionType(t testing.TB, scenario BasicScenario, provider EncryptionProvider) {
	switch provider.Type {
	case configv1.EncryptionTypeAESCBC:
		TestEncryptionTypeAESCBC(t, scenario, provider)
	case configv1.EncryptionTypeAESGCM:
		TestEncryptionTypeAESGCM(t, scenario, provider)
	case configv1.EncryptionTypeKMS:
		TestEncryptionTypeKMS(t, scenario, provider)
	case configv1.EncryptionTypeIdentity, "":
		TestEncryptionTypeIdentity(t, scenario)
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

func TestEncryptionTurnOnAndOff(t testing.TB, scenario OnOffScenario) {
	scenarios := []testStep{
		{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.CreateResourceFunc(e, GetClients(e), scenario.Namespace)
		}},
		{name: fmt.Sprintf("On%s", strings.ToUpper(string(scenario.EncryptionProvider.Type))), testFunc: func(t testing.TB) { TestEncryptionType(t, scenario.BasicScenario, scenario.EncryptionProvider) }},
		{name: fmt.Sprintf("Assert%sEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: "OffIdentity", testFunc: func(t testing.TB) { TestEncryptionTypeIdentity(t, scenario.BasicScenario) }},
		{name: fmt.Sprintf("Assert%sNotEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: fmt.Sprintf("On%sSecond", strings.ToUpper(string(scenario.EncryptionProvider.Type))), testFunc: func(t testing.TB) { TestEncryptionType(t, scenario.BasicScenario, scenario.EncryptionProvider) }},
		{name: fmt.Sprintf("Assert%sEncryptedSecond", scenario.ResourceName), testFunc: func(t testing.TB) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: "OffIdentitySecond", testFunc: func(t testing.TB) { TestEncryptionTypeIdentity(t, scenario.BasicScenario) }},
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
func TestEncryptionProvidersMigration(t testing.TB, scenario ProvidersMigrationScenario) {
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
				TestEncryptionType(t, scenario.BasicScenario, provider)
			}},
			testStep{name: fmt.Sprintf("Assert%sEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
				e := NewE(t)
				scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
			}},
		)
	}

	// step 3: switch to identity (off) to verify the resource is re-written unencrypted
	scenarios = append(scenarios, testStep{name: fmt.Sprintf("OffIdentityAndAssert%sNotEncrypted", scenario.ResourceName), testFunc: func(t testing.TB) {
		TestEncryptionTypeIdentity(t, scenario.BasicScenario)
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
	CreateResourceFunc    func(t testing.TB, clientSet ClientSet, namespace string) runtime.Object
	GetRawResourceFunc    func(t testing.TB, clientSet ClientSet, namespace string) string
	UnsupportedConfigFunc UpdateUnsupportedConfigFunc
	EncryptionProvider    EncryptionProvider
	// GetOperatorConditionsFunc is optional. Overlap tests use it to detect an active migration via
	// EncryptionMigrationControllerProgressing before falling back to polling encryption key secrets.
	GetOperatorConditionsFunc GetOperatorConditionsFuncType
}

// TestEncryptionRotation first encrypts data with aescbc key
// then it forces a key rotation by setting the "encyrption.Reason" in the operator's configuration file
func TestEncryptionRotation(t testing.TB, scenario RotationScenario) {
	// test data
	ns := scenario.Namespace
	labelSelector := scenario.LabelSelector

	// step 1: create the desired resource
	e := NewE(t)
	defer func() {
		if err := ClearForcedKeyRotationReason(e, scenario.UnsupportedConfigFunc); err != nil {
			e.Logf("cleanup: clear encryption rotation reason: %v", err)
			if !t.Failed() {
				require.NoError(e, err, "test cleanup: clear encryption rotation reason")
			}
		}
	}()
	clientSet := GetClients(e)
	scenario.CreateResourceFunc(e, GetClients(e), ns)

	// step 2: run provided encryption scenario
	TestEncryptionType(t, scenario.BasicScenario, scenario.EncryptionProvider)

	// step 3: take samples
	rawEncryptedResourceWithKey1 := scenario.GetRawResourceFunc(e, clientSet, ns)

	// step 4: force key rotation and wait for migration to complete
	lastMigratedKeyMeta, err := GetLastKeyMeta(t, clientSet.Kube, ns, labelSelector)
	require.NoError(e, err)
	require.NoError(e, ForceKeyRotation(e, scenario.UnsupportedConfigFunc, fmt.Sprintf("test-key-rotation-%s", rand.String(4))))
	WaitForNextMigratedKey(e, clientSet.Kube, lastMigratedKeyMeta, scenario.TargetGRs, ns, labelSelector)
	scenario.AssertFunc(e, clientSet, scenario.EncryptionProvider.Type, ns, labelSelector)

	// step 5: verify if the provided resource was encrypted with a different key (step 2 vs step 4)
	rawEncryptedResourceWithKey2 := scenario.GetRawResourceFunc(e, clientSet, ns)
	if rawEncryptedResourceWithKey1 == rawEncryptedResourceWithKey2 {
		t.Errorf("expected the resource to has a different content after a key rotation,\ncontentBeforeRotation %s\ncontentAfterRotation %s", rawEncryptedResourceWithKey1, rawEncryptedResourceWithKey2)
	}

	// TODO: assert conditions - operator and encryption migration controller must report status as active not progressing, and not failing for all scenarios
}

// TestEncryptionRotationDuringFirstMigration ensures storage starts from identity, turns encryption on
// (initial migration), forces a key rotation while that first migration is still running, then asserts
// convergence. Use this to exercise overlap between the first encrypt migration and an external rotation
// reason—not stacked rotations on an already-encrypted cluster.
func TestEncryptionRotationDuringFirstMigration(t testing.TB, scenario RotationScenario) {
	ns := scenario.Namespace
	labelSelector := scenario.LabelSelector

	e := NewE(t)
	defer func() {
		if err := ClearForcedKeyRotationReason(e, scenario.UnsupportedConfigFunc); err != nil {
			e.Logf("cleanup: clear encryption rotation reason: %v", err)
			if !t.Failed() {
				require.NoError(e, err, "test cleanup: clear encryption rotation reason")
			}
		}
	}()
	clientSet := GetClients(e)
	scenario.CreateResourceFunc(e, clientSet, ns)

	// ApplyAPIServerEncryptionType is a no-op when the APIServer is already on the target type; start from
	// identity so the first storage migration always runs.
	TestEncryptionTypeIdentity(t, scenario.BasicScenario)

	prevMeta, err := GetLastKeyMeta(e, clientSet.Kube, ns, labelSelector)
	require.NoError(e, err)
	expectedFirstWriteKey, err := determineNextEncryptionKeyName(prevMeta.Name, labelSelector)
	require.NoError(e, err)

	ApplyAPIServerEncryptionType(e, clientSet, scenario.EncryptionProvider)

	if !WaitForEncryptionMigrationInProgressWindow(e, clientSet.Kube, scenario.GetOperatorConditionsFunc, expectedFirstWriteKey, scenario.TargetGRs, ns, labelSelector) {
		t.Skipf("initial migration finished before an in-progress window was observed; set GetOperatorConditionsFunc or use a cluster where migration stays visible longer")
	}

	require.NoError(e, ForceKeyRotation(e, scenario.UnsupportedConfigFunc, fmt.Sprintf("test-rotation-during-first-migration-%s", rand.String(4))))
	// n=2: one write-key revision from turning encryption on, one from ForceKeyRotation.
	WaitForNRotations(e, clientSet.Kube, scenario.EncryptionProvider.Type, scenario.TargetGRs, ns, labelSelector, prevMeta, 2)

	scenario.AssertFunc(e, clientSet, scenario.EncryptionProvider.Type, ns, labelSelector)
}

// TestEncryptionRotationDuringOngoingRotation runs with encryption already enabled and stable, then forces
// two key rotations in quick succession so the second happens while migration from the first is still
// in progress. This targets stacked external rotation reasons—not the first encrypt-from-identity path.
func TestEncryptionRotationDuringOngoingRotation(t testing.TB, scenario RotationScenario) {
	ns := scenario.Namespace
	labelSelector := scenario.LabelSelector

	e := NewE(t)
	defer func() {
		if err := ClearForcedKeyRotationReason(e, scenario.UnsupportedConfigFunc); err != nil {
			e.Logf("cleanup: clear encryption rotation reason: %v", err)
			if !t.Failed() {
				require.NoError(e, err, "test cleanup: clear encryption rotation reason")
			}
		}
	}()
	clientSet := GetClients(e)
	scenario.CreateResourceFunc(e, clientSet, ns)

	TestEncryptionType(t, scenario.BasicScenario, scenario.EncryptionProvider)

	metaAfterEncrypt, err := GetLastKeyMeta(e, clientSet.Kube, ns, labelSelector)
	require.NoError(e, err)
	expectedNextWriteKey, err := determineNextEncryptionKeyName(metaAfterEncrypt.Name, labelSelector)
	require.NoError(e, err)

	require.NoError(e, ForceKeyRotation(e, scenario.UnsupportedConfigFunc, fmt.Sprintf("test-rotation-overlap-first-%s", rand.String(4))))

	if !WaitForEncryptionMigrationInProgressWindow(e, clientSet.Kube, scenario.GetOperatorConditionsFunc, expectedNextWriteKey, scenario.TargetGRs, ns, labelSelector) {
		t.Skipf("migration after first forced rotation finished before an in-progress window was observed; set GetOperatorConditionsFunc or use a slower cluster")
	}

	require.NoError(e, ForceKeyRotation(e, scenario.UnsupportedConfigFunc, fmt.Sprintf("test-rotation-overlap-second-%s", rand.String(4))))
	// n=2: two ForceKeyRotation steps after metaAfterEncrypt.
	WaitForNRotations(e, clientSet.Kube, scenario.EncryptionProvider.Type, scenario.TargetGRs, ns, labelSelector, metaAfterEncrypt, 2)

	scenario.AssertFunc(e, clientSet, scenario.EncryptionProvider.Type, ns, labelSelector)
}

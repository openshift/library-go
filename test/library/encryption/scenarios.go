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
	"k8s.io/apimachinery/pkg/util/rand"

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
	CreateResourceFunc    func(t testing.TB, clientSet ClientSet, namespace string) runtime.Object
	GetRawResourceFunc    func(t testing.TB, clientSet ClientSet, namespace string) string
	UnsupportedConfigFunc UpdateUnsupportedConfigFunc
	EncryptionProvider    EncryptionProvider
}

// TestEncryptionRotation first encrypts data with aescbc key
// then it forces a key rotation by setting the "encyrption.Reason" in the operator's configuration file
func TestEncryptionRotation(ctx context.Context, t testing.TB, scenario RotationScenario) {
	// test data
	ns := scenario.Namespace
	labelSelector := scenario.LabelSelector

	// step 1: create the desired resource
	e := NewE(t)
	clientSet := GetClients(e)
	scenario.CreateResourceFunc(e, GetClients(e), ns)

	// step 2: run provided encryption scenario
	TestEncryptionType(ctx, t, scenario.BasicScenario, scenario.EncryptionProvider)

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

// InvalidImageRecoveryScenario tests that an invalid KMS plugin image causes
// the operator to degrade (even when switching to aescbc) and that providing
// a valid KMS image restores normal operation.
//
// Flow:
//  1. Enable KMS with invalid (non-existent) plugin image
//  2. Switch to aescbc — cluster should remain stuck on KMS (rollout blocked)
//  3. Operator reports degraded (stuck NodeInstaller, ImagePullBackOff, etc.)
//  4. Fix by applying KMS with valid image and wait for full encryption migration
type InvalidImageRecoveryScenario struct {
	BasicScenario
	// InvalidImageProvider is the KMS EncryptionProvider configured with an invalid
	// (non-existent or broken) KMS plugin image. Enabling this should cause degradation.
	InvalidImageProvider EncryptionProvider
	// ValidImageProvider is the KMS EncryptionProvider configured with the correct
	// KMS plugin image. Applying this after degradation should restore the cluster.
	ValidImageProvider EncryptionProvider
	// WaitForDegraded should block until the operator reports a degraded condition.
	WaitForDegraded func(ctx context.Context, t testing.TB)
}

// TestEncryptionInvalidImageRecovery tests that:
//  1. Enabling KMS with an invalid plugin image causes the operator to degrade
//  2. Switching to aescbc does NOT recover (cluster is stuck on the failed KMS rollout)
//  3. Providing a valid KMS image restores the cluster (uses SetAndWaitForEncryptionType)
func TestEncryptionInvalidImageRecovery(ctx context.Context, t testing.TB, scenario InvalidImageRecoveryScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	require.NotNil(t, scenario.WaitForDegraded, "WaitForDegraded must not be nil")
	require.Equal(t, configv1.EncryptionTypeKMS, scenario.InvalidImageProvider.Type, "InvalidImageProvider must be KMS type")
	require.Equal(t, configv1.EncryptionTypeKMS, scenario.ValidImageProvider.Type, "ValidImageProvider must be KMS type")

	cs := GetClients(e)

	// step 1: enable KMS with invalid image (set config but don't wait for completion)
	t.Log("Setting KMS encryption with invalid plugin image")
	if scenario.InvalidImageProvider.Setup != nil {
		scenario.InvalidImageProvider.Setup(ctx, e)
	}
	apiServer, err := cs.ApiServerConfig.Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)
	apiServer.Spec.Encryption = scenario.InvalidImageProvider.APIServerEncryption
	_, err = cs.ApiServerConfig.Update(ctx, apiServer, metav1.UpdateOptions{})
	require.NoError(t, err)

	// step 2: attempt to switch to aescbc — the cluster should remain stuck on KMS
	// because the static pod rollout with the invalid image is blocking progress
	t.Log("Attempting to switch to aescbc (cluster should remain stuck on KMS)")
	apiServer, err = cs.ApiServerConfig.Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)
	apiServer.Spec.Encryption = configv1.APIServerEncryption{Type: configv1.EncryptionTypeAESCBC}
	_, err = cs.ApiServerConfig.Update(ctx, apiServer, metav1.UpdateOptions{})
	require.NoError(t, err)

	// step 3: wait for degraded — the operator is stuck because the invalid KMS image
	// prevents the NodeInstaller from completing the rollout
	t.Log("Waiting for operator to report degraded status")
	scenario.WaitForDegraded(ctx, e)

	// step 4: fix by applying KMS with valid image and wait for full recovery
	// (uses SetAndWaitForEncryptionType which waits for encryption key migration,
	// same as the standard encryption on/off and migration tests)
	t.Log("Recovering: applying KMS with valid plugin image and waiting for full migration")
	SetAndWaitForEncryptionType(ctx, e, scenario.ValidImageProvider, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)

	t.Log("Invalid image recovery test passed")
}

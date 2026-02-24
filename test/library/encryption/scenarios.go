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

func TestEncryptionTypeIdentity(t *testing.T, scenario BasicScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, configv1.EncryptionTypeIdentity, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, configv1.EncryptionTypeIdentity, scenario.Namespace, scenario.LabelSelector)
}

func TestEncryptionTypeUnset(t *testing.T, scenario BasicScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, "", scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, configv1.EncryptionTypeIdentity, scenario.Namespace, scenario.LabelSelector)
}

func TestEncryptionTypeAESCBC(t *testing.T, scenario BasicScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, configv1.EncryptionTypeAESCBC, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, configv1.EncryptionTypeAESCBC, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
}

func TestEncryptionTypeAESGCM(t *testing.T, scenario BasicScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, configv1.EncryptionTypeAESGCM, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, configv1.EncryptionTypeAESGCM, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
}

func TestEncryptionTypeKMS(t *testing.T, scenario BasicScenario) {
	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	clientSet := SetAndWaitForEncryptionType(e, configv1.EncryptionTypeKMS, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	scenario.AssertFunc(e, clientSet, configv1.EncryptionTypeKMS, scenario.Namespace, scenario.LabelSelector)
	AssertEncryptionConfig(e, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
}

func TestEncryptionType(t *testing.T, scenario BasicScenario, provider configv1.EncryptionType) {
	switch provider {
	case configv1.EncryptionTypeAESCBC:
		TestEncryptionTypeAESCBC(t, scenario)
	case configv1.EncryptionTypeAESGCM:
		TestEncryptionTypeAESGCM(t, scenario)
	case configv1.EncryptionTypeKMS:
		TestEncryptionTypeKMS(t, scenario)
	case configv1.EncryptionTypeIdentity, "":
		TestEncryptionTypeIdentity(t, scenario)
	default:
		t.Fatalf("Unknown encryption type: %s", provider)
	}
}

type OnOffScenario struct {
	BasicScenario
	CreateResourceFunc             func(t testing.TB, clientSet ClientSet, namespace string) runtime.Object
	AssertResourceEncryptedFunc    func(t testing.TB, clientSet ClientSet, resource runtime.Object)
	AssertResourceNotEncryptedFunc func(t testing.TB, clientSet ClientSet, resource runtime.Object)
	ResourceFunc                   func(t testing.TB, namespace string) runtime.Object
	ResourceName                   string
	EncryptionProvider             configv1.EncryptionType
}

type testStep struct {
	name     string
	testFunc func(*testing.T)
}

func TestEncryptionTurnOnAndOff(t *testing.T, scenario OnOffScenario) {
	scenarios := []testStep{
		{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t *testing.T) {
			e := NewE(t)
			scenario.CreateResourceFunc(e, GetClients(e), scenario.Namespace)
		}},
		{name: fmt.Sprintf("On%s", strings.ToUpper(string(scenario.EncryptionProvider))), testFunc: func(t *testing.T) { TestEncryptionType(t, scenario.BasicScenario, scenario.EncryptionProvider) }},
		{name: fmt.Sprintf("Assert%sEncrypted", scenario.ResourceName), testFunc: func(t *testing.T) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: "OffIdentity", testFunc: func(t *testing.T) { TestEncryptionTypeIdentity(t, scenario.BasicScenario) }},
		{name: fmt.Sprintf("Assert%sNotEncrypted", scenario.ResourceName), testFunc: func(t *testing.T) {
			e := NewE(t)
			scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: fmt.Sprintf("On%sSecond", strings.ToUpper(string(scenario.EncryptionProvider))), testFunc: func(t *testing.T) { TestEncryptionType(t, scenario.BasicScenario, scenario.EncryptionProvider) }},
		{name: fmt.Sprintf("Assert%sEncryptedSecond", scenario.ResourceName), testFunc: func(t *testing.T) {
			e := NewE(t)
			scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
		{name: "OffIdentitySecond", testFunc: func(t *testing.T) { TestEncryptionTypeIdentity(t, scenario.BasicScenario) }},
		{name: fmt.Sprintf("Assert%sNotEncryptedSecond", scenario.ResourceName), testFunc: func(t *testing.T) {
			e := NewE(t)
			scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
		}},
	}

	// run scenarios
	for _, testScenario := range scenarios {
		t.Run(testScenario.name, testScenario.testFunc)
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
	EncryptionProviders []configv1.EncryptionType
}

// ShuffleEncryptionProviders returns a new slice with the providers in random order,
// leaving the original slice unchanged. Use this to test different migration orderings.
func ShuffleEncryptionProviders(providers []configv1.EncryptionType) []configv1.EncryptionType {
	shuffled := make([]configv1.EncryptionType, len(providers))
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
func TestEncryptionProvidersMigration(t *testing.T, scenario ProvidersMigrationScenario) {
	if len(scenario.EncryptionProviders) < 2 {
		t.Fatalf("ProvidersMigrationScenario requires at least 2 encryption providers, got %d", len(scenario.EncryptionProviders))
	}

	for _, provider := range scenario.EncryptionProviders {
		if provider == configv1.EncryptionTypeIdentity || provider == "" {
			t.Fatalf("Unsupported encryption provider %q passed", provider)
		}
	}

	// step 1: create the resource
	scenarios := []testStep{
		{name: fmt.Sprintf("CreateAndStore%s", scenario.ResourceName), testFunc: func(t *testing.T) {
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
			testStep{name: fmt.Sprintf("%s%s", prefix, strings.ToUpper(string(provider))), testFunc: func(t *testing.T) {
				TestEncryptionType(t, scenario.BasicScenario, provider)
			}},
			testStep{name: fmt.Sprintf("Assert%sEncrypted", scenario.ResourceName), testFunc: func(t *testing.T) {
				e := NewE(t)
				scenario.AssertResourceEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
			}},
		)
	}

	// step 3: switch to identity (off) to verify the resource is re-written unencrypted
	scenarios = append(scenarios, testStep{name: fmt.Sprintf("OffIdentityAndAssert%sNotEncrypted", scenario.ResourceName), testFunc: func(t *testing.T) {
		TestEncryptionTypeIdentity(t, scenario.BasicScenario)
		e := NewE(t)
		scenario.AssertResourceNotEncryptedFunc(e, GetClients(e), scenario.ResourceFunc(e, scenario.Namespace))
	}})

	// run scenarios
	for _, testScenario := range scenarios {
		t.Run(testScenario.name, testScenario.testFunc)
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
	EncryptionProvider    configv1.EncryptionType
}

// TestEncryptionRotation first encrypts data with aescbc key
// then it forces a key rotation by setting the "encyrption.Reason" in the operator's configuration file
func TestEncryptionRotation(t *testing.T, scenario RotationScenario) {
	// test data
	ns := scenario.Namespace
	labelSelector := scenario.LabelSelector

	// step 1: create the desired resource
	e := NewE(t)
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
	scenario.AssertFunc(e, clientSet, scenario.EncryptionProvider, ns, labelSelector)

	// step 5: verify if the provided resource was encrypted with a different key (step 2 vs step 4)
	rawEncryptedResourceWithKey2 := scenario.GetRawResourceFunc(e, clientSet, ns)
	if rawEncryptedResourceWithKey1 == rawEncryptedResourceWithKey2 {
		t.Errorf("expected the resource to has a different content after a key rotation,\ncontentBeforeRotation %s\ncontentAfterRotation %s", rawEncryptedResourceWithKey1, rawEncryptedResourceWithKey2)
	}

	// TODO: assert conditions - operator and encryption migration controller must report status as active not progressing, and not failing for all scenarios
}

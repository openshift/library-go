package encryption

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"

	configv1 "github.com/openshift/api/config/v1"
)

// TestKMSPerfEncryption is the KMS-specific migration perf entrypoint. It populates
// the database once, enables a single shared EncryptionProvider, and encrypts every
// scenario in parallel (typically KAS/Auth/OAS) while asserting each operator's
// migration time. Leave TestPerfEncryption unchanged for AES/single-operator cases.
func TestKMSPerfEncryption(ctx context.Context, t testing.TB, scenarios ...PerfScenario) {
	inputs, err := resolveKMSPerfScenarioInputs(scenarios)
	if err != nil {
		t.Fatalf("invalid KMS perf scenarios: %v", err)
	}

	e := NewE(t, PrintEventsOnFailure(scenarios[0].OperatorNamespace))

	if inputs.dbLoader != nil {
		populateDatabase(e, inputs.dbWorkers, inputs.dbLoader, inputs.dbAssert)
	}

	migrationStartedChs := make([]chan time.Time, len(scenarios))
	for i := range scenarios {
		if scenarios[i].GetOperatorConditionsFunc == nil {
			continue
		}
		migrationStartedChs[i] = make(chan time.Time, 1)
		watchForMigrationControllerProgressingConditionAsync(e, scenarios[i].GetOperatorConditionsFunc, migrationStartedChs[i])
	}

	provider := inputs.provider
	if provider.Setup != nil {
		setup := provider.Setup
		var setupOnce sync.Once
		provider.Setup = func(ctx context.Context, t testing.TB) {
			setupOnce.Do(func() { setup(ctx, t) })
		}
	}

	endTimeStamps := make([]time.Time, len(scenarios))
	encryptSteps := make([]testStep, 0, len(scenarios))
	for i := range scenarios {
		encryptSteps = append(encryptSteps, testStep{
			name: fmt.Sprintf("EncryptWith%sFor%s", strings.ToUpper(string(provider.Type)), scenarios[i].OperatorNamespace),
			testFunc: func(t testing.TB) {
				endTimeStamps[i] = runKMSPerfEncryption(ctx, t, scenarios[i], provider)
			},
		})
	}
	inParallel(encryptSteps...).testFunc(e)
	if t.Failed() {
		t.Errorf("stopping the test as enabling encryption failed")
		return
	}

	for i := range scenarios {
		if scenarios[i].AssertMigrationTime == nil {
			continue
		}
		select {
		case migrationStarted := <-migrationStartedChs[i]:
			scenarios[i].AssertMigrationTime(e, endTimeStamps[i].Sub(migrationStarted))
		default:
			// Operators with tiny GR sets (e.g. OAS routes) can finish migrating before
			// Progressing=True is observed. Encryption already succeeded above, so skip
			// timing rather than failing the whole multi-operator run.
			t.Logf("skipping migration timing for %q: EncryptionMigrationControllerProgressing was not observed (migration likely too fast to sample)", scenarios[i].OperatorNamespace)
		}
	}
}

type kmsPerfInputs struct {
	provider  EncryptionProvider
	dbLoader  DBLoaderFuncType
	dbAssert  func(t testing.TB, errorStore map[string]int, statStore map[string]int)
	dbWorkers int
}

func resolveKMSPerfScenarioInputs(scenarios []PerfScenario) (kmsPerfInputs, error) {
	if len(scenarios) == 0 {
		return kmsPerfInputs{}, fmt.Errorf("at least one scenario is required")
	}

	var (
		providers []EncryptionProvider
		loaders   []DBLoaderFuncType
		dbAsserts []func(t testing.TB, errorStore map[string]int, statStore map[string]int)
		workers   int
	)
	var inputs kmsPerfInputs
	for _, scenario := range scenarios {
		if scenario.EncryptionProvider.Type != "" {
			providers = append(providers, scenario.EncryptionProvider)
		}
		if (scenario.DBLoaderFunc != nil) != (scenario.AssertDBPopulatedFunc != nil) {
			return kmsPerfInputs{}, fmt.Errorf("scenario for %q must set both DBLoaderFunc and AssertDBPopulatedFunc, or neither", scenario.OperatorNamespace)
		}
		if (scenario.GetOperatorConditionsFunc != nil) != (scenario.AssertMigrationTime != nil) {
			return kmsPerfInputs{}, fmt.Errorf("scenario for %q must set both GetOperatorConditionsFunc and AssertMigrationTime, or neither", scenario.OperatorNamespace)
		}
		if scenario.DBLoaderFunc != nil {
			loaders = append(loaders, scenario.DBLoaderFunc)
			workers = max(workers, scenario.DBLoaderWorkers)
		}
		if scenario.AssertDBPopulatedFunc != nil {
			dbAsserts = append(dbAsserts, scenario.AssertDBPopulatedFunc)
		}
	}
	if len(providers) != 1 {
		return kmsPerfInputs{}, fmt.Errorf("expected exactly one EncryptionProvider, got %d", len(providers))
	}
	inputs.provider = providers[0]
	if len(loaders) > 0 {
		inputs.dbLoader = func(kubeClient kubernetes.Interface, namespace string, errorCollector func(error), statsCollector func(string)) error {
			return runWorkFunctions(kubeClient, namespace, errorCollector, statsCollector, loaders...)
		}
		inputs.dbAssert = func(t testing.TB, errorStore map[string]int, statStore map[string]int) {
			for _, assert := range dbAsserts {
				assert(t, errorStore, statStore)
			}
		}
		inputs.dbWorkers = max(workers, 1)
	}
	return inputs, nil
}

func runKMSPerfEncryption(ctx context.Context, tt testing.TB, scenario PerfScenario, provider EncryptionProvider) time.Time {
	var ts time.Time
	TestEncryptionType(ctx, tt, BasicScenario{
		Namespace:                       scenario.Namespace,
		LabelSelector:                   scenario.LabelSelector,
		EncryptionConfigSecretName:      scenario.EncryptionConfigSecretName,
		EncryptionConfigSecretNamespace: scenario.EncryptionConfigSecretNamespace,
		OperatorNamespace:               scenario.OperatorNamespace,
		TargetGRs:                       scenario.TargetGRs,
		AssertFunc: func(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
			ts = time.Now()
			scenario.AssertFunc(t, clientSet, expectedMode, scenario.Namespace, scenario.LabelSelector)
			t.Logf("AssertFunc for KMS perf scenario with %q provider took %v", provider.Type, time.Since(ts))
		},
	}, provider)
	return ts
}

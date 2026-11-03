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
	v1 "github.com/openshift/api/operator/v1"
)

type GetOperatorConditionsFuncType func(t testing.TB) ([]v1.OperatorCondition, error)

type PerfScenario struct {
	BasicScenario
	GetOperatorConditionsFunc GetOperatorConditionsFuncType

	DBLoaderFunc          DBLoaderFuncType
	AssertDBPopulatedFunc func(t testing.TB, errorStore map[string]int, statStore map[string]int)
	AssertMigrationTime   func(t testing.TB, migrationTime time.Duration)
	// DBLoaderWorkers is the number of workers that will execute DBLoaderFunc
	DBLoaderWorkers    int
	EncryptionProvider EncryptionProvider
}

// TestPerfEncryption populates the database, enables encryption, and asserts migration time
// per scenario. At most one scenario may set EncryptionProvider (cluster-wide).
func TestPerfEncryption(ctx context.Context, t testing.TB, scenarios ...PerfScenario) {
	inputs, err := resolvePerfScenarioInputs(scenarios)
	if err != nil {
		t.Fatalf("invalid perf scenarios: %v", err)
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

	// Parallel encryption steps share one provider; wrap Setup so it runs at most once.
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
				endTimeStamps[i] = runTestEncryption(ctx, t, scenarios[i], provider)
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
			e.Error("unable to calculate the migration time, failed to observe when the migration has started")
		}
	}
}

type perfInputs struct {
	provider  EncryptionProvider
	dbLoader  DBLoaderFuncType
	dbAssert  func(t testing.TB, errorStore map[string]int, statStore map[string]int)
	dbWorkers int
}

func resolvePerfScenarioInputs(scenarios []PerfScenario) (perfInputs, error) {
	if len(scenarios) == 0 {
		return perfInputs{}, fmt.Errorf("at least one scenario is required")
	}

	var (
		providers []EncryptionProvider
		loaders   []DBLoaderFuncType
		dbAsserts []func(t testing.TB, errorStore map[string]int, statStore map[string]int)
		workers   int
	)
	var inputs perfInputs
	for _, scenario := range scenarios {
		if scenario.EncryptionProvider.Type != "" {
			providers = append(providers, scenario.EncryptionProvider)
		}
		if (scenario.DBLoaderFunc != nil) != (scenario.AssertDBPopulatedFunc != nil) {
			return perfInputs{}, fmt.Errorf("scenario for %q must set both DBLoaderFunc and AssertDBPopulatedFunc, or neither", scenario.OperatorNamespace)
		}
		if (scenario.GetOperatorConditionsFunc != nil) != (scenario.AssertMigrationTime != nil) {
			return perfInputs{}, fmt.Errorf("scenario for %q must set both GetOperatorConditionsFunc and AssertMigrationTime, or neither", scenario.OperatorNamespace)
		}
		if scenario.DBLoaderFunc != nil {
			loaders = append(loaders, scenario.DBLoaderFunc)
			workers = max(workers, scenario.DBLoaderWorkers)
		}
		if scenario.AssertDBPopulatedFunc != nil {
			dbAsserts = append(dbAsserts, scenario.AssertDBPopulatedFunc)
		}
	}
	if len(providers) > 1 {
		return perfInputs{}, fmt.Errorf("expected at most one EncryptionProvider, got %d", len(providers))
	}
	if len(providers) == 1 {
		inputs.provider = providers[0]
	}
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

func runTestEncryption(ctx context.Context, tt testing.TB, scenario PerfScenario, provider EncryptionProvider) time.Time {
	var ts time.Time
	TestEncryptionType(ctx, tt, BasicScenario{
		Namespace:                       scenario.Namespace,
		LabelSelector:                   scenario.LabelSelector,
		EncryptionConfigSecretName:      scenario.EncryptionConfigSecretName,
		EncryptionConfigSecretNamespace: scenario.EncryptionConfigSecretNamespace,
		OperatorNamespace:               scenario.OperatorNamespace,
		TargetGRs:                       scenario.TargetGRs,
		AssertFunc: func(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
			// Note that AssertFunc is executed after an encryption secret has been annotated
			ts = time.Now()
			scenario.AssertFunc(t, clientSet, expectedMode, scenario.Namespace, scenario.LabelSelector)
			t.Logf("AssertFunc for TestEncryption scenario with %q provider took %v", provider.Type, time.Since(ts))
		},
	}, provider)
	return ts
}

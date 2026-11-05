package encryption

import (
	"context"
	"testing"
	"time"

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

	// APIWorkload optionally measures secret create/get/list latency before and after encryption.
	// Set together with AssertAPIPerformance.
	APIWorkload          *APIWorkloadConfig
	AssertAPIPerformance func(t testing.TB, baseline, encrypted *APIWorkloadResult)
}

func TestPerfEncryption(ctx context.Context, t testing.TB, scenario PerfScenario) {
	if (scenario.APIWorkload != nil) != (scenario.AssertAPIPerformance != nil) {
		t.Fatalf("APIWorkload and AssertAPIPerformance must both be set, or neither")
	}

	e := NewE(t, PrintEventsOnFailure(scenario.OperatorNamespace))
	migrationStartedCh := make(chan time.Time, 1)

	populateDatabase(e, scenario.DBLoaderWorkers, scenario.DBLoaderFunc, scenario.AssertDBPopulatedFunc)

	var baseline *APIWorkloadResult
	if scenario.APIWorkload != nil {
		baseline = RunAPIWorkload(ctx, e, *scenario.APIWorkload)
	}

	watchForMigrationControllerProgressingConditionAsync(e, scenario.GetOperatorConditionsFunc, migrationStartedCh)
	endTimeStamp := runTestEncryption(ctx, t, scenario)

	select {
	case migrationStarted := <-migrationStartedCh:
		scenario.AssertMigrationTime(e, endTimeStamp.Sub(migrationStarted))
	default:
		e.Error("unable to calculate the migration time, failed to observe when the migration has started")
	}

	if scenario.APIWorkload != nil {
		if t.Failed() {
			t.Errorf("skipping the API workload as earlier phases failed")
			return
		}
		encrypted := RunAPIWorkload(ctx, e, *scenario.APIWorkload)
		scenario.AssertAPIPerformance(e, baseline, encrypted)
	}
}

func runTestEncryption(ctx context.Context, tt testing.TB, scenario PerfScenario) time.Time {
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
			t.Logf("AssertFunc for TestEncryption scenario with %q provider took %v", scenario.EncryptionProvider.Type, time.Since(ts))
		},
	}, scenario.EncryptionProvider)
	return ts
}

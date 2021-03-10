package healthmonitor

import (
	"testing"
)

func TestCurrentHealthyTargetsMetrics(t *testing.T) {
	target := newHealthMonitor()
	target.unhealthyProbesThreshold = 1
	target.healthyProbesThreshold = 1
	target.targetsToMonitor = []string{"master-0", "master-1"}
	fakeMetrics := &fakeMetrics{}
	target.metrics = &Metrics{HealthyTargetsTotal: fakeMetrics.HealthyTargetsTotal, UnHealthyTargetsTotal: fakeMetrics.UnHealthyTargetsTotal, CurrentHealthyTargets: fakeMetrics.CurrentHealthyTargets}

	scenarios := []struct {
		name                string
		currentHealthProbes []targetErrTuple

		expectedCurrentlyHealthyTargets int
	}{
		{
			name:                            "round 1: master-0 failed probe",
			currentHealthProbes:             []targetErrTuple{createUnHealthyProbe("master-0")},
			expectedCurrentlyHealthyTargets: 0,
		},

		{
			name:                            "round 2: master-0 failed probe again",
			currentHealthProbes:             []targetErrTuple{createUnHealthyProbe("master-0")},
			expectedCurrentlyHealthyTargets: 0,
		},

		{
			name:                            "round 3: master-0 passed probe",
			currentHealthProbes:             []targetErrTuple{createHealthyProbe("master-0")},
			expectedCurrentlyHealthyTargets: 1,
		},

		{
			name:                            "round 4: master-0 passed probe again",
			currentHealthProbes:             []targetErrTuple{createHealthyProbe("master-0")},
			expectedCurrentlyHealthyTargets: 1,
		},

		{
			name:                            "round 5: master-1 passed probe",
			currentHealthProbes:             []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1")},
			expectedCurrentlyHealthyTargets: 2,
		},

		{
			name:                            "round 6: master-0 and master-1 failed probes",
			currentHealthProbes:             []targetErrTuple{createUnHealthyProbe("master-0"), createUnHealthyProbe("master-1")},
			expectedCurrentlyHealthyTargets: 0,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			target.updateHealthChecksFor(scenario.currentHealthProbes)

			// validate
			if fakeMetrics.currentlyHealthyTargets != scenario.expectedCurrentlyHealthyTargets {
				t.Errorf("incorrect number of currenlty healthy targes recordec by CurrentHealthyTargets method, expected = %v, got %v", scenario.expectedCurrentlyHealthyTargets, fakeMetrics.currentlyHealthyTargets)
			}
		})
	}
}

func TestHealthyUnHealthyCounterMetrics(t *testing.T) {
	target := newHealthMonitor()
	target.unhealthyProbesThreshold = 1
	target.healthyProbesThreshold = 1
	target.targetsToMonitor = []string{"master-0"}

	scenarios := []struct {
		name                string
		currentHealthProbes []targetErrTuple

		expectedRegisteredHealthyTarget   string
		expectedRegisteredUnhealthyTarget string
	}{
		{
			name:                              "round 1: master-0 failed probe",
			currentHealthProbes:               []targetErrTuple{createUnHealthyProbe("master-0")},
			expectedRegisteredUnhealthyTarget: "master-0",
		},

		{
			name:                "round 2: master-0 failed probe again",
			currentHealthProbes: []targetErrTuple{createUnHealthyProbe("master-0")},
		},

		{
			name:                            "round 3: master-0 passed probe",
			currentHealthProbes:             []targetErrTuple{createHealthyProbe("master-0")},
			expectedRegisteredHealthyTarget: "master-0",
		},

		{
			name:                "round 4: master-0 passed probe again",
			currentHealthProbes: []targetErrTuple{createHealthyProbe("master-0")},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			fakeMetrics := &fakeMetrics{}
			target.metrics = &Metrics{HealthyTargetsTotal: fakeMetrics.HealthyTargetsTotal, UnHealthyTargetsTotal: fakeMetrics.UnHealthyTargetsTotal, CurrentHealthyTargets: fakeMetrics.CurrentHealthyTargets}
			target.updateHealthChecksFor(scenario.currentHealthProbes)

			// validate
			if fakeMetrics.totalHealthyTargets != scenario.expectedRegisteredHealthyTarget {
				t.Errorf("incorrect target recorded for HealthyTargetsTotal method, expected = %v, got %v", scenario.expectedRegisteredHealthyTarget, fakeMetrics.totalHealthyTargets)
			}
			if fakeMetrics.totalUnHealthyTargets != scenario.expectedRegisteredUnhealthyTarget {
				t.Errorf("incorrect target recorded for UnHealthyTargetsTotal method, expected = %v, got %v", scenario.expectedRegisteredUnhealthyTarget, fakeMetrics.totalUnHealthyTargets)
			}
		})
	}
}

type fakeMetrics struct {
	totalHealthyTargets     string
	totalUnHealthyTargets   string
	currentlyHealthyTargets int
}

func (f *fakeMetrics) HealthyTargetsTotal(target string) {
	f.totalHealthyTargets = target
}

func (f *fakeMetrics) UnHealthyTargetsTotal(target string) {
	f.totalUnHealthyTargets = target
}

func (f *fakeMetrics) CurrentHealthyTargets(count float64) {
	f.currentlyHealthyTargets = int(count)
}

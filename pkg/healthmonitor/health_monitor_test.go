package healthmonitor

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type fakeTargetProvider []string

func (sp fakeTargetProvider) CurrentTargetsList() []string {
	return sp
}

type fakeHealthyTargetListener struct {
	called bool
}

func (f *fakeHealthyTargetListener) Enqueue() {
	f.called = true
}

func (f *fakeHealthyTargetListener) reset() {
	f.called = false
}

func TestNeverHealthyTargets(t *testing.T) {
	fakeListener := &fakeHealthyTargetListener{}

	target := newHealthMonitor()
	target.AddListener(fakeListener)
	target.unhealthyProbesThreshold = 1
	target.healthyProbesThreshold = 1
	target.targetsToMonitor = []string{"master-0"}

	scenarios := []struct {
		name                string
		currentHealthProbes []targetErrTuple

		expectedHealthyTargets   []string
		expectedUnhealthyTargets []string
		listenerNotified         bool
	}{
		{
			name:                     "round 1: master-0 failed probe",
			currentHealthProbes:      []targetErrTuple{createUnHealthyProbe("master-0")},
			expectedUnhealthyTargets: []string{"master-0"},
			listenerNotified:         true,
		},

		{
			name:                     "round 2: master-0 failed probe again",
			currentHealthProbes:      []targetErrTuple{createUnHealthyProbe("master-0")},
			expectedUnhealthyTargets: []string{"master-0"},
			listenerNotified:         false,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			fakeListener.reset()
			target.updateHealthChecksFor(scenario.currentHealthProbes)
			actualHealthyTargets, actualUnhealthyTargets := target.Targets()

			// validate
			if !cmp.Equal(actualHealthyTargets, scenario.expectedHealthyTargets, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected list of healthy targets = %v, expected = %v", actualHealthyTargets, scenario.expectedHealthyTargets)
			}
			if !cmp.Equal(actualUnhealthyTargets, scenario.expectedUnhealthyTargets, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected list of unhealthy targets = %v, expected = %v", actualUnhealthyTargets, scenario.expectedUnhealthyTargets)
			}
			if fakeListener.called != scenario.listenerNotified {
				t.Errorf("unexpected state of the registered listener, notified = %v, expected notified = %v", fakeListener.called, scenario.listenerNotified)
			}
		})
	}
}

func TestHealthyTargets(t *testing.T) {
	fakeListener := &fakeHealthyTargetListener{}

	target := newHealthMonitor()
	target.AddListener(fakeListener)
	target.unhealthyProbesThreshold = 1
	target.healthyProbesThreshold = 1
	target.targetsToMonitor = []string{"master-0", "master-1", "master-2"}

	scenarios := []struct {
		name                string
		currentHealthProbes []targetErrTuple

		expectedHealthyTargets   []string
		expectedUnhealthyTargets []string
		listenerNotified         bool
	}{
		{
			name: "round 0: works with empty list",
		},

		{
			name:                   "round 1: all servers passed probe, registered listener notified about healthy targets",
			currentHealthProbes:    []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyTargets: []string{"master-0", "master-1", "master-2"},
			listenerNotified:       true,
		},

		{
			name:                     "round 2: master-1 becomes unhealthy, registered listener notified",
			currentHealthProbes:      []targetErrTuple{createHealthyProbe("master-0"), createUnHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyTargets:   []string{"master-0", "master-2"},
			expectedUnhealthyTargets: []string{"master-1"},
			listenerNotified:         true,
		},

		{
			name:                     "round 3: nothing changes, the listener is not notified",
			currentHealthProbes:      []targetErrTuple{createHealthyProbe("master-0"), createUnHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyTargets:   []string{"master-0", "master-2"},
			expectedUnhealthyTargets: []string{"master-1"},
			listenerNotified:         false,
		},

		{
			name:                     "round 4: master-2 becomes unhealthy, registered listener notified",
			currentHealthProbes:      []targetErrTuple{createHealthyProbe("master-0"), createUnHealthyProbe("master-1"), createUnHealthyProbe("master-2")},
			expectedHealthyTargets:   []string{"master-0"},
			expectedUnhealthyTargets: []string{"master-1", "master-2"},
			listenerNotified:         true,
		},

		{
			name:                   "round 5: master-1 and master-2 becomes healthy, registered listener notified",
			currentHealthProbes:    []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyTargets: []string{"master-0", "master-1", "master-2"},
			listenerNotified:       true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			fakeListener.reset()
			target.updateHealthChecksFor(scenario.currentHealthProbes)
			actualHealthyTargets, actualUnhealthyTargets := target.Targets()

			// validate
			if !cmp.Equal(actualHealthyTargets, scenario.expectedHealthyTargets, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected list of healthy targets = %v, expected = %v", actualHealthyTargets, scenario.expectedHealthyTargets)
			}
			if !cmp.Equal(actualUnhealthyTargets, scenario.expectedUnhealthyTargets, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected list of unhealthy targets = %v, expected = %v", actualUnhealthyTargets, scenario.expectedUnhealthyTargets)
			}
			if fakeListener.called != scenario.listenerNotified {
				t.Errorf("unexpected state of the registered listener, notified = %v, expected notified = %v", fakeListener.called, scenario.listenerNotified)
			}
		})
	}
}

func TestInternalStateAfterRefreshingTargets(t *testing.T) {
	monitor := newHealthMonitor()

	scenarios := []struct {
		name                 string
		shouldRefreshTargets bool
		provider             fakeTargetProvider
		currentTargetList    []string

		currentHealthyTargets    []string
		expectedHealthyTargets   []string
		currentUnhealthyTargets  []string
		expectedUnhealthyTargets []string

		currentConsecutiveSuccessfulProbes  map[string]int
		expectedConsecutiveSuccessfulProbes map[string]int
		currentConsecutiveFailedProbes      map[string][]error
		expectedConsecutiveFailedProbes     map[string][]error
	}{
		{
			name:                   "a new target is not immediately added to the list of healthy targets",
			shouldRefreshTargets:   true,
			provider:               fakeTargetProvider{"master-0", "master-1", "master-2", "master-3"},
			currentTargetList:      []string{"master-0", "master-1", "master-2"},
			currentHealthyTargets:  []string{"master-0", "master-1", "master-2"},
			expectedHealthyTargets: []string{"master-0", "master-1", "master-2"},
		},

		{
			name:                                "an old target is immediately removed from the list of healthy targets",
			shouldRefreshTargets:                true,
			provider:                            fakeTargetProvider{"master-0", "master-1", "master-2"},
			currentTargetList:                   []string{"master-0", "master-1", "master-2", "master-3"},
			currentHealthyTargets:               []string{"master-0", "master-1", "master-2", "master-3"},
			expectedHealthyTargets:              []string{"master-0", "master-1", "master-2"},
			currentConsecutiveSuccessfulProbes:  map[string]int{"master-0": 3, "master-1": 3, "master-2": 3, "master-3": 3},
			expectedConsecutiveSuccessfulProbes: map[string]int{"master-0": 3, "master-1": 3, "master-2": 3},
		},

		{
			name:                                "an old target is immediately removed from the list of unhealthy targets",
			shouldRefreshTargets:                true,
			provider:                            fakeTargetProvider{"master-0", "master-1", "master-2"},
			currentTargetList:                   []string{"master-0", "master-1", "master-2", "master-3"},
			currentHealthyTargets:               []string{"master-0", "master-1", "master-2"},
			expectedHealthyTargets:              []string{"master-0", "master-1", "master-2"},
			currentUnhealthyTargets:             []string{"master-3"},
			expectedUnhealthyTargets:            []string{},
			currentConsecutiveFailedProbes:      map[string][]error{"master-3": {errors.New("abc")}},
			expectedConsecutiveFailedProbes:     map[string][]error{},
			currentConsecutiveSuccessfulProbes:  map[string]int{"master-0": 3, "master-1": 3, "master-2": 3},
			expectedConsecutiveSuccessfulProbes: map[string]int{"master-0": 3, "master-1": 3, "master-2": 3},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			monitor.refreshTargets = scenario.shouldRefreshTargets
			monitor.targetProvider = scenario.provider
			monitor.targetsToMonitor = scenario.currentTargetList
			monitor.healthyTargets = scenario.currentHealthyTargets
			monitor.unhealthyTargets = scenario.currentUnhealthyTargets
			monitor.consecutiveSuccessfulProbes = scenario.currentConsecutiveSuccessfulProbes
			monitor.consecutiveFailedProbes = scenario.currentConsecutiveFailedProbes

			// act
			monitor.refreshTargetsLocked()

			// validate
			if !cmp.Equal(monitor.healthyTargets, scenario.expectedHealthyTargets, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected list of healthy targets = %v, expected = %v", monitor.healthyTargets, scenario.expectedHealthyTargets)
			}
			if !cmp.Equal(monitor.unhealthyTargets, scenario.expectedUnhealthyTargets, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected list of unhealthy targets = %v, expected = %v", monitor.unhealthyTargets, scenario.expectedUnhealthyTargets)
			}

			if !cmp.Equal(monitor.consecutiveSuccessfulProbes, scenario.expectedConsecutiveSuccessfulProbes, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected state of consecutiveSuccessfulProbes = %v, expected = %v", monitor.consecutiveSuccessfulProbes, scenario.expectedConsecutiveSuccessfulProbes)
			}
			if !cmp.Equal(monitor.consecutiveFailedProbes, scenario.expectedConsecutiveFailedProbes, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected state of consecutiveFailedProbes = %v, expected = %v", monitor.consecutiveFailedProbes, scenario.expectedConsecutiveFailedProbes)
			}
		})
	}
}

func TestRefreshTargets(t *testing.T) {
	monitor := newHealthMonitor()

	scenarios := []struct {
		name                 string
		shouldRefreshTargets bool
		provider             fakeTargetProvider
		currentTargetList    []string
		expectedTargetList   []string
	}{
		{
			name:               "shouldn't refresh, nothing changes",
			currentTargetList:  []string{"master-0", "master-1", "master-2"},
			expectedTargetList: []string{"master-0", "master-1", "master-2"},
		},

		{
			name:               "new list available but hasn't been scheduled, nothing changes",
			provider:           fakeTargetProvider{"master-0", "master-1", "master-2", "master-3"},
			currentTargetList:  []string{"master-0", "master-1", "master-2"},
			expectedTargetList: []string{"master-0", "master-1", "master-2"},
		},

		{
			name:                 "new list available and scheduled, new target observed",
			shouldRefreshTargets: true,
			provider:             fakeTargetProvider{"master-0", "master-1", "master-2", "master-3"},
			currentTargetList:    []string{"master-0", "master-1", "master-2"},
			expectedTargetList:   []string{"master-0", "master-1", "master-2", "master-3"},
		},

		{
			name:                 "new list available and scheduled, old target removed",
			shouldRefreshTargets: true,
			provider:             fakeTargetProvider{"master-0", "master-1", "master-2"},
			currentTargetList:    []string{"master-0", "master-1", "master-2", "master-3"},
			expectedTargetList:   []string{"master-0", "master-1", "master-2"},
		},

		{
			name:                 "new list available and scheduled, old target removed and new one observed",
			shouldRefreshTargets: true,
			provider:             fakeTargetProvider{"master-0", "master-1", "master-2", "master-4"},
			currentTargetList:    []string{"master-0", "master-1", "master-2", "master-3"},
			expectedTargetList:   []string{"master-0", "master-1", "master-2", "master-4"},
		},

		{
			name:                 "new list available and scheduled, all targets observed",
			shouldRefreshTargets: true,
			provider:             fakeTargetProvider{"master-0", "master-1", "master-2", "master-4"},
			expectedTargetList:   []string{"master-0", "master-1", "master-2", "master-4"},
		},

		{
			name:                 "new list available and scheduled, all targets removed",
			shouldRefreshTargets: true,
			provider:             fakeTargetProvider{},
			currentTargetList:    []string{"master-0", "master-1", "master-2", "master-4"},
			expectedTargetList:   []string{},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			monitor.refreshTargets = scenario.shouldRefreshTargets
			monitor.targetProvider = scenario.provider
			monitor.targetsToMonitor = scenario.currentTargetList

			// act
			monitor.refreshTargetsLocked()

			// validate
			if !cmp.Equal(monitor.targetsToMonitor, scenario.expectedTargetList, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected list of targets = %v, expected = %v", monitor.targetsToMonitor, scenario.expectedTargetList)
			}
		})
	}
}

func TestHealthProbes(t *testing.T) {
	target := newHealthMonitor()
	target.targetsToMonitor = []string{"master-0", "master-1", "master-2"}

	scenarios := []struct {
		name                     string
		currentHealthProbes      []targetErrTuple
		expectedHealthyServers   []string
		expectedUnhealthyServers []string
	}{
		{
			name:                "round 1: all servers passed probe",
			currentHealthProbes: []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1"), createHealthyProbe("master-2")},
		},

		{
			name:                "round 2: all servers passed probe",
			currentHealthProbes: []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1"), createHealthyProbe("master-2")},
		},

		{
			name:                   "round 3: all servers became healthy",
			currentHealthProbes:    []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyServers: []string{"master-0", "master-1", "master-2"},
		},

		{
			name:                   "round 4: all servers passed probe, nothing has changed",
			currentHealthProbes:    []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyServers: []string{"master-0", "master-1", "master-2"},
		},

		{
			name:                   "round 5: master-1 failed probe",
			currentHealthProbes:    []targetErrTuple{createHealthyProbe("master-0"), createUnHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyServers: []string{"master-0", "master-1", "master-2"},
		},

		{
			name:                     "round 6: master-1 became unhealthy",
			currentHealthProbes:      []targetErrTuple{createHealthyProbe("master-0"), createUnHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyServers:   []string{"master-0", "master-2"},
			expectedUnhealthyServers: []string{"master-1"},
		},

		{
			name:                     "round 7: master-1 passed probe",
			currentHealthProbes:      []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyServers:   []string{"master-0", "master-2"},
			expectedUnhealthyServers: []string{"master-1"},
		},

		{
			name:                     "round 8: master-1 passed probe",
			currentHealthProbes:      []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyServers:   []string{"master-0", "master-2"},
			expectedUnhealthyServers: []string{"master-1"},
		},

		{
			name:                   "round 9: master-1 became healthy",
			currentHealthProbes:    []targetErrTuple{createHealthyProbe("master-0"), createHealthyProbe("master-1"), createHealthyProbe("master-2")},
			expectedHealthyServers: []string{"master-0", "master-1", "master-2"},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			target.updateHealthChecksFor(scenario.currentHealthProbes)

			// validate
			if !cmp.Equal(target.healthyTargets, scenario.expectedHealthyServers, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected list of healthy servers = %v, expected = %v", target.healthyTargets, scenario.expectedHealthyServers)
			}
			if !cmp.Equal(target.unhealthyTargets, scenario.expectedUnhealthyServers, cmpopts.EquateEmpty()) {
				t.Errorf("unexpected list of unhealthy servers = %v, expected = %v", target.unhealthyTargets, scenario.expectedUnhealthyServers)
			}
		})
	}
}

func newHealthMonitor() *HealthMonitor {
	hm := &HealthMonitor{
		unhealthyProbesThreshold: 2,
		healthyProbesThreshold:   3,

		consecutiveSuccessfulProbes: map[string]int{},
		consecutiveFailedProbes:     map[string][]error{},

		metrics: &Metrics{
			HealthyTargetsTotal:   noopMetrics{}.TargetsTotal,
			UnHealthyTargetsTotal: noopMetrics{}.TargetsTotal,
		},
	}
	hm.exportedHealthyTargets.Store([]string{})
	hm.exportedUnhealthyTargets.Store([]string{})

	return hm
}

func createHealthyProbe(server string) targetErrTuple {
	return targetErrTuple{server, nil}
}

func createUnHealthyProbe(server string) targetErrTuple {
	return targetErrTuple{server, errors.New("random error")}
}

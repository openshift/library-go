package featuregates

import (
	"context"
	clocktesting "k8s.io/utils/clock/testing"
	"reflect"
	"sync"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type testFeatureGateBuilder struct {
	versionToFeatures map[string]Features
}

func featureGateBuilder() *testFeatureGateBuilder {
	return &testFeatureGateBuilder{
		versionToFeatures: map[string]Features{},
	}
}

func (f *testFeatureGateBuilder) enabled(version string, enabled ...string) *testFeatureGateBuilder {
	curr := f.versionToFeatures[version]
	curr.Enabled = StringsToFeatureGateNames(enabled)
	f.versionToFeatures[version] = curr

	return f
}

func (f *testFeatureGateBuilder) disabled(version string, disabled ...string) *testFeatureGateBuilder {
	curr := f.versionToFeatures[version]
	curr.Disabled = StringsToFeatureGateNames(disabled)
	f.versionToFeatures[version] = curr

	return f
}

func (f *testFeatureGateBuilder) toFeatureGate() *configv1.FeatureGate {
	ret := &configv1.FeatureGate{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
	}
	for version, features := range f.versionToFeatures {
		details := configv1.FeatureGateDetails{
			Version: version,
		}
		for _, curr := range features.Enabled {
			details.Enabled = append(details.Enabled, configv1.FeatureGateAttributes{Name: curr})
		}
		for _, curr := range features.Disabled {
			details.Disabled = append(details.Disabled, configv1.FeatureGateAttributes{Name: curr})
		}
		ret.Status.FeatureGates = append(ret.Status.FeatureGates, details)
	}

	return ret
}

type featureChangeTracker struct {
	history []FeatureChange
}

func (f *featureChangeTracker) change(featureChange FeatureChange) {
	f.history = append(f.history, featureChange)
}

func Test_defaultFeatureGateAccess_syncHandler(t *testing.T) {
	closedCh := make(chan struct{})
	close(closedCh)

	type fields struct {
		desiredVersion              string
		missingVersionMarker        string
		initialFeatureGatesObserved chan struct{}
		initialFeatures             Features
		currentFeatures             Features
	}
	tests := []struct {
		name              string
		firstFeatureGate  *configv1.FeatureGate
		secondFeatureGate *configv1.FeatureGate
		clusterVersion    string

		fields fields

		changeVerifier func(t *testing.T, history []FeatureChange)
		wantErr        bool
	}{
		{
			name: "read-explicit-version",

			firstFeatureGate: featureGateBuilder().
				enabled("desired-version", "alpha", "bravo").
				disabled("desired-version", "charlie", "delta").
				toFeatureGate(),
			fields: fields{
				desiredVersion: "desired-version",
			},

			changeVerifier: func(t *testing.T, history []FeatureChange) {
				if len(history) != 1 {
					t.Fatalf("bad changes: %v", history)
				}
				if history[0].Previous != nil {
					t.Fatalf("bad changes: %v", history)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"alpha", "bravo"}, history[0].New.Enabled) {
					t.Fatal(history[0].New.Enabled)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"charlie", "delta"}, history[0].New.Disabled) {
					t.Fatal(history[0].New.Enabled)
				}
			},
		},
		{
			name: "read-explicit-version-from-others",

			firstFeatureGate: featureGateBuilder().
				enabled("desired-version", "alpha", "bravo").
				disabled("desired-version", "charlie", "delta").
				enabled("other-version", "yankee", "zulu").
				toFeatureGate(),
			fields: fields{
				desiredVersion: "desired-version",
			},

			changeVerifier: func(t *testing.T, history []FeatureChange) {
				if len(history) != 1 {
					t.Fatalf("bad changes: %v", history)
				}
				if history[0].Previous != nil {
					t.Fatalf("bad changes: %v", history)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"alpha", "bravo"}, history[0].New.Enabled) {
					t.Fatal(history[0].New.Enabled)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"charlie", "delta"}, history[0].New.Disabled) {
					t.Fatal(history[0].New.Enabled)
				}
			},
		},
		{
			name: "no-change-means-no-extra-watch-call",

			firstFeatureGate: featureGateBuilder().
				enabled("desired-version", "alpha", "bravo").
				disabled("desired-version", "charlie", "delta").
				toFeatureGate(),
			secondFeatureGate: featureGateBuilder().
				enabled("desired-version", "alpha", "bravo").
				disabled("desired-version", "charlie", "delta").
				toFeatureGate(),
			fields: fields{
				desiredVersion: "desired-version",
			},

			changeVerifier: func(t *testing.T, history []FeatureChange) {
				if len(history) != 1 {
					t.Fatalf("bad changes: %v", history)
				}
				if history[0].Previous != nil {
					t.Fatalf("bad changes: %v", history)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"alpha", "bravo"}, history[0].New.Enabled) {
					t.Fatal(history[0].New.Enabled)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"charlie", "delta"}, history[0].New.Disabled) {
					t.Fatal(history[0].New.Enabled)
				}
			},
		},
		{
			name: "change-means-watch-call",

			firstFeatureGate: featureGateBuilder().
				enabled("desired-version", "alpha", "bravo").
				disabled("desired-version", "charlie", "delta").
				toFeatureGate(),
			secondFeatureGate: featureGateBuilder().
				enabled("desired-version", "alpha", "bravo", "charlie", "delta").
				toFeatureGate(),
			fields: fields{
				desiredVersion: "desired-version",
			},

			changeVerifier: func(t *testing.T, history []FeatureChange) {
				if len(history) != 2 {
					t.Fatalf("bad changes: %v", history)
				}
				if history[0].Previous != nil {
					t.Fatalf("bad changes: %v", history)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"alpha", "bravo"}, history[0].New.Enabled) {
					t.Fatal(history[0].New.Enabled)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"charlie", "delta"}, history[0].New.Disabled) {
					t.Fatal(history[0].New.Enabled)
				}
				if !reflect.DeepEqual(*(history[1].Previous), history[0].New) {
					t.Fatalf("bad changes: %v", history)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"alpha", "bravo", "charlie", "delta"}, history[1].New.Enabled) {
					t.Fatal(history[1].New.Enabled)
				}
				if len(history[1].New.Disabled) != 0 {
					t.Fatal(history[1].New.Disabled)
				}
			},
		},
		{
			name: "missing-version-means-use-cluster-version",

			firstFeatureGate: featureGateBuilder().
				enabled("other-version", "alpha", "bravo").
				disabled("other-version", "charlie", "delta").
				toFeatureGate(),
			fields: fields{
				desiredVersion:       "missing-version",
				missingVersionMarker: "missing-version",
			},
			clusterVersion: "other-version",

			changeVerifier: func(t *testing.T, history []FeatureChange) {
				if len(history) != 1 {
					t.Fatalf("bad changes: %v", history)
				}
				if history[0].Previous != nil {
					t.Fatalf("bad changes: %v", history)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"alpha", "bravo"}, history[0].New.Enabled) {
					t.Fatal(history[0].New.Enabled)
				}
				if !reflect.DeepEqual([]configv1.FeatureGateName{"charlie", "delta"}, history[0].New.Disabled) {
					t.Fatal(history[0].New.Enabled)
				}
			},
		},
		{
			name: "missing desiredVersion",

			firstFeatureGate: featureGateBuilder().
				enabled("other-version", "alpha", "bravo").
				disabled("other-version", "charlie", "delta").
				toFeatureGate(),
			fields: fields{
				desiredVersion: "desired-version",
			},

			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, cancel := context.WithCancel(ctx)
			defer cancel()

			featureGateIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			featureGateLister := configlistersv1.NewFeatureGateLister(featureGateIndexer)
			if tt.firstFeatureGate != nil {
				featureGateIndexer.Add(tt.firstFeatureGate)
			}

			var clusterVersionLister configlistersv1.ClusterVersionLister
			if len(tt.clusterVersion) > 0 {
				indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				indexer.Add(&configv1.ClusterVersion{
					ObjectMeta: metav1.ObjectMeta{Name: "version"},
					Status: configv1.ClusterVersionStatus{
						History: []configv1.UpdateHistory{
							{Version: tt.clusterVersion},
						},
					},
				})
				clusterVersionLister = configlistersv1.NewClusterVersionLister(indexer)
			}

			changeTracker := &featureChangeTracker{}

			initialFeatureGatesObserved := tt.fields.initialFeatureGatesObserved
			if tt.fields.initialFeatureGatesObserved == nil {
				initialFeatureGatesObserved = make(chan struct{})
			}
			c := &defaultFeatureGateAccess{
				desiredVersion:              tt.fields.desiredVersion,
				missingVersionMarker:        tt.fields.missingVersionMarker,
				clusterVersionLister:        clusterVersionLister,
				featureGateLister:           featureGateLister,
				featureGateChangeHandlerFn:  changeTracker.change,
				initialFeatureGatesObserved: initialFeatureGatesObserved,
				lock:                        sync.Mutex{},
				started:                     true,
				initialFeatures:             tt.fields.initialFeatures,
				currentFeatures:             tt.fields.currentFeatures,
				eventRecorder:               events.NewInMemoryRecorder("fakee", clocktesting.NewFakePassiveClock(time.Now())),
			}

			if c.AreInitialFeatureGatesObserved() {
				t.Fatal("have seen initial)")
			}

			err := c.syncHandler(ctx)
			switch {
			case err != nil && tt.wantErr:
				return
			case err == nil && !tt.wantErr:
			default:
				t.Errorf("syncHandler() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !c.AreInitialFeatureGatesObserved() {
				t.Fatal("haven't seen initial)")
			}

			if tt.secondFeatureGate != nil {
				if err := featureGateIndexer.Update(tt.secondFeatureGate); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.syncHandler(ctx); (err != nil) != tt.wantErr {
				t.Errorf("syncHandler() error = %v, wantErr %v", err, tt.wantErr)
			}

			tt.changeVerifier(t, changeTracker.history)
		})
	}
}

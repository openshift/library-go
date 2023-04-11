package featuregates

import (
	"context"
	"reflect"
	"sync"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type testFeatureGateBuilder struct {
	featureSetName    string
	versionToFeatures map[string]Features
}

func featureGateBuilder() *testFeatureGateBuilder {
	return &testFeatureGateBuilder{
		versionToFeatures: map[string]Features{},
	}
}

func (f *testFeatureGateBuilder) specFeatureSet(featureSetName string) *testFeatureGateBuilder {
	f.featureSetName = featureSetName

	return f
}

func (f *testFeatureGateBuilder) enabled(version string, enabled ...string) *testFeatureGateBuilder {
	curr := f.versionToFeatures[version]
	curr.Enabled = enabled
	f.versionToFeatures[version] = curr

	return f
}

func (f *testFeatureGateBuilder) disabled(version string, disabled ...string) *testFeatureGateBuilder {
	curr := f.versionToFeatures[version]
	curr.Disabled = disabled
	f.versionToFeatures[version] = curr

	return f
}

func (f *testFeatureGateBuilder) toFeatureGate() *configv1.FeatureGate {
	ret := &configv1.FeatureGate{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.FeatureGateSpec{
			FeatureGateSelection: configv1.FeatureGateSelection{
				FeatureSet: configv1.FeatureSet(f.featureSetName),
			},
		},
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
				specFeatureSet("features-for-desired-version").
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
				if !reflect.DeepEqual([]string{"alpha", "bravo"}, history[0].New.Enabled) {
					t.Fatal(history[0].New.Enabled)
				}
				if !reflect.DeepEqual([]string{"charlie", "delta"}, history[0].New.Disabled) {
					t.Fatal(history[0].New.Enabled)
				}
			},
		},
		{
			name: "read-explicit-version-from-others",

			firstFeatureGate: featureGateBuilder().
				specFeatureSet("features-for-desired-version").
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
				if !reflect.DeepEqual([]string{"alpha", "bravo"}, history[0].New.Enabled) {
					t.Fatal(history[0].New.Enabled)
				}
				if !reflect.DeepEqual([]string{"charlie", "delta"}, history[0].New.Disabled) {
					t.Fatal(history[0].New.Enabled)
				}
			},
		},
		{
			name: "no-change-means-no-extra-watch-call",

			firstFeatureGate: featureGateBuilder().
				specFeatureSet("features-for-desired-version").
				enabled("desired-version", "alpha", "bravo").
				disabled("desired-version", "charlie", "delta").
				toFeatureGate(),
			secondFeatureGate: featureGateBuilder().
				specFeatureSet("features-for-desired-version").
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
				if !reflect.DeepEqual([]string{"alpha", "bravo"}, history[0].New.Enabled) {
					t.Fatal(history[0].New.Enabled)
				}
				if !reflect.DeepEqual([]string{"charlie", "delta"}, history[0].New.Disabled) {
					t.Fatal(history[0].New.Enabled)
				}
			},
		},
		{
			name: "missing desiredVersion",

			firstFeatureGate: featureGateBuilder().
				specFeatureSet("features-for-missing-version").
				enabled("other-version", "alpha", "bravo").
				disabled("other-version", "charlie", "delta").
				toFeatureGate(),
			fields: fields{
				desiredVersion: "missing-version",
			},

			wantErr: true,
		},
	}

	// set the map.  This is very  ugly, but will hopefully be replaced by https://github.com/openshift/library-go/pull/1468/files shortly
	configv1.FeatureSets["features-for-desired-version"] = &configv1.FeatureGateEnabledDisabled{
		Enabled:  []string{"alpha", "bravo"},
		Disabled: []string{"charlie", "delta"},
	}
	configv1.FeatureSets["features-for-other-version"] = &configv1.FeatureGateEnabledDisabled{
		Enabled:  []string{"alpha", "bravo"},
		Disabled: []string{"charlie", "delta"},
	}
	defer func() {
		delete(configv1.FeatureSets, "features-for-desired-version")
	}()

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
				eventRecorder:               events.NewInMemoryRecorder("fakee"),
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

package state

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

func TestMigratedFor(t *testing.T) {
	secrets := schema.GroupResource{Group: "", Resource: "secrets"}
	configmaps := schema.GroupResource{Group: "", Resource: "configmaps"}

	tests := []struct {
		name                 string
		grs                  []schema.GroupResource
		keyState             KeyState
		wantOK               bool
		wantMissing          []schema.GroupResource
		wantNeedsRemigration bool
	}{
		{
			name: "all resources migrated, no generation",
			grs:  []schema.GroupResource{secrets, configmaps},
			keyState: KeyState{
				Key:      apiserverconfigv1.Key{Name: "1"},
				Migrated: MigrationState{Resources: []schema.GroupResource{secrets, configmaps}},
			},
			wantOK:               true,
			wantNeedsRemigration: false,
		},
		{
			name: "missing resource",
			grs:  []schema.GroupResource{secrets, configmaps},
			keyState: KeyState{
				Key:      apiserverconfigv1.Key{Name: "1"},
				Migrated: MigrationState{Resources: []schema.GroupResource{secrets}},
			},
			wantOK:               false,
			wantMissing:          []schema.GroupResource{configmaps},
			wantNeedsRemigration: false,
		},
		{
			name: "all migrated, generation matches — no remigration",
			grs:  []schema.GroupResource{secrets},
			keyState: KeyState{
				Key:                 apiserverconfigv1.Key{Name: "1"},
				Migrated:            MigrationState{Resources: []schema.GroupResource{secrets}, Generation: 2},
				MigrationGeneration: 2,
			},
			wantOK:               true,
			wantNeedsRemigration: false,
		},
		{
			name: "all migrated, generation mismatch — needs remigration",
			grs:  []schema.GroupResource{secrets},
			keyState: KeyState{
				Key:                 apiserverconfigv1.Key{Name: "1"},
				Migrated:            MigrationState{Resources: []schema.GroupResource{secrets}, Generation: 1},
				MigrationGeneration: 2,
			},
			wantOK:               true,
			wantNeedsRemigration: true,
		},
		{
			name: "all migrated, first generation bump — needs remigration",
			grs:  []schema.GroupResource{secrets, configmaps},
			keyState: KeyState{
				Key:                 apiserverconfigv1.Key{Name: "5"},
				Migrated:            MigrationState{Resources: []schema.GroupResource{secrets, configmaps}, Generation: 0},
				MigrationGeneration: 1,
			},
			wantOK:               true,
			wantNeedsRemigration: true,
		},
		{
			name: "missing resources takes precedence over generation mismatch",
			grs:  []schema.GroupResource{secrets, configmaps},
			keyState: KeyState{
				Key:                 apiserverconfigv1.Key{Name: "1"},
				Migrated:            MigrationState{Resources: []schema.GroupResource{secrets}, Generation: 1},
				MigrationGeneration: 2,
			},
			wantOK:               false,
			wantMissing:          []schema.GroupResource{configmaps},
			wantNeedsRemigration: false,
		},
		{
			name: "no resources to check",
			grs:  []schema.GroupResource{},
			keyState: KeyState{
				Key: apiserverconfigv1.Key{Name: "1"},
			},
			wantOK:               true,
			wantNeedsRemigration: false,
		},
		{
			name: "zero generations — backward compatible",
			grs:  []schema.GroupResource{secrets},
			keyState: KeyState{
				Key:                 apiserverconfigv1.Key{Name: "1"},
				Migrated:            MigrationState{Resources: []schema.GroupResource{secrets}, Generation: 0},
				MigrationGeneration: 0,
			},
			wantOK:               true,
			wantNeedsRemigration: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, missing, needsRemigration, _ := MigratedFor(tt.grs, tt.keyState)
			if ok != tt.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tt.wantOK)
			}
			if needsRemigration != tt.wantNeedsRemigration {
				t.Errorf("needsRemigration: got %v, want %v", needsRemigration, tt.wantNeedsRemigration)
			}
			if len(missing) != len(tt.wantMissing) {
				t.Errorf("missing: got %v, want %v", missing, tt.wantMissing)
			}
		})
	}
}

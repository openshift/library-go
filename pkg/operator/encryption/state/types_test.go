package state

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestKMSReferenceDataSet(t *testing.T) {
	tests := []struct {
		name       string
		secretName string
		dataKey    string
		value      []byte
		wantErr    bool
		expected   KMSReferenceData
	}{
		{
			name:       "valid set",
			secretName: "vault-approle-secret",
			dataKey:    "role-id",
			value:      []byte("test-role-id"),
			expected: KMSReferenceData{entries: map[string]map[string][]byte{
				"vault-approle-secret": {"role-id": []byte("test-role-id")},
			}},
		},
		{
			name:       "secret name with underscore returns error",
			secretName: "vault_approle_secret",
			dataKey:    "role-id",
			value:      []byte("test-role-id"),
			wantErr:    true,
		},
		{
			name:       "secret name with trailing underscore returns error",
			secretName: "vault-approle-secret_",
			dataKey:    "role-id",
			value:      []byte("test-role-id"),
			wantErr:    true,
		},
		{
			name:       "secret name with leading underscore returns error",
			secretName: "_vault-approle-secret",
			dataKey:    "role-id",
			value:      []byte("test-role-id"),
			wantErr:    true,
		},
		{
			name:    "empty secret name returns error",
			dataKey: "role-id",
			value:   []byte("test-role-id"),
			wantErr: true,
		},
		{
			name:       "empty data key returns error",
			secretName: "vault-approle-secret",
			value:      []byte("test-role-id"),
			wantErr:    true,
		},
		{
			name:       "empty value returns error",
			secretName: "vault-approle-secret",
			dataKey:    "role-id",
			value:      []byte{},
			wantErr:    true,
		},
		{
			name:       "nil value returns error",
			secretName: "vault-approle-secret",
			dataKey:    "role-id",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d KMSReferenceData
			err := d.Set(tt.secretName, tt.dataKey, tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.expected, d, cmp.AllowUnexported(KMSReferenceData{})); diff != "" {
				t.Errorf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestKMSReferenceDataSetFromRawKey(t *testing.T) {
	tests := []struct {
		name     string
		rawKey   string
		value    []byte
		wantErr  bool
		expected KMSReferenceData
	}{
		{
			name:   "valid raw key",
			rawKey: "vault-approle-secret_role-id",
			value:  []byte("test-role-id"),
			expected: KMSReferenceData{entries: map[string]map[string][]byte{
				"vault-approle-secret": {"role-id": []byte("test-role-id")},
			}},
		},
		{
			name:    "missing separator returns error",
			rawKey:  "no-separator-here",
			value:   []byte("v"),
			wantErr: true,
		},
		{
			name:   "multiple underscores splits on first only",
			rawKey: "vault_approle_secret_role-id",
			value:  []byte("v"),
			expected: KMSReferenceData{entries: map[string]map[string][]byte{
				"vault": {"approle_secret_role-id": []byte("v")},
			}},
		},
		{
			name:    "empty raw key returns error",
			rawKey:  "",
			value:   []byte("v"),
			wantErr: true,
		},
		{
			name:    "empty value returns error",
			rawKey:  "vault-approle-secret_role-id",
			value:   []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d KMSReferenceData
			err := d.SetFromRawKey(tt.rawKey, tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.expected, d, cmp.AllowUnexported(KMSReferenceData{})); diff != "" {
				t.Errorf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestKMSReferenceDataFlatEntries(t *testing.T) {
	d := KMSReferenceData{entries: map[string]map[string][]byte{
		"vault-approle-secret": {
			"role-id":   []byte("test-role-id"),
			"secret-id": []byte("test-secret-id"),
		},
	}}

	expected := map[string][]byte{
		"vault-approle-secret_role-id":   []byte("test-role-id"),
		"vault-approle-secret_secret-id": []byte("test-secret-id"),
	}

	if diff := cmp.Diff(expected, d.FlatEntries(), cmp.AllowUnexported(KMSReferenceData{})); diff != "" {
		t.Errorf("unexpected result (-want +got):\n%s", diff)
	}

	// zero value returns nil
	var empty KMSReferenceData
	if empty.FlatEntries() != nil {
		t.Errorf("expected nil, got %v", empty.FlatEntries())
	}
}

package kms

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
)

// MigrationFieldsChanged returns true if any field that affects the KEK has changed
// between stored and current KMSConfig, meaning a new encryption key and data
// re-encryption are required.
// A provider type change always triggers migration.
func MigrationFieldsChanged(stored, current *configv1.KMSConfig) bool {
	if stored == nil || current == nil {
		return stored != current
	}

	if stored.Type != current.Type {
		return true
	}

	switch current.Type {
	case configv1.VaultKMSProvider:
		return vaultMigrationFieldsChanged(stored.Vault, current.Vault)
	default:
		return false
	}
}

func vaultMigrationFieldsChanged(stored, current *configv1.VaultKMSConfig) bool {
	if stored == nil || current == nil {
		return stored != current
	}
	return stored.VaultAddress != current.VaultAddress ||
		stored.VaultNamespace != current.VaultNamespace ||
		stored.TransitKey != current.TransitKey ||
		stored.TransitMount != current.TransitMount
}

// ApplyInPlaceFields returns a copy of stored with only in-place fields
// (fields that do not affect the KEK) updated from current.
// Migration-triggering fields are preserved from stored.
func ApplyInPlaceFields(stored, current *configv1.KMSConfig) (*configv1.KMSConfig, error) {
	if stored == nil || current == nil {
		return nil, fmt.Errorf("stored and current KMSConfig must not be nil")
	}

	result := stored.DeepCopy()
	switch current.Type {
	case configv1.VaultKMSProvider:
		if result.Vault != nil && current.Vault != nil {
			result.Vault.Image = current.Vault.Image
			result.Vault.TLSCA = current.Vault.TLSCA
			result.Vault.TLSServerName = current.Vault.TLSServerName
			result.Vault.ApproleSecretRef = current.Vault.ApproleSecretRef
		}
	}
	return result, nil
}

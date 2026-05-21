package encryptionstatus

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
)

func parseMigratedResources(secret *corev1.Secret) ([]schema.GroupResource, error) {
	if secret == nil || secret.Annotations == nil {
		return nil, nil
	}
	raw, ok := secret.Annotations[secrets.EncryptionSecretMigratedResources]
	if !ok || len(raw) == 0 {
		return nil, nil
	}
	migrated := secrets.MigratedGroupResources{}
	if err := json.Unmarshal([]byte(raw), &migrated); err != nil {
		return nil, fmt.Errorf("invalid %s annotation: %w", secrets.EncryptionSecretMigratedResources, err)
	}
	return migrated.Resources, nil
}

// AllEncryptedGRsMigrated returns true when every encrypted GR is listed in migrated-resources.
func AllEncryptedGRsMigrated(secret *corev1.Secret, encryptedGRs []schema.GroupResource) (bool, error) {
	migrated, err := parseMigratedResources(secret)
	if err != nil {
		return false, err
	}
	for _, gr := range encryptedGRs {
		found := false
		for _, migratedGR := range migrated {
			if migratedGR == gr {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return len(encryptedGRs) > 0, nil
}

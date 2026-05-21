package encryptionstatus

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
)

func TestAllEncryptedGRsMigrated(t *testing.T) {
	grs := []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}
	migrated := secrets.MigratedGroupResources{Resources: grs}
	raw, err := json.Marshal(migrated)
	if err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{}
	secret.Annotations = map[string]string{
		secrets.EncryptionSecretMigratedResources: string(raw),
	}
	ok, err := AllEncryptedGRsMigrated(secret, grs)
	if err != nil || !ok {
		t.Fatalf("expected all migrated, ok=%v err=%v", ok, err)
	}

	partial := secrets.MigratedGroupResources{Resources: grs[:1]}
	raw, _ = json.Marshal(partial)
	secret.Annotations[secrets.EncryptionSecretMigratedResources] = string(raw)
	ok, err = AllEncryptedGRsMigrated(secret, grs)
	if err != nil || ok {
		t.Fatalf("expected partial migration, ok=%v err=%v", ok, err)
	}
}

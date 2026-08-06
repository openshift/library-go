package controllers

import (
	"context"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func TestBuildEncryptionKeyStateMissingRefs(t *testing.T) {
	apiServerEncryption := configv1.APIServerEncryption{
		Type: configv1.EncryptionTypeKMS,
		KMS: configv1.KMSPluginConfig{
			Type:  configv1.VaultKMSProvider,
			Vault: wellKnownBaseVaultConfig,
		},
	}
	providerCfg, err := newKMSProviderConfig(apiServerEncryption.KMS)
	if err != nil {
		t.Fatalf("failed to create provider config: %v", err)
	}

	t.Run("missing referenced secret", func(t *testing.T) {
		client := fake.NewSimpleClientset(&wellKnownBaseConfigMap)
		_, err := buildEncryptionKeyState(
			context.TODO(),
			1,
			state.KMS,
			apiServerEncryption,
			providerCfg,
			client.CoreV1(),
			client.CoreV1(),
			"test-reason",
			"",
			"",
		)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "vault-approle") {
			t.Fatalf("expected error mentioning the missing secret, got: %v", err)
		}
	})

	t.Run("missing referenced configmap", func(t *testing.T) {
		client := fake.NewSimpleClientset(&wellKnownBaseSecret)
		_, err := buildEncryptionKeyState(
			context.TODO(),
			1,
			state.KMS,
			apiServerEncryption,
			providerCfg,
			client.CoreV1(),
			client.CoreV1(),
			"test-reason",
			"",
			"",
		)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "vault-ca-bundle") {
			t.Fatalf("expected error mentioning the missing configmap, got: %v", err)
		}
	})

	t.Run("returns fetched refs for hasher reuse", func(t *testing.T) {
		client := fake.NewSimpleClientset([]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap}...)
		result, err := buildEncryptionKeyState(
			context.TODO(),
			1,
			state.KMS,
			apiServerEncryption,
			providerCfg,
			client.CoreV1(),
			client.CoreV1(),
			"test-reason",
			"",
			"unix:///var/run/kmsplugin/kms.sock",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.refSecret == nil || result.refSecret.Name != "vault-approle" {
			t.Fatalf("expected refSecret vault-approle, got %+v", result.refSecret)
		}
		if result.refCM == nil || result.refCM.Name != "vault-ca-bundle" {
			t.Fatalf("expected refCM vault-ca-bundle, got %+v", result.refCM)
		}
		if result.keyState.KMS == nil || result.keyState.KMS.Encryption.Endpoint != "unix:///var/run/kmsplugin/kms.sock" {
			t.Fatalf("expected endpoint override, got %+v", result.keyState.KMS)
		}
	})
}

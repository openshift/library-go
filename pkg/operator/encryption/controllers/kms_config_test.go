package controllers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestResolveKMSConfig(t *testing.T) {
	expected := encryptiontesting.DefaultKMSPluginConfig
	expected.Vault.VaultNamespace = "tenant"
	expected.Vault.VaultAuthNamespace = "auth-tenant"
	expected.Vault.TLS.ServerName = "vault.example.com"
	obj := vaultPluginConfig(t, expected)
	obj.SetName("custom-config")
	obj.SetAnnotations(map[string]string{"note": "ignored"})
	require.NoError(t, unstructured.SetNestedField(obj.Object, "ignored", "status", "futureField"))
	require.NoError(t, unstructured.SetNestedField(obj.Object, "wrong-image", "spec", "kmsPluginImage"))
	before := obj.DeepCopy()
	ref := defaultKMSConfigReference
	ref.PluginConfig.Name = obj.GetName()
	// The reference controls the lookup; the internal GVK is independent of the CR GVK.
	ref.PluginConfig.APIVersion = "example.test/v1"
	ref.PluginConfig.Resource = "pluginconfigs"
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	client.PrependReactor("get", "pluginconfigs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		require.Equal(t, schema.GroupVersionResource{Group: "example.test", Version: "v1", Resource: "pluginconfigs"}, action.GetResource())
		require.Empty(t, action.GetNamespace())
		require.Equal(t, "custom-config", action.(k8stesting.GetAction).GetName())
		return true, obj, nil
	})
	actual, err := ResolveKMSConfig(context.Background(), client, ref)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, before, obj)
	require.Len(t, client.Actions(), 1)
	encoded, err := encoding.EncodeKMSPluginConfig(actual)
	require.NoError(t, err)
	decoded, err := encoding.DecodeKMSPluginConfig(encoded)
	require.NoError(t, err)
	require.Equal(t, actual, decoded)
	actual.Vault.VaultAddress = "changed"
	require.Equal(t, before, obj)
}

func TestResolveKMSConfigErrors(t *testing.T) {
	ref := defaultKMSConfigReference
	_, err := ResolveKMSConfig(context.Background(), nil, ref)
	require.ErrorContains(t, err, "dynamic client is required")
	invalid := ref
	invalid.PluginConfig.APIVersion = "invalid/group/version"
	_, err = ResolveKMSConfig(context.Background(), newKMSDynamicClient(t), invalid)
	require.ErrorContains(t, err, "invalid KMS plugin configuration apiVersion")
	sentinel := errors.New("get failed")
	client := newKMSDynamicClient(t)
	client.PrependReactor("get", "vaultkmsconfigs", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, sentinel })
	_, err = ResolveKMSConfig(context.Background(), client, ref)
	require.ErrorIs(t, err, sentinel)
	for _, gvk := range []schema.GroupVersionKind{
		{Group: "other.test", Version: "v1alpha1", Kind: "VaultKMSConfig"},
		{Group: "kms.openshift.io", Version: "v2", Kind: "VaultKMSConfig"},
		{Group: "kms.openshift.io", Version: "v1alpha1", Kind: "UnknownConfig"},
	} {
		obj := vaultPluginConfig(t, encryptiontesting.DefaultKMSPluginConfig)
		obj.SetGroupVersionKind(gvk)
		client := newKMSDynamicClient(t)
		client.PrependReactor("get", "vaultkmsconfigs", func(k8stesting.Action) (bool, runtime.Object, error) { return true, obj, nil })
		_, err = ResolveKMSConfig(context.Background(), client, ref)
		require.ErrorContains(t, err, "unsupported KMS plugin configuration kind")
	}
	for _, obj := range []*unstructured.Unstructured{nil, {}} {
		client := newKMSDynamicClient(t)
		client.PrependReactor("get", "vaultkmsconfigs", func(k8stesting.Action) (bool, runtime.Object, error) {
			if obj == nil {
				return true, nil, nil
			}
			return true, obj, nil
		})
		_, err := ResolveKMSConfig(context.Background(), client, ref)
		require.ErrorContains(t, err, "must not be nil or empty")
	}
	for _, path := range [][]string{{"spec"}, {"spec", "vaultAddress"}, {"status"}, {"status", "kmsPluginImage"}} {
		t.Run(path[len(path)-1], func(t *testing.T) {
			obj := vaultPluginConfig(t, encryptiontesting.DefaultKMSPluginConfig)
			require.NoError(t, unstructured.SetNestedField(obj.Object, int64(1), path...))
			client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
			_, err := ResolveKMSConfig(context.Background(), client, ref)
			require.Error(t, err)
		})
	}
}

func TestResolveKMSConfigImageComesOnlyFromStatus(t *testing.T) {
	obj := vaultPluginConfig(t, encryptiontesting.DefaultKMSPluginConfig)
	require.NoError(t, unstructured.SetNestedField(obj.Object, "wrong-image", "spec", "kmsPluginImage"))
	delete(obj.Object, "status")
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
	_, err := ResolveKMSConfig(context.Background(), client, defaultKMSConfigReference)
	require.ErrorContains(t, err, "status.kmsPluginImage must not be empty")
}

func TestResolveKMSConfigRequiredFields(t *testing.T) {
	for _, path := range [][]string{
		{"status", "kmsPluginImage"},
		{"spec", "vaultAddress"},
		{"spec", "vaultKeyPath"},
		{"spec", "authentication", "type"},
		{"spec", "authentication", "appRole", "secret", "name"},
	} {
		for _, variant := range []string{"missing", "empty", "null", "wrong type"} {
			t.Run(strings.Join(path, ".")+"/"+variant, func(t *testing.T) {
				obj := vaultPluginConfig(t, encryptiontesting.DefaultKMSPluginConfig)
				switch variant {
				case "missing":
					unstructured.RemoveNestedField(obj.Object, path...)
				case "empty":
					require.NoError(t, unstructured.SetNestedField(obj.Object, "", path...))
				case "null":
					require.NoError(t, unstructured.SetNestedField(obj.Object, nil, path...))
				case "wrong type":
					require.NoError(t, unstructured.SetNestedField(obj.Object, int64(1), path...))
				}
				client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
				config, err := ResolveKMSConfig(context.Background(), client, defaultKMSConfigReference)
				require.Error(t, err)
				require.Empty(t, config)
				if variant == "missing" || variant == "empty" {
					require.ErrorContains(t, err, strings.Join(path, ".")+" must not be empty")
				}
			})
		}
	}
}

func TestResolveKMSConfigRequiredSections(t *testing.T) {
	for _, path := range [][]string{
		{"spec"}, {"status"}, {"spec", "authentication"},
		{"spec", "authentication", "appRole"}, {"spec", "authentication", "appRole", "secret"},
	} {
		t.Run(strings.Join(path, "."), func(t *testing.T) {
			obj := vaultPluginConfig(t, encryptiontesting.DefaultKMSPluginConfig)
			unstructured.RemoveNestedField(obj.Object, path...)
			client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
			_, err := ResolveKMSConfig(context.Background(), client, defaultKMSConfigReference)
			require.Error(t, err)
		})
	}
}

func TestResolveKMSConfigOptionalTLS(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tls       map[string]interface{}
		wantError bool
	}{
		{name: "absent"},
		{name: "empty TLS", tls: map[string]interface{}{}},
		{name: "server name only", tls: map[string]interface{}{"serverName": "vault.example.com"}},
		{name: "empty CA reference", tls: map[string]interface{}{"caBundle": map[string]interface{}{}}},
		{name: "null CA reference", tls: map[string]interface{}{"caBundle": nil}},
		{name: "empty CA name", tls: map[string]interface{}{"caBundle": map[string]interface{}{"name": ""}}},
		{name: "null CA name", tls: map[string]interface{}{"caBundle": map[string]interface{}{"name": nil}}},
		{name: "invalid CA name type", tls: map[string]interface{}{"caBundle": map[string]interface{}{"name": int64(1)}}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := vaultPluginConfig(t, encryptiontesting.DefaultKMSPluginConfig)
			unstructured.RemoveNestedField(obj.Object, "spec", "tls")
			if tc.tls != nil {
				require.NoError(t, unstructured.SetNestedMap(obj.Object, tc.tls, "spec", "tls"))
			}
			client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
			_, err := ResolveKMSConfig(context.Background(), client, defaultKMSConfigReference)
			if tc.wantError {
				require.ErrorContains(t, err, "failed to convert Vault KMS plugin configuration spec")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResolveKMSConfigRejectsUnknownSpecFields(t *testing.T) {
	for _, path := range [][]string{{"futureField"}, {"authentication", "futureField"}, {"tls", "futureField"}} {
		t.Run(strings.Join(path, "."), func(t *testing.T) {
			obj := vaultPluginConfig(t, encryptiontesting.DefaultKMSPluginConfig)
			require.NoError(t, unstructured.SetNestedField(obj.Object, "unsupported", append([]string{"spec"}, path...)...))
			client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
			config, err := ResolveKMSConfig(context.Background(), client, defaultKMSConfigReference)
			require.ErrorContains(t, err, `unknown field "`+strings.Join(path, ".")+`"`)
			require.Empty(t, config)
		})
	}
}

func TestResolveKMSConfigImageDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, image string
		valid       bool
	}{
		{"digest", "quay.io/test/plugin@" + digest, true},
		{"tag and digest", "quay.io/test/plugin:v1@" + digest, true},
		{"tag only", "quay.io/test/plugin:v1", false},
		{"implicit latest", "quay.io/test/plugin", false},
		{"malformed digest", "quay.io/test/plugin@sha256:abc", false},
		{"invalid reference", "https://quay.io/test/plugin@" + digest, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := vaultPluginConfig(t, encryptiontesting.DefaultKMSPluginConfig)
			require.NoError(t, unstructured.SetNestedField(obj.Object, tc.image, "status", "kmsPluginImage"))
			client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
			config, err := ResolveKMSConfig(context.Background(), client, defaultKMSConfigReference)
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, tc.image, config.Vault.KMSPluginImage)
			} else {
				require.ErrorContains(t, err, "status.kmsPluginImage")
				require.Empty(t, config)
			}
		})
	}
}

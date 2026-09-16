package controllers

import (
	"context"
	"errors"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	expected.Vault.KMSPluginImage = "quay.io/test/plugin:v1"
	obj := vaultPluginConfig(t, expected)
	obj.SetName("custom-config")
	obj.SetAnnotations(map[string]string{"note": "ignored"})
	require.NoError(t, unstructured.SetNestedField(obj.Object, "ignored", "spec", "futureField"))
	require.NoError(t, unstructured.SetNestedField(obj.Object, "wrong-image", "spec", "kmsPluginImage"))
	before := obj.DeepCopy()
	ref := kmsConfigReference(expected)
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
	ref := kmsConfigReference(encryptiontesting.DefaultKMSPluginConfig)
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
	unsupported := ref
	unsupported.Type = configv1.KMSProviderType("Unknown")
	_, err = ResolveKMSConfig(context.Background(), newKMSDynamicClient(t), unsupported)
	require.ErrorContains(t, err, "unsupported KMS provider type")
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
	config, err := ResolveKMSConfig(context.Background(), client, kmsConfigReference(encryptiontesting.DefaultKMSPluginConfig))
	require.NoError(t, err)
	require.Empty(t, config.Vault.KMSPluginImage)
	require.Equal(t, metav1.TypeMeta{APIVersion: kms.SchemeGroupVersion.String(), Kind: "KMSPluginConfig"}, config.TypeMeta)
}

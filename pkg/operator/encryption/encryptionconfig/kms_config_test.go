package encryptionconfig

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestHashKMSConfig(t *testing.T) {
	// test equality and ordering of elements
	kms1 := configv1.KMSConfig{
		AWS: &configv1.AWSKMSConfig{
			Region: "us-east-1",
			KeyARN: "arn:aws:kms:us-east-1:999999999999:key/6b512e30-0f99-4cf5-8174-fc1a5b22cd6a",
		},
		Type: configv1.AWSKMSProvider,
	}
	kms2 := configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:999999999999:key/6b512e30-0f99-4cf5-8174-fc1a5b22cd6a",
			Region: "us-east-1",
		},
	}
	t.Run("equality and ordering", func(t *testing.T) {
		k1, err := HashKMSConfig(kms1)
		require.NoError(t, err)
		k2, err := HashKMSConfig(kms2)
		require.NoError(t, err)

		assert.Equal(t, k1, k2, "hashes should match irrespective of ordering")
	})

	// test inequality
	kms1 = configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "foo",
		},
	}
	kms2 = configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "bar",
		},
	}
	t.Run("inequality", func(t *testing.T) {
		k1, err := HashKMSConfig(kms1)
		require.NoError(t, err)
		k2, err := HashKMSConfig(kms2)
		require.NoError(t, err)

		assert.NotEqual(t, k1, k2, "config with inequal values should yield different hash")
	})

	// test if hash has same size
	kms1 = configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:999999999999:key/6b512e30-0f99-4cf5-8174-fc1a5b22cd6a",
		},
	}
	kms2 = configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:999999999999:key/6b512e30-0f99-4cf5-8174-fc1a5b22cd6a",
			Region: "us-east-1",
		},
	}
	t.Run("identical size", func(t *testing.T) {
		k1, err := HashKMSConfig(kms1)
		require.NoError(t, err)
		k2, err := HashKMSConfig(kms2)
		require.NoError(t, err)

		assert.Equal(t, len(k1), len(k2), "length of hashes should match irrespective of contents")
	})

	// test if pointer based nested struct contents are honored
	t.Run("pointer to nested structs", func(t *testing.T) {
		kms1.AWS = &configv1.AWSKMSConfig{}
		kms2.AWS = nil

		k1, err := HashKMSConfig(kms1)
		require.NoError(t, err)
		k2, err := HashKMSConfig(kms2)
		require.NoError(t, err)

		assert.NotEqual(t, k1, k2, "hash should not yield identical for nil pointer and empty object")
	})

	// FutureKMSConfig holds existing kms config fields plus a few newly added fields,
	// this mocks a future event of adding a new kms provider platform to configv1.KMSConfig api
	type FutureKMSConfig struct {
		configv1.KMSConfig

		CustomPlatform *struct {
			AccessPoint string `json:"accessPoint"`
		} `json:"custom,omitempty"`
	}

	kms1 = configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:999999999999:key/6b512e30-0f99-4cf5-8174-fc1a5b22cd6a",
			Region: "us-east-1",
		},
	}
	kmsFut := FutureKMSConfig{
		KMSConfig:      *kms1.DeepCopy(),
		CustomPlatform: nil,
	}
	t.Run("hash should be identical even when new fields are added", func(t *testing.T) {
		k1, err := HashKMSConfig(kms1)
		require.NoError(t, err)

		k2, err := HashKMSConfig(kmsFut)
		require.NoError(t, err)

		assert.Equal(t, k1, k2, "hash cannot change when new fields with empty values are added to KMSConfig struct")
	})
}

func TestGRHash(t *testing.T) {
	t.Run("equality and ordering", func(t *testing.T) {
		hash1 := resourceHash(
			schema.GroupResource{Resource: "secrets"},
			schema.GroupResource{Group: "route.openshift.io", Resource: "routes"},
		)
		hash2 := resourceHash(
			schema.GroupResource{Group: "route.openshift.io", Resource: "routes"},
			schema.GroupResource{Resource: "secrets"},
		)
		assert.Equal(t, hash1, hash2)
	})

	t.Run("identical size", func(t *testing.T) {
		hash1 := resourceHash(
			schema.GroupResource{Resource: "secrets"},
		)
		hash2 := resourceHash(
			schema.GroupResource{Group: "route.openshift.io", Resource: "routes"},
			schema.GroupResource{Resource: "secrets"},
		)
		assert.Equal(t, len(hash1), len(hash2), "length of hashes should match irrespective of contents")
	})

	t.Run("inequality", func(t *testing.T) {
		hash1 := resourceHash(
			schema.GroupResource{Group: "route.openshift.io", Resource: "routes"},
			schema.GroupResource{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
		)
		hash2 := resourceHash(
			schema.GroupResource{Group: "route.openshift.io", Resource: "routes"},
			schema.GroupResource{Group: "", Resource: "oauthaccesstokens"},
		)
		assert.NotEqual(t, hash1, hash2, "non-identical GRs should yield different hash")
	})
}

func TestKMSConfigEncodeDecode(t *testing.T) {
	cfgs := []*configv1.KMSConfig{
		{
			Type: configv1.AWSKMSProvider,
			AWS: &configv1.AWSKMSConfig{
				KeyARN: "arn:aws:kms:us-east-1:999999999999:key/6b512e30-0f99-4cf5-8174-fc1a5b22cd6a",
				Region: "us-east-1",
			},
		},
		{
			Type: configv1.AWSKMSProvider,
			AWS: &configv1.AWSKMSConfig{
				KeyARN: "arn:aws:kms:us-east-1:999999999999:key/6b512e30-0f99-4cf5-8174-fc1a5b22cd6a",
			},
		},
		{
			Type: "",
			AWS:  &configv1.AWSKMSConfig{},
		},
		{
			Type: "",
		},
	}

	for _, cfg := range cfgs {
		b, err := EncodeKMSConfig(cfg)
		require.NoError(t, err)
		t.Logf("%s", b)
		cfgBack, err := DecodeKMSConfig(b)
		require.NoError(t, err)

		if !cmp.Equal(cfg, cfgBack) {
			t.Fatal(fmt.Errorf("%s", cmp.Diff(cfg, cfgBack)))
		}
	}
}

func TestKMSConfigHashRT(t *testing.T) {
	actualKMSHash, err := HashKMSConfig(configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS:  &configv1.AWSKMSConfig{},
	})
	require.NoError(t, err)

	actualKeyGeneration := uint64(10)

	generated := generateKMSProviderName(actualKeyGeneration, actualKMSHash, schema.GroupResource{Resource: "secrets"})
	expectedKMSHash, expectedKeyGeneration, ok := extractKMSFromProviderName(generated)
	require.Equal(t, ok, true)

	assert.Equal(t, actualKMSHash, expectedKMSHash, "extracted kms hash does not match original kms hash")
	assert.Equal(t, actualKeyGeneration, expectedKeyGeneration, "extracted key generation does not match original generation")
}

package encryptionconfig

import (
	"hash/fnv"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestHashObject(t *testing.T) {
	hasher := fnv.New64a()

	// test if hash can sort map keys
	t.Run("sort map keys", func(t *testing.T) {
		cm1 := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cm",
				Namespace: "openshift",
			},
			Data: map[string]string{
				"k": "v",
				"v": "k",
			},
		}
		cm2 := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cm",
				Namespace: "openshift",
			},
			Data: map[string]string{
				"v": "k",
				"k": "v",
			},
		}

		h1 := HashObject(hasher, cm1)
		h2 := HashObject(hasher, cm2)

		assert.Equal(t, h1, h2, "hash should match irrespective of map ordering")
	})

	kms1 := configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:269733383066:key/6b512e30-0f99-4cf5-8174-fc1a5b22cd6a",
		},
	}
	kms2 := configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:269733383066:key/6b512e30-0f99-4cf5-8174-fc1a5b22cd6a",
			Region: "us-east-1",
		},
	}

	// test if hash has same size
	t.Run("identical size", func(t *testing.T) {
		k1 := HashObject(hasher, kms1)
		k2 := HashObject(hasher, kms2)

		assert.Equal(t, len(k1), len(k2), "length of hashes should match irrespective of contents")
	})

	// test if pointer based nested struct contents are honored
	t.Run("pointer to nested structs", func(t *testing.T) {
		kms1.AWS = &configv1.AWSKMSConfig{}
		kms2.AWS = nil

		k1 := HashObject(hasher, kms1)
		k2 := HashObject(hasher, kms2)

		assert.NotEqual(t, k1, k2, "hash should not yield identical for nil pointer and empty object")
	})
}

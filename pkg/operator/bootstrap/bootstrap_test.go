package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

var (
	bootstrapComplete = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "bootstrap", Namespace: "kube-system"},
		Data:       map[string]string{"status": "complete"},
	}

	bootstrapProgressing = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "bootstrap", Namespace: "kube-system"},
		Data:       map[string]string{"status": "progressing"},
	}

	bootstrapNoStatus = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "bootstrap", Namespace: "kube-system"},
		Data:       map[string]string{"noStatus": "complete"},
	}
)

func TestIsBootstrapComplete(t *testing.T) {
	tests := map[string]struct {
		bootstrapConfigMap *corev1.ConfigMap
		expectComplete     bool
		expectError        error
	}{
		"bootstrap complete": {
			bootstrapConfigMap: bootstrapComplete,
			expectComplete:     true,
			expectError:        nil,
		},
		"bootstrap progressing": {
			bootstrapConfigMap: bootstrapProgressing,
			expectComplete:     false,
			expectError:        nil,
		},
		"bootstrap no status": {
			bootstrapConfigMap: bootstrapNoStatus,
			expectComplete:     false,
			expectError:        nil,
		},
		"bootstrap configmap missing": {
			bootstrapConfigMap: nil,
			expectComplete:     false,
			expectError:        nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			if test.bootstrapConfigMap != nil {
				if err := indexer.Add(test.bootstrapConfigMap); err != nil {
					t.Fatal(err)
				}
			}
			fakeConfigMapLister := corev1listers.NewConfigMapLister(indexer)

			actualComplete, actualErr := IsBootstrapComplete(fakeConfigMapLister)

			assert.Equal(t, test.expectComplete, actualComplete)
			assert.Equal(t, test.expectError, actualErr)
		})
	}
}

package encryption

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptionconfig"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
)

func TestEncryptionEnabledPrecondition(t *testing.T) {
	component := "oas"
	encryptionSecretSelector, err := labels.Parse(secrets.EncryptionKeySecretsLabel + "=" + component)
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name                           string
		encryptionType                 configv1.EncryptionType
		existingSecret                 runtime.Object
		expectedPreconditionsToBeReady bool
		expectError                    bool
	}{

		// scenario 1
		{
			name: "encryption off, empty currentMode",
		},

		// scenario 2
		{
			name:           "encryption off, currentMode set to identity",
			encryptionType: configv1.EncryptionTypeIdentity,
		},

		// scenario 3
		{
			name:                           "encryption on, currentMode set to identity",
			encryptionType:                 configv1.EncryptionTypeAESCBC,
			expectedPreconditionsToBeReady: true,
		},

		// scenario 4
		{
			name:                           "encryption off on previously enabled cluster, with existing encryption key secret",
			encryptionType:                 configv1.EncryptionTypeIdentity,
			existingSecret:                 encryptiontesting.CreateEncryptionKeySecretWithRawKey("oas", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 1, []byte("61def964fb967f5d7c44a2af8dab6865")),
			expectedPreconditionsToBeReady: true,
		},

		// scenario 5
		{
			name:           "encryption off on previously enabled cluster, with existing encryption configuration secret",
			encryptionType: configv1.EncryptionTypeIdentity,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-%s", encryptionconfig.EncryptionConfSecretName, component),
					Namespace: "openshift-config-managed",
				},
			},
			expectedPreconditionsToBeReady: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// test data
			apiServerConfigIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			apiServerConfigIndexer.Add(&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}, Spec: configv1.APIServerSpec{Encryption: configv1.APIServerEncryption{Type: scenario.encryptionType}}})
			apiServerConfigLister := configlistersv1.NewAPIServerLister(apiServerConfigIndexer)

			secretsIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if scenario.existingSecret != nil {
				secretsIndexer.Add(scenario.existingSecret)
			}
			namespacedSecretLister := corev1listers.NewSecretLister(secretsIndexer).Secrets("openshift-config-managed")

			// act
			target := &preconditionChecker{component: component, encryptionSecretSelector: encryptionSecretSelector, secretLister: namespacedSecretLister, apiServerConfigLister: apiServerConfigLister}
			preconditionsReady, err := target.PreconditionFulfilled()

			// validate
			if scenario.expectedPreconditionsToBeReady != preconditionsReady {
				t.Errorf("expected precondition to be ready = %v but got ready = %v", scenario.expectedPreconditionsToBeReady, preconditionsReady)
			}

			if scenario.expectError && err == nil {
				t.Error("expected to get an error but none was returned")
			}

			if !scenario.expectError && err != nil {
				t.Errorf("unexpected error was returned, err = %v", err)
			}
		})
	}
}

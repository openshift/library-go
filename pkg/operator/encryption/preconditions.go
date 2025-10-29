package encryption

import (
	"fmt"

	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptionconfig"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

type preconditionChecker struct {
	component                string
	encryptionSecretSelector labels.Selector

	secretLister          corev1listers.SecretNamespaceLister
	apiServerConfigLister configv1listers.APIServerLister
}

// newEncryptionEnabledPrecondition determines if encryption controllers should synchronise.
// It uses the cache for gathering data to avoid sending requests to the API servers.
func newEncryptionEnabledPrecondition(apiServerConfigLister configv1listers.APIServerLister, kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces, encryptionSecretSelectorString, component string) (*preconditionChecker, error) {
	encryptionSecretSelector, err := labels.Parse(encryptionSecretSelectorString)
	if err != nil {
		return nil, err
	}
	return &preconditionChecker{
		component:                component,
		encryptionSecretSelector: encryptionSecretSelector,
		secretLister:             kubeInformersForNamespaces.SecretLister().Secrets("openshift-config-managed"),
		apiServerConfigLister:    apiServerConfigLister,
	}, nil
}

// PreconditionFulfilled a method that indicates whether all prerequisites are met and we can Sync.
// This method MUST be call after the informers synced
func (pc *preconditionChecker) PreconditionFulfilled() (bool, error) {
	encryptionWasEnabled, err := pc.encryptionWasEnabled()
	if err != nil {
		return false, err // got an error, report it and run the sync loops
	}
	if !encryptionWasEnabled {
		return false, nil // encryption hasn't been enabled - no work to do
	}

	// TODO: add a step that would determine if encryption is disabled on previously encrypted clusters that would require:
	//       having the current mode set to Identity
	//       having all servers on the same revision
	//       having desired and actual encryption configuration aligned
	//       having all resources migrated

	return true, nil // we might have work to do
}

// encryptionWasEnabled checks whether encryption was enabled on a cluster. It wasn't enabled when:
//
//	a server configuration doesn't exist
//	the current encryption mode is empty or set to identity mode and
//	a secret with encryption configuration doesn't exist in the managed namespace and
//	secrets with encryption keys don't exist in the managed namespace
func (pc *preconditionChecker) encryptionWasEnabled() (bool, error) {
	apiServerConfig, err := pc.apiServerConfigLister.Get("cluster")
	if errors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err // unknown error
	}

	currentMode := state.Mode(apiServerConfig.Spec.Encryption.Type)
	if len(currentMode) > 0 && currentMode != state.Identity {
		return true, nil // encryption might be actually in progress
	}

	encryptionConfiguration, err := pc.secretLister.Get(fmt.Sprintf("%s-%s", encryptionconfig.EncryptionConfSecretName, pc.component))
	if err != nil && !errors.IsNotFound(err) {
		return false, err // unknown error
	}
	if encryptionConfiguration != nil {
		return true, nil
	}

	// very unlikely - encryption config doesn't exists but we have some encryption keys
	// but since this is coming from a cache just double check

	encryptionSecrets, err := pc.secretLister.List(pc.encryptionSecretSelector)
	if err != nil && !errors.IsNotFound(err) {
		return false, err // unknown error
	}
	return len(encryptionSecrets) > 0, nil
}

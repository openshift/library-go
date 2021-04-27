package encryption

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptionconfig"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

type preconditionChecker struct {
	component                string
	encryptionSecretSelector labels.Selector

	secretLister          corev1listers.SecretNamespaceLister
	apiServerConfigLister configv1listers.APIServerLister

	cacheSynced []cache.InformerSynced
}

// newEncryptionEnabledPrecondition determines if encryption controllers should synchronise.
// It uses the cache for gathering data to avoid sending requests to the API servers.
func newEncryptionEnabledPrecondition(apiServerConfigInformer configv1informers.APIServerInformer, kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces, encryptionSecretSelectorString string) (*preconditionChecker, error) {
	encryptionSecretSelector, err := labels.Parse(encryptionSecretSelectorString)
	if err != nil {
		return nil, err
	}
	return &preconditionChecker{
		encryptionSecretSelector: encryptionSecretSelector,
		secretLister:             kubeInformersForNamespaces.SecretLister().Secrets("openshift-config-managed"),
		apiServerConfigLister:    apiServerConfigInformer.Lister(),
		cacheSynced: []cache.InformerSynced{
			apiServerConfigInformer.Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets().Informer().HasSynced,
		},
	}, nil
}

// PreconditionFulfilled a method that indicates whether all prerequisites are met and we can Sync.
func (pc *preconditionChecker) PreconditionFulfilled() (bool, error) {
	if !pc.hasCachesSynced() {
		// at this point we are unable to perform our checks
		// report there is work to do so that controllers run their sync loops
		klog.V(4).Info("unable to check preconditions. The caches haven't been synchronized. Forcing the encryption controllers to run their sync loops.")
		return true, nil
	}

	encryptionNeverEnabled, err := pc.encryptionNeverEnabled()
	if err != nil {
		return false, err // got an error, report it and run the sync loops
	}
	if encryptionNeverEnabled {
		return false, nil // encryption hasn't been enabled - no work to do
	}

	// TODO: add a step that would determine if encryption is disabled on previously encrypted clusters that would require:
	//       having the current mode set to Identity
	//       having all servers on the same revision
	//       having desired and actual encryption configuration aligned
	//       having all resources migrated

	return true, nil // we might have work to do
}

// encryptionNeverEnabled checks whether encryption hasn't been enabled on a cluster
// it hasn't been enabled when:
//   the current mode is set to identity
//   AND the encryption configuration in the managed namespace doesn't exists AND we don't have encryption secrets
func (pc *preconditionChecker) encryptionNeverEnabled() (bool, error) {
	apiServerConfig, err := pc.apiServerConfigLister.Get("cluster")
	if err != nil {
		if !errors.IsNotFound(err) {
			return false, err // unknown error
		}
		return true, nil
	}
	if currentMode := state.Mode(apiServerConfig.Spec.Encryption.Type); len(currentMode) != 0 && currentMode != state.Identity {
		return false, nil
	}

	encryptionConfiguration, err := pc.secretLister.Get(fmt.Sprintf("%s-%s", encryptionconfig.EncryptionConfSecretName, pc.component))
	if err != nil && !errors.IsNotFound(err) {
		return false, err // unknown error
	}

	encryptionSecrets, err := pc.secretLister.List(pc.encryptionSecretSelector)
	if err != nil && !errors.IsNotFound(err) {
		return false, err // unknown error
	}

	return encryptionConfiguration == nil && len(encryptionSecrets) == 0, nil
}

func (pc *preconditionChecker) hasCachesSynced() bool {
	for i := range pc.cacheSynced {
		if !pc.cacheSynced[i]() {
			return false
		}
	}
	return true
}

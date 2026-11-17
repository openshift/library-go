package certrotation

import (
	"fmt"

	kubeinformers "k8s.io/client-go/informers"
	kubernetes "k8s.io/client-go/kubernetes"
	clock "k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/operator/events"
)

// InformerSource supplies namespace-scoped shared informer factories, one
// per namespace the Rotation touches. v1helpers.KubeInformersForNamespaces
// already satisfies it.
type InformerSource interface {
	InformersFor(namespace string) kubeinformers.SharedInformerFactory
}

// Options carries the required operational inputs of a Reconciler or
// controller. Role, KubeClient, PKI and Recorder are required; their absence
// is a construction error, not a runtime behavior.
type Options struct {
	// Role states who this process is with respect to the artifacts.
	// Required.
	Role Role

	// KubeClient is the client used for all reads and writes. Required.
	KubeClient kubernetes.Interface

	// PKI selects how key material is produced. Required: LegacyPKI() or
	// ConfigurablePKI(provider).
	PKI PKI

	// Recorder emits events for artifact lifecycle changes. Required; pass a
	// LoggingRecorder when no events recorder is available.
	Recorder events.Recorder

	// Informers is required by NewController, which derives its filtered
	// informers from it. NewReconciler accepts nil, in which case all reads
	// are live GETs through KubeClient (one-shot callers such as oc).
	Informers InformerSource

	// Reporter, if set, receives per-target sync results for status
	// conditions. Optional; nil means events and logs only.
	Reporter StatusReporter

	// Clock, if set, is the time source for all rotation decisions and
	// issuance. Optional; defaults to clock.RealClock{}. Tests inject a
	// fake or virtual clock.
	Clock clock.PassiveClock
}

// validate checks the required fields. requireInformers additionally
// requires Informers, which only NewController demands.
func (o Options) validate(requireInformers bool) error {
	if o.Role != RoleWriter && o.Role != RoleHealer {
		return ErrRoleRequired
	}
	if o.KubeClient == nil {
		return ErrKubeClientRequired
	}
	if o.PKI.mode == pkiModeInvalid {
		return ErrPKIRequired
	}
	if err := o.PKI.validate(); err != nil {
		return err
	}
	if o.Recorder == nil {
		return ErrRecorderRequired
	}
	if requireInformers && o.Informers == nil {
		return ErrInformersRequired
	}
	return nil
}

// namespaces returns every namespace the Rotation touches, for informer
// derivation and validation.
func namespaces(rotation Rotation) []string {
	seen := map[string]struct{}{
		rotation.Signer.Namespace: {},
		rotation.Bundle.Namespace: {},
	}
	for i := range rotation.Targets {
		seen[rotation.Targets[i].Namespace] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for ns := range seen {
		result = append(result, ns)
	}
	return result
}

// validateInformerSource checks that the source supplies a factory for every
// namespace the Rotation touches.
func validateInformerSource(rotation Rotation, source InformerSource) error {
	for _, ns := range namespaces(rotation) {
		if source.InformersFor(ns) == nil {
			return fmt.Errorf("%w: %s", ErrInformerSourceNil, ns)
		}
	}
	return nil
}

package certrotation

import (
	"errors"
	"fmt"
)

// Sentinel errors of the package. Errors returned by Reconcile wrap one of
// these (see ArtifactError); each has a defined requeue and reporting policy
// in the controller.
var (
	// ErrConflict reports an optimistic concurrency conflict: another writer
	// updated the artifact between read and write. The controller requeues
	// immediately; persistent conflicts escalate to ErrWriterContention.
	ErrConflict = errors.New("certrotation: optimistic concurrency conflict")

	// ErrInputNotReady reports that an input the Rotation needs is not yet
	// available, for example a serving cert with no hostnames resolved yet.
	// The controller requeues and reports Degraded only if it persists.
	ErrInputNotReady = errors.New("certrotation: input not ready")

	// ErrPKIConfig reports that PKI configuration is unavailable or invalid.
	// There is never a silent fallback.
	ErrPKIConfig = errors.New("certrotation: PKI configuration unavailable or invalid")

	// ErrInvariant reports a violated invariant, for example a persisted CA
	// bundle that is empty or does not contain the current signer. Targets
	// are never evaluated against a bundle that fails verification.
	ErrInvariant = errors.New("certrotation: invariant violated")

	// ErrWriterContention reports that conflicts on the same artifact have
	// persisted beyond the contention window, which means two processes are
	// actively fighting over an artifact. Reported Degraded.
	ErrWriterContention = errors.New("certrotation: persistent write contention")
)

// Construction-time validation errors.
var (
	// ErrRoleRequired reports that Options.Role was left at its invalid zero
	// value.
	ErrRoleRequired = errors.New("certrotation: Options.Role is required (RoleWriter or RoleHealer)")

	// ErrPKIRequired reports that Options.PKI was left at its invalid zero
	// value.
	ErrPKIRequired = errors.New("certrotation: Options.PKI is required (LegacyPKI() or ConfigurablePKI(...))")

	// ErrKubeClientRequired reports that Options.KubeClient is nil.
	ErrKubeClientRequired = errors.New("certrotation: Options.KubeClient is required")

	// ErrRecorderRequired reports that Options.Recorder is nil.
	ErrRecorderRequired = errors.New("certrotation: Options.Recorder is required")

	// ErrInformersRequired reports that Options.Informers is nil, which is
	// only valid for NewReconciler, not NewController.
	ErrInformersRequired = errors.New("certrotation: Options.Informers is required by NewController")

	// ErrInformerSourceNil reports that InformerSource.InformersFor returned
	// nil for a namespace the Rotation touches.
	ErrInformerSourceNil = errors.New("certrotation: InformerSource.InformersFor returned nil for a required namespace")
)

// ArtifactKind identifies which slot of the Rotation an artifact fills. The
// values mirror the managed-certificate-type label values, on purpose: the
// label is the on-cluster serialization of this concept.
type ArtifactKind string

const (
	ArtifactKindSigner ArtifactKind = "signer"
	ArtifactKindBundle ArtifactKind = "ca-bundle"
	ArtifactKindTarget ArtifactKind = "target"
)

// Phase identifies where in the reconcile pass an error occurred.
type Phase string

const (
	PhaseRead     Phase = "read"
	PhaseClassify Phase = "classify"
	PhaseIssue    Phase = "issue"
	PhaseWrite    Phase = "write"
	PhaseVerify   Phase = "verify"
)

// ArtifactRef identifies the artifact an error or action is about.
type ArtifactRef struct {
	Kind ArtifactKind
	// Location is the namespace and name of the underlying Secret or
	// ConfigMap.
	Location Location
}

func (a ArtifactRef) String() string {
	return fmt.Sprintf("%s %s/%s", a.Kind, a.Location.Namespace, a.Location.Name)
}

// ArtifactError attributes an error to one artifact and one phase of the
// reconcile pass. Err wraps one of the sentinel errors above or an
// underlying API error.
type ArtifactError struct {
	Artifact ArtifactRef
	Phase    Phase
	Err      error
}

// Error renders the artifact error with its attribution.
func (e *ArtifactError) Error() string {
	return fmt.Sprintf("%s (phase %s): %v", e.Artifact, e.Phase, e.Err)
}

// Unwrap exposes the underlying error for errors.Is.
func (e *ArtifactError) Unwrap() error {
	return e.Err
}

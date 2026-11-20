package certrotation

import "github.com/openshift/library-go/pkg/operator/pki/certrotation/internal/engine"

// Role states who this process is with respect to the TLS artifacts of a
// Rotation. The zero value is invalid: every caller must choose.
//
// Exactly one writer per artifact set should run, under the operator's
// leader election. A healer may run alongside the writer in a separate
// process (as CKAO's cert-regeneration-controller and KCMO's
// recovery-controller do today), including a healer built from a different
// library-go version or from v1.
//
// Role is an alias of the engine's role type, which is where the decision
// table lives.
type Role = engine.Role

const (
	// RoleWriter owns the full artifact lifecycle: creation, scheduled
	// rotation (refresh period, 80% of validity, stale trust, hostname drift,
	// key-algorithm drift under ConfigurablePKI) and metadata repair
	// (annotations, labels, owner references, Secret type normalization).
	RoleWriter = engine.RoleWriter

	// RoleHealer restores artifacts that are unusable: missing, expired, or
	// invalid (unparseable data, or the force-regeneration sentinel). It
	// never performs scheduled rotation and never repairs metadata on an
	// otherwise usable artifact, so it cannot fight the writer regardless of
	// which version the writer runs. When it does regenerate, it issues with
	// the current inputs (hostnames, PKI resolution), exactly as the writer
	// would.
	RoleHealer = engine.RoleHealer
)

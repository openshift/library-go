package health

import "time"

// HealthClass is the closed-set classifier for Healthz.
type HealthClass string

const (
	HealthClassOK       HealthClass = "ok"
	HealthClassNotOK    HealthClass = "not-ok"
	HealthClassRPCError HealthClass = "rpc-error"
)

type Healthz struct {
	Class  HealthClass
	Detail string
}

// IsOK is the canonical health predicate. Prefer this over comparing
// Class directly so consumers don't depend on the internal shape.
func (h Healthz) IsOK() bool { return h.Class == HealthClassOK }

// String renders the wire format: "ok" or "unhealthy:<class>:<detail>".
func (h Healthz) String() string {
	if h.Class == HealthClassOK {
		return string(HealthClassOK)
	}
	return "unhealthy:" + string(h.Class) + ":" + h.Detail
}

type HealthStatus struct {
	Healthz Healthz

	// KeyIDHash is the sha256 hex of the KeyID the plugin returned, or
	// empty if the probe could not reach Status. Hashing avoids leaking
	// key material; consumers can still diff hashes across instances to
	// detect rotation skew.
	KeyIDHash string

	// Timestamp: RFC3339 on the wire.
	Timestamp time.Time

	// ObserverPod is stable across deployment stages. ConfigMapWriter
	// does not strictly need it (one CM per monitor, identity is in the
	// CM name); the OpenShift CRD-condition writer does (one CR
	// aggregates conditions from N pods, and identity must travel with
	// each entry).
	ObserverPod string
}

package health

import "time"

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

// IsOK is the canonical predicate; prefer it over comparing Class so
// consumers don't depend on the internal classification shape.
func (h Healthz) IsOK() bool { return h.Class == HealthClassOK }

type HealthStatus struct {
	Healthz Healthz

	// KeyIDHash is the sha256 hex of the plugin's KeyID, empty when Status
	// couldn't be reached. Hashing avoids leaking key material; consumers
	// can still diff hashes across instances to detect rotation skew.
	KeyIDHash string

	Timestamp time.Time

	// ObserverPod identifies this monitor instance; one OperatorCondition
	// CR aggregates entries from N pods, so identity must travel with
	// each condition entry.
	ObserverPod string
}

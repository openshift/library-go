package health

import "context"

// StatusWriter ships each HealthStatus produced by the Monitor. Write errors
// should be logged and tolerated by the Monitor. A missed publish is strictly
// less bad than crashing the sidecar.
type StatusWriter interface {
	Write(ctx context.Context, status HealthStatus) error
}

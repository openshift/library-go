package health

import (
	"context"
	"sync"
	"time"

	kmsservice "k8s.io/kms/pkg/service"
)

// healthzOK is the value the KMS plugin returns when healthy.
// See https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/kms/apis/v2/api.proto#L39
const healthzOK = "ok"

const (
	statusHealthy   = "healthy"
	statusUnhealthy = "unhealthy"
	statusError     = "error"
)

type pluginHealthReport struct {
	// KeyID is the controller's sequential key id; KEKID is the KMS provider's
	// encryption key id. Distinct identifiers, easy to confuse.
	KeyID       string
	KEKID       string
	Status      string
	LastChecked time.Time
	Detail      string
}

// pluginClient is the dialed handle to one co-located KMS plugin; the plugin
// itself is a separate process behind the unix socket.
type pluginClient struct {
	keyID   string
	service kmsservice.Service
}

type prober struct {
	plugins []pluginClient
	now     func() time.Time
}

func newProber(plugins []pluginClient) *prober {
	return &prober{
		plugins: plugins,
		now:     time.Now,
	}
}

// probeAll never returns an error: a failed probe is encoded as a report
// with Status "error" so the caller always gets one entry per plugin.
// Probes run concurrently so one hung plugin doesn't delay the others;
// worst-case duration is one read-timeout, not the sum.
func (p *prober) probeAll(ctx context.Context) []pluginHealthReport {
	reports := make([]pluginHealthReport, len(p.plugins))

	var wg sync.WaitGroup
	for i, plugin := range p.plugins {
		wg.Go(func() {
			reports[i] = p.probe(ctx, plugin)
		})
	}
	wg.Wait()

	return reports
}

func (p *prober) probe(ctx context.Context, plugin pluginClient) pluginHealthReport {
	report := pluginHealthReport{
		KeyID:       plugin.keyID,
		LastChecked: p.now(),
	}

	resp, err := plugin.service.Status(ctx)
	switch {
	case err != nil:
		report.Status = statusError
		report.Detail = err.Error()
	case resp == nil:
		// The in-tree gRPC client never returns (nil, nil), but a misbehaving
		// plugin must not panic the reporter.
		report.Status = statusError
		report.Detail = "kms plugin returned nil status response"
	case resp.Healthz == healthzOK:
		report.Status = statusHealthy
		report.KEKID = resp.KeyID
	default:
		report.Status = statusUnhealthy
		report.Detail = resp.Healthz
	}

	return report
}

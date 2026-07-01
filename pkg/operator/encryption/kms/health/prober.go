package health

import (
	"context"
	"errors"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kmsservice "k8s.io/kms/pkg/service"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
)

// healthzOK is the value the KMS plugin returns when healthy.
// See https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/kms/apis/v2/api.proto#L39
const healthzOK = "ok"

var errResponseless error = errors.New("kms plugin returned nil status response")

// pluginClient is the dialed handle to one co-located KMS plugin; the plugin
// itself is a separate process behind the unix socket.
type pluginClient struct {
	keyID   string
	service kmsservice.Service
}

type prober struct {
	nodeName string
	plugins  []pluginClient
	now      func() time.Time
}

func newProber(nodeName string, plugins []pluginClient) *prober {
	return &prober{
		nodeName: nodeName,
		plugins:  plugins,
		now:      time.Now,
	}
}

// probeAll never returns an error: a failed probe is encoded as a report
// with Status "error" so the caller always gets one entry per plugin.
// Probes run concurrently so one hung plugin doesn't delay the others;
// worst-case duration is one read-timeout, not the sum.
func (p *prober) probeAll(ctx context.Context) *applyoperatorv1.KMSEncryptionStatusApplyConfiguration {
	reports := make([]*applyoperatorv1.KMSPluginHealthReportApplyConfiguration, len(p.plugins))

	var wg sync.WaitGroup
	for i, plugin := range p.plugins {
		wg.Go(func() {
			reports[i] = p.probe(ctx, plugin)
		})
	}
	wg.Wait()

	return applyoperatorv1.KMSEncryptionStatus().WithHealthReports(reports...)
}

func (p *prober) probe(ctx context.Context, plugin pluginClient) *applyoperatorv1.KMSPluginHealthReportApplyConfiguration {
	report := applyoperatorv1.KMSPluginHealthReport().
		WithNodeName(p.nodeName).
		WithKeyId(plugin.keyID).
		WithLastCheckedTime(metav1.NewTime(p.now()))

	resp, err := plugin.service.Status(ctx)
	switch {
	case err != nil:
		report.WithStatus(operatorv1.KMSPluginHealthStatusError).
			WithDetail(err.Error())
	case resp == nil:
		// The in-tree gRPC client never returns (nil, nil), but a misbehaving
		// plugin must not panic the reporter.
		report.WithStatus(operatorv1.KMSPluginHealthStatusError).
			WithDetail(errResponseless.Error())
	case resp.Healthz == healthzOK:
		report.WithStatus(operatorv1.KMSPluginHealthStatusHealthy).
			WithKEKId(resp.KeyID)
	default:
		report.WithStatus(operatorv1.KMSPluginHealthStatusUnhealthy).
			WithDetail(resp.Healthz)
	}

	return report
}

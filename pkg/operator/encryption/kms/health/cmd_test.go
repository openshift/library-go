package health

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	kmsservice "k8s.io/kms/pkg/service"
)

// TestRunReportsOnce checks the loop wiring: Run probes, builds the status, and
// hands it to the reporter. The reporter cancels the context so the loop ends
// after a single tick.
func TestRunReportsOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	var have *applyoperatorv1.KMSEncryptionStatusApplyConfiguration
	c := &Config{
		interval:     time.Hour, // never reached; cancelled after the first tick
		writeTimeout: time.Second,
		prober: &prober{
			nodeName: "node-1",
			plugins: []pluginClient{
				{keyID: "1", service: &fakeService{resp: &kmsservice.StatusResponse{Healthz: "ok", KeyID: "kek-abc"}}},
			},
			now: func() time.Time { return time.Unix(0, 0).UTC() },
		},
		writeStatus: func(_ context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
			have = status
			cancel()
			return nil
		},
	}

	require.NoError(t, c.Run(ctx))
	require.Len(t, have.HealthReports, 1)
	require.Equal(t, "node-1", *have.HealthReports[0].NodeName)
	require.Equal(t, "1", *have.HealthReports[0].KeyId)
}

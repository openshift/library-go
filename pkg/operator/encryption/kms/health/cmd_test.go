package health

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	operatorv1 "github.com/openshift/api/operator/v1"
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
	var haveFieldManager string
	c := &Config{
		interval:     time.Hour, // never reached; cancelled after the first tick
		writeTimeout: time.Second,
		fieldManager: "test-field-manager",
		prober: &prober{
			nodeName: "node-1",
			plugins: []pluginClient{
				{keyID: "1", service: &fakeService{resp: &kmsservice.StatusResponse{Healthz: "ok", KeyID: "kek-abc"}}},
			},
			now: func() time.Time { return time.Unix(0, 0).UTC() },
		},
		statusClient: &fakeEncryptionStatusClient{
			applyFn: func(_ context.Context, fieldManager string, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
				have = status
				haveFieldManager = fieldManager
				cancel()
				return nil
			},
		},
	}

	require.NoError(t, c.Run(ctx))
	require.Len(t, have.HealthReports, 1)
	require.Equal(t, "node-1", *have.HealthReports[0].NodeName)
	require.Equal(t, "1", *have.HealthReports[0].KeyId)
	require.Equal(t, "test-field-manager", haveFieldManager)
}

type fakeEncryptionStatusClient struct {
	applyFn func(ctx context.Context, fieldManager string, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error
}

func (f *fakeEncryptionStatusClient) GetKMSEncryptionStatus(_ context.Context) (*operatorv1.KMSEncryptionStatus, error) {
	return &operatorv1.KMSEncryptionStatus{}, nil
}

func (f *fakeEncryptionStatusClient) ApplyKMSEncryptionStatus(ctx context.Context, fieldManager string, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
	return f.applyFn(ctx, fieldManager, status)
}

func (f *fakeEncryptionStatusClient) UpdateKMSEncryptionStatus(_ context.Context, _ func(*operatorv1.KMSEncryptionStatus)) error {
	return nil
}

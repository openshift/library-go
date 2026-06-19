package health

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	kmsservice "k8s.io/kms/pkg/service"
)

// validOptions returns an options value that passes validate. Each test case
// mutates a single field so the failure under test is unambiguous.
func validOptions() *options {
	return &options{
		KMSSockets:   []string{"unix:///var/run/kmsplugin/kms-1.sock"},
		Interval:     30 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		NodeName:     "node-1",
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*options)
		wantErr bool
	}{
		{
			name:   "valid",
			mutate: func(*options) {},
		},
		{
			name:    "no sockets",
			mutate:  func(o *options) { o.KMSSockets = nil },
			wantErr: true,
		},
		{
			name:    "empty socket entry",
			mutate:  func(o *options) { o.KMSSockets = []string{""} },
			wantErr: true,
		},
		{
			name:   "multiple valid sockets",
			mutate: func(o *options) { o.KMSSockets = append(o.KMSSockets, "unix:///var/run/kmsplugin/kms-2.sock") },
		},
		{
			name:    "duplicate sockets",
			mutate:  func(o *options) { o.KMSSockets = append(o.KMSSockets, o.KMSSockets[0]) },
			wantErr: true,
		},
		{
			name:    "socket missing unix scheme",
			mutate:  func(o *options) { o.KMSSockets = []string{"/var/run/kmsplugin/kms-1.sock"} },
			wantErr: true,
		},
		{
			name:    "socket scheme without path",
			mutate:  func(o *options) { o.KMSSockets = []string{"unix://"} },
			wantErr: true,
		},
		{
			name:    "socket wrong directory",
			mutate:  func(o *options) { o.KMSSockets = []string{"unix:///tmp/kms-1.sock"} },
			wantErr: true,
		},
		{
			name:    "socket non-numeric index",
			mutate:  func(o *options) { o.KMSSockets = []string{"unix:///var/run/kmsplugin/kms-x.sock"} },
			wantErr: true,
		},
		{
			name:    "socket missing .sock suffix",
			mutate:  func(o *options) { o.KMSSockets = []string{"unix:///var/run/kmsplugin/kms-1"} },
			wantErr: true,
		},
		{
			name:    "socket with surrounding whitespace",
			mutate:  func(o *options) { o.KMSSockets = []string{" unix:///var/run/kmsplugin/kms-1.sock "} },
			wantErr: true,
		},
		{
			name:    "interval zero",
			mutate:  func(o *options) { o.Interval = 0 },
			wantErr: true,
		},
		{
			name:    "interval negative",
			mutate:  func(o *options) { o.Interval = -time.Second },
			wantErr: true,
		},
		{
			name:    "read timeout zero",
			mutate:  func(o *options) { o.ReadTimeout = 0 },
			wantErr: true,
		},
		{
			name:    "write timeout zero",
			mutate:  func(o *options) { o.WriteTimeout = 0 },
			wantErr: true,
		},
		{
			name:    "node name empty",
			mutate:  func(o *options) { o.NodeName = "" },
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := validOptions()
			tc.mutate(o)

			err := o.validate()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestRunReportsOnce checks the loop wiring: Run probes, builds the status, and
// hands it to the reporter. The reporter cancels the context so the loop ends
// after a single tick.
func TestRunReportsOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var have *applyoperatorv1.KMSEncryptionStatusApplyConfiguration
	c := &Config{
		nodeName:     "node-1",
		interval:     time.Hour, // never reached; cancelled after the first tick
		writeTimeout: time.Second,
		prober: &prober{
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

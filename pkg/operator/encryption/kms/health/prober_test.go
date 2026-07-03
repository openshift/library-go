package health

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	kmsservice "k8s.io/kms/pkg/service"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
)

type fakeService struct {
	resp *kmsservice.StatusResponse
	err  error
}

func (f *fakeService) Status(context.Context) (*kmsservice.StatusResponse, error) {
	return f.resp, f.err
}

func (f *fakeService) Encrypt(context.Context, string, []byte) (*kmsservice.EncryptResponse, error) {
	return nil, nil
}

func (f *fakeService) Decrypt(context.Context, string, *kmsservice.DecryptRequest) ([]byte, error) {
	return nil, nil
}

func TestProber_ProbeAll(t *testing.T) {
	fixed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	p := &prober{
		nodeName: "node-1",
		plugins: []pluginClient{
			{keyID: "1", service: &fakeService{resp: &kmsservice.StatusResponse{Healthz: "ok", KeyID: "kek-abc"}}},
			{keyID: "2", service: &fakeService{err: fmt.Errorf("connection refused")}},
			{keyID: "3", service: &fakeService{resp: &kmsservice.StatusResponse{Healthz: "degraded"}}},
			{keyID: "4", service: &fakeService{}},
		},
		now: func() time.Time { return fixed },
	}

	have := p.probeAll(context.Background())

	// Each entry stamps nodeName; kekId only on healthy, detail only on the
	// unhealthy/error entries, status mapped to the API enum.
	want := applyoperatorv1.KMSEncryptionStatus().WithHealthReports(
		applyoperatorv1.KMSPluginHealthReport().
			WithNodeName("node-1").
			WithKeyId("1").
			WithStatus(operatorv1.KMSPluginHealthStatusHealthy).
			WithLastCheckedTime(metav1.NewTime(fixed)).
			WithKEKId("kek-abc"),
		applyoperatorv1.KMSPluginHealthReport().
			WithNodeName("node-1").
			WithKeyId("2").
			WithStatus(operatorv1.KMSPluginHealthStatusError).
			WithLastCheckedTime(metav1.NewTime(fixed)).
			WithDetail("connection refused"),
		applyoperatorv1.KMSPluginHealthReport().
			WithNodeName("node-1").
			WithKeyId("3").
			WithStatus(operatorv1.KMSPluginHealthStatusUnhealthy).
			WithLastCheckedTime(metav1.NewTime(fixed)).
			WithDetail("degraded"),
		applyoperatorv1.KMSPluginHealthReport().
			WithNodeName("node-1").
			WithKeyId("4").
			WithStatus(operatorv1.KMSPluginHealthStatusError).
			WithLastCheckedTime(metav1.NewTime(fixed)).
			WithDetail("kms plugin returned nil status response"),
	)

	require.Equal(t, want, have)
}

// blockingService releases Status only once all expected probes have
// arrived, so the test passes only if probeAll runs them concurrently.
type blockingService struct {
	*fakeService
	barrier *sync.WaitGroup
}

func (b *blockingService) Status(ctx context.Context) (*kmsservice.StatusResponse, error) {
	b.barrier.Done()
	b.barrier.Wait()
	return b.fakeService.Status(ctx)
}

func TestProber_ProbeAllFansOut(t *testing.T) {
	const n = 3
	var barrier sync.WaitGroup
	barrier.Add(n)

	plugins := make([]pluginClient, 0, n)
	for i := range n {
		keyID := strconv.Itoa(i + 1)
		plugins = append(plugins, pluginClient{
			keyID: keyID,
			service: &blockingService{
				fakeService: &fakeService{resp: &kmsservice.StatusResponse{Healthz: "ok", KeyID: "kek-" + keyID}},
				barrier:     &barrier,
			},
		})
	}
	p := newProber("node-1", plugins)

	done := make(chan *applyoperatorv1.KMSEncryptionStatusApplyConfiguration, 1)
	go func() { done <- p.probeAll(context.Background()) }()

	select {
	case have := <-done:
		for i, report := range have.HealthReports {
			want := strconv.Itoa(i + 1)
			if *report.KeyId != want || *report.KEKId != "kek-"+want {
				t.Errorf("reports[%d] = {KeyId:%q KEKId:%q}, want {KeyId:%q KEKId:%q}",
					i, *report.KeyId, *report.KEKId, want, "kek-"+want)
			}
		}
	case <-time.After(wait.ForeverTestTimeout):
		t.Fatal("probeAll timed out: probes ran sequentially or deadlocked")
	}
}

func Test_keyIDFromSocket(t *testing.T) {
	tests := []struct {
		socket  string
		want    string
		wantErr bool
	}{
		{socket: "unix:///var/run/kmsplugin/kms-1.sock", want: "1"},
		{socket: "unix:///var/run/kmsplugin/kms-42.sock", want: "42"},
		{socket: "unix:///var/run/kmsplugin/plugin.sock", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.socket, func(t *testing.T) {
			have, err := keyIDFromSocket(tt.socket)
			if (err != nil) != tt.wantErr {
				t.Fatalf("keyIDFromSocket(%q) err = %v, wantErr %v", tt.socket, err, tt.wantErr)
			}
			if have != tt.want {
				t.Errorf("keyIDFromSocket(%q) = %q, want %q", tt.socket, have, tt.want)
			}
		})
	}
}

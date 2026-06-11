package health

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	kmsservice "k8s.io/kms/pkg/service"
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
		plugins: []pluginClient{
			{keyID: "1", service: &fakeService{resp: &kmsservice.StatusResponse{Healthz: "ok", KeyID: "kek-abc"}}},
			{keyID: "2", service: &fakeService{err: fmt.Errorf("connection refused")}},
			{keyID: "3", service: &fakeService{resp: &kmsservice.StatusResponse{Healthz: "degraded"}}},
			{keyID: "4", service: &fakeService{}},
		},
		now: func() time.Time { return fixed },
	}

	have := p.probeAll(context.Background())
	want := []pluginHealthReport{
		{KeyID: "1", KEKID: "kek-abc", Status: "healthy", LastChecked: fixed},
		{KeyID: "2", Status: "error", Detail: "connection refused", LastChecked: fixed},
		{KeyID: "3", Status: "unhealthy", Detail: "degraded", LastChecked: fixed},
		{KeyID: "4", Status: "error", Detail: "kms plugin returned nil status response", LastChecked: fixed},
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("probeAll():\n have: %+v\n want: %+v", have, want)
	}
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
	p := newProber(plugins)

	done := make(chan []pluginHealthReport, 1)
	go func() { done <- p.probeAll(context.Background()) }()

	select {
	case have := <-done:
		for i, report := range have {
			want := strconv.Itoa(i + 1)
			if report.KeyID != want || report.KEKID != "kek-"+want {
				t.Errorf("reports[%d] = {KeyID:%q KEKID:%q}, want {KeyID:%q KEKID:%q}",
					i, report.KeyID, report.KEKID, want, "kek-"+want)
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

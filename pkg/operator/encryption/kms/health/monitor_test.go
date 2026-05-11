package health

import (
	"context"
	"errors"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	kmsservice "k8s.io/kms/pkg/service"
)

type stubKMSService struct {
	resp *kmsservice.StatusResponse
	err  error
}

func (s *stubKMSService) Status(ctx context.Context) (*kmsservice.StatusResponse, error) {
	return s.resp, s.err
}
func (s *stubKMSService) Encrypt(ctx context.Context, uid string, plaintext []byte) (*kmsservice.EncryptResponse, error) {
	return nil, errors.New("not used")
}
func (s *stubKMSService) Decrypt(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error) {
	return nil, errors.New("not used")
}

func newTestMonitor(interval time.Duration) (*Monitor, v1helpers.OperatorClient) {
	svc := &stubKMSService{resp: &kmsservice.StatusResponse{Healthz: "ok", KeyID: "k1"}}
	client := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil)
	writer := NewOperatorConditionWriter(client, "test-pod")
	return NewMonitor(NewProbe(svc, time.Second), writer, "test-pod", interval, time.Second), client
}

func TestMonitor_tickProbesAndWrites(t *testing.T) {
	m, client := newTestMonitor(time.Second)
	m.tick(context.Background())

	_, status, _, _ := client.GetOperatorState()
	if len(status.Conditions) == 0 {
		t.Fatal("no conditions written after tick")
	}
}

func TestMonitor_runStopsOnContextCancel(t *testing.T) {
	m, _ := newTestMonitor(10 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Monitor did not stop within 2s of context cancel")
	}
}

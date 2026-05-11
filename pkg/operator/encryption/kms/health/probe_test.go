package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	kmsservice "k8s.io/kms/pkg/service"
)

type fakeService struct {
	StatusFn func(ctx context.Context) (*kmsservice.StatusResponse, error)
}

func (f *fakeService) Status(ctx context.Context) (*kmsservice.StatusResponse, error) {
	return f.StatusFn(ctx)
}
func (f *fakeService) Encrypt(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
	panic("Encrypt not expected")
}
func (f *fakeService) Decrypt(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error) {
	panic("Decrypt not expected")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestProbe_healthy(t *testing.T) {
	fake := &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			return &kmsservice.StatusResponse{Healthz: "ok", Version: "v2", KeyID: "test-key-1"}, nil
		},
	}
	got := NewProbe(fake, time.Second).Probe(context.Background())

	if !got.Healthz.IsOK() {
		t.Errorf("Healthz: got %q, want IsOK", got.Healthz)
	}
	if got.KeyIDHash != sha256Hex("test-key-1") {
		t.Errorf("KeyIDHash mismatch")
	}
	if got.Timestamp.IsZero() {
		t.Error("Timestamp: expected non-zero")
	}
}

func TestProbe_notOK(t *testing.T) {
	fake := &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			return &kmsservice.StatusResponse{Healthz: "not-ready", KeyID: "test-key-1"}, nil
		},
	}
	got := NewProbe(fake, time.Second).Probe(context.Background())

	want := Healthz{Class: HealthClassNotOK, Detail: "not-ready"}
	if got.Healthz != want {
		t.Errorf("Healthz: got %q, want %q", got.Healthz, want)
	}
}

// Naive byte-slicing at healthzMaxBodyLen would split a multi-byte rune;
// apiserver rejects Condition.Message containing invalid UTF-8 and would
// freeze the published status. The 198 + 4-byte emoji + tail boundary
// targets that exact slice point.
func TestProbe_notOK_truncatesSafelyAtMultiByteBoundary(t *testing.T) {
	body := strings.Repeat("x", 198) + "👍" + "tail"
	fake := &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			return &kmsservice.StatusResponse{Healthz: body, KeyID: "test-key-1"}, nil
		},
	}
	got := NewProbe(fake, time.Second).Probe(context.Background())

	if !utf8.ValidString(got.Healthz.Detail) {
		t.Errorf("Healthz detail is not valid UTF-8: %q", got.Healthz.Detail)
	}
	if len(got.Healthz.Detail) > healthzMaxBodyLen {
		t.Errorf("Healthz detail too long: got %d bytes, want <= %d", len(got.Healthz.Detail), healthzMaxBodyLen)
	}
}

func TestProbe_respectsPerProbeTimeout(t *testing.T) {
	fake := &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		},
	}
	probe := NewProbe(fake, 20*time.Millisecond)

	start := time.Now()
	got := probe.Probe(context.Background())
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("probe elapsed %v: per-probe timeout not applied", elapsed)
	}
	want := Healthz{Class: HealthClassRPCError, Detail: "DeadlineExceeded"}
	if got.Healthz != want {
		t.Errorf("Healthz: got %q, want %q", got.Healthz, want)
	}
}

func TestProbe_rpcError_classifiesNonGRPCAsUnknown(t *testing.T) {
	fake := &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			return nil, errors.New("connection refused")
		},
	}
	got := NewProbe(fake, time.Second).Probe(context.Background())

	want := Healthz{Class: HealthClassRPCError, Detail: codes.Unknown.String()}
	if got.Healthz != want {
		t.Errorf("Healthz: got %q, want %q", got.Healthz, want)
	}
	if got.KeyIDHash != "" {
		t.Errorf("KeyIDHash: got %q, want empty on unreachable plugin", got.KeyIDHash)
	}
}

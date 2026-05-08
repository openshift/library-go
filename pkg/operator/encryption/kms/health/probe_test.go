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

// testTimeout is a generous per-probe timeout for fast-fake tests that
// should never hit it. Tests that DO exercise the deadline path use a
// short timeout locally.
const testTimeout = 10 * time.Second

// fakeService injects scripted Status responses. Same shape as
// preflight's fake (checker_test.go:14-30) — only StatusFn is exercised
// here because the Probe never calls Encrypt/Decrypt.
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
			return &kmsservice.StatusResponse{
				Healthz: "ok",
				Version: "v2",
				KeyID:   "test-key-1",
			}, nil
		},
	}

	probe := NewProbe(fake, testTimeout)
	got := probe.Probe(context.Background())

	if !got.Healthz.IsOK() {
		t.Errorf("Healthz: got %q, want IsOK", got.Healthz)
	}
	wantHash := sha256Hex("test-key-1")
	if got.KeyIDHash != wantHash {
		t.Errorf("KeyIDHash: got %q, want %q", got.KeyIDHash, wantHash)
	}
	if got.Timestamp.IsZero() {
		t.Error("Timestamp: expected non-zero")
	}
}

func TestProbe_notOk_classifiesAsUnhealthy(t *testing.T) {
	fake := &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			return &kmsservice.StatusResponse{
				Healthz: "not-ready",
				KeyID:   "test-key-1",
			}, nil
		},
	}

	got := NewProbe(fake, testTimeout).Probe(context.Background())

	want := Healthz{Class: HealthClassNotOK, Detail: "not-ready"}
	if got.Healthz != want {
		t.Errorf("Healthz: got %q, want %q", got.Healthz, want)
	}
}

func TestProbe_notOk_truncatesTo200Chars(t *testing.T) {
	// 260-char ASCII body — exercise the byte-length cap.
	longBody := strings.Repeat("x", 260)
	fake := &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			return &kmsservice.StatusResponse{
				Healthz: longBody,
				KeyID:   "test-key-1",
			}, nil
		},
	}

	got := NewProbe(fake, testTimeout).Probe(context.Background())

	if got.Healthz.Class != HealthClassNotOK {
		t.Errorf("Healthz class: got %q, want %q", got.Healthz.Class, HealthClassNotOK)
	}
	if len(got.Healthz.Detail) != healthzMaxBodyLen {
		t.Errorf("Healthz detail length: got %d, want %d", len(got.Healthz.Detail), healthzMaxBodyLen)
	}
}

func TestProbe_notOk_truncatesSafelyAtMultiByteBoundary(t *testing.T) {
	// 198 ASCII bytes + thumbs-up emoji (4 bytes) + tail. Naive byte-
	// slicing at healthzMaxBodyLen=200 would land between bytes 2 and 3
	// of the emoji, producing invalid UTF-8 — apiserver rejects
	// ConfigMap Updates with invalid UTF-8 in cm.Data values, which
	// would freeze the published status indefinitely.
	body := strings.Repeat("x", 198) + "👍" + "tail"
	fake := &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			return &kmsservice.StatusResponse{
				Healthz: body,
				KeyID:   "test-key-1",
			}, nil
		},
	}

	got := NewProbe(fake, testTimeout).Probe(context.Background())

	if !utf8.ValidString(got.Healthz.Detail) {
		t.Errorf("Healthz detail is not valid UTF-8: %q", got.Healthz.Detail)
	}
	if len(got.Healthz.Detail) > healthzMaxBodyLen {
		t.Errorf("Healthz detail too long: got %d bytes, want <= %d", len(got.Healthz.Detail), healthzMaxBodyLen)
	}
}

func TestProbe_respectsPerProbeTimeout(t *testing.T) {
	// Fake blocks until ctx fires; Probe's own WithTimeout should cut it
	// off after probeTimeout. The fake wraps ctx.Err() exactly the way
	// gRPC's transport does in production (status.FromContextError), so
	// classification sees DeadlineExceeded.
	fake := &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		},
	}

	const probeTimeout = 20 * time.Millisecond
	probe := NewProbe(fake, probeTimeout)

	start := time.Now()
	// Parent context has NO deadline — if Probe doesn't apply its own
	// timeout, this test hangs and we'd notice via go test -timeout.
	got := probe.Probe(context.Background())
	elapsed := time.Since(start)

	// Budget: probeTimeout + generous slack for CI. If we see >1s we're
	// honoring the parent ctx instead of our own timeout.
	if elapsed > 500*time.Millisecond {
		t.Errorf("probe elapsed %v — per-probe timeout not applied", elapsed)
	}
	want := Healthz{Class: HealthClassRPCError, Detail: "DeadlineExceeded"}
	if got.Healthz != want {
		t.Errorf("Healthz: got %q, want %q", got.Healthz, want)
	}
}

func TestProbe_rpcError(t *testing.T) {
	// The real k8senvelopekmsv2 client returns status errors from gRPC
	// calls; generic (non-status) errors are treated by grpc/status as code
	// Unknown. See vendor/google.golang.org/grpc/status/status.go.
	scenarios := []struct {
		name     string
		fakeErr  error
		wantCode string
	}{
		{
			name:     "generic non-gRPC error classifies as Unknown",
			fakeErr:  errors.New("connection refused"),
			wantCode: "Unknown",
		},
		{
			name:     "gRPC Unavailable propagates through classification",
			fakeErr:  status.Error(codes.Unavailable, "server gone"),
			wantCode: "Unavailable",
		},
		{
			name:     "gRPC DeadlineExceeded propagates through classification",
			fakeErr:  status.Error(codes.DeadlineExceeded, "too slow"),
			wantCode: "DeadlineExceeded",
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeService{
				StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
					return nil, tc.fakeErr
				},
			}

			got := NewProbe(fake, testTimeout).Probe(context.Background())

			want := Healthz{Class: HealthClassRPCError, Detail: tc.wantCode}
			if got.Healthz != want {
				t.Errorf("Healthz: got %q, want %q", got.Healthz, want)
			}
			if got.KeyIDHash != "" {
				t.Errorf("KeyIDHash: got %q, want empty (unreachable plugin)", got.KeyIDHash)
			}
			if got.Timestamp.IsZero() {
				t.Error("Timestamp: expected non-zero even on RPC error")
			}
		})
	}
}

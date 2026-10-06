package preflight

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	kmsservice "k8s.io/kms/pkg/service"
)

type fakeService struct {
	StatusFn  func(ctx context.Context) (*kmsservice.StatusResponse, error)
	EncryptFn func(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error)
	DecryptFn func(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error)
}

func (f *fakeService) Status(ctx context.Context) (*kmsservice.StatusResponse, error) {
	return f.StatusFn(ctx)
}

func (f *fakeService) Encrypt(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
	return f.EncryptFn(ctx, uid, data)
}

func (f *fakeService) Decrypt(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error) {
	return f.DecryptFn(ctx, uid, req)
}

func newTestChecker(service *fakeService) *checker {
	return &checker{
		service: service,
		// deterministic reader so encrypt/decrypt assertions are predictable
		randReader: bytes.NewReader(bytes.Repeat([]byte{0xAB}, 32)),
		// short values to keep tests fast while still exercising the retry loop
		statusTimeout:  100 * time.Millisecond,
		statusInterval: 10 * time.Millisecond,
	}
}

func healthyFakeService() *fakeService {
	var plaintext []byte
	return &fakeService{
		StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
			return &kmsservice.StatusResponse{Healthz: "ok", Version: "v2", KeyID: "key-1"}, nil
		},
		EncryptFn: func(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
			plaintext = data
			return &kmsservice.EncryptResponse{Ciphertext: []byte("ciphertext"), KeyID: "key-1"}, nil
		},
		DecryptFn: func(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error) {
			return plaintext, nil
		},
	}
}

func TestCheckInternal(t *testing.T) {
	scenarios := []struct {
		name      string
		service   *fakeService
		expectErr string
	}{
		{
			name:    "happy path",
			service: healthyFakeService(),
		},
		{
			name: "healthy after transient status error",
			service: func() *fakeService {
				svc := healthyFakeService()
				callCount := 0
				svc.StatusFn = func(ctx context.Context) (*kmsservice.StatusResponse, error) {
					callCount++
					if callCount == 1 {
						return nil, fmt.Errorf("connection refused")
					}
					return &kmsservice.StatusResponse{Healthz: "ok", Version: "v2", KeyID: "key-1"}, nil
				}
				return svc
			}(),
		},
		{
			name: "persistent status error exceeds timeout",
			service: &fakeService{
				StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
					return nil, fmt.Errorf("connection refused")
				},
			},
			expectErr: "connection refused",
		},
		{
			name: "persistent unhealthy status exceeds timeout",
			service: &fakeService{
				StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
					return &kmsservice.StatusResponse{Healthz: "not-ready"}, nil
				},
			},
			expectErr: "last status: healthz=\"not-ready\"",
		},
		{
			name: "encrypt error",
			service: &fakeService{
				StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
					return &kmsservice.StatusResponse{Healthz: "ok", Version: "v2", KeyID: "key-1"}, nil
				},
				EncryptFn: func(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
					return nil, fmt.Errorf("key not found")
				},
			},
			expectErr: "encrypt call failed",
		},
		{
			name: "encrypt returns plaintext unchanged",
			service: &fakeService{
				StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
					return &kmsservice.StatusResponse{Healthz: "ok", Version: "v2", KeyID: "key-1"}, nil
				},
				EncryptFn: func(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
					return &kmsservice.EncryptResponse{Ciphertext: data, KeyID: "key-1"}, nil
				},
			},
			expectErr: "encrypt returned plaintext unchanged",
		},
		{
			name: "decrypt error",
			service: &fakeService{
				StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
					return &kmsservice.StatusResponse{Healthz: "ok", Version: "v2", KeyID: "key-1"}, nil
				},
				EncryptFn: func(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
					return &kmsservice.EncryptResponse{Ciphertext: []byte("ciphertext"), KeyID: "key-1"}, nil
				},
				DecryptFn: func(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error) {
					return nil, fmt.Errorf("decryption failed")
				},
			},
			expectErr: "decrypt call failed",
		},
		{
			name: "decrypt roundtrip mismatch",
			service: &fakeService{
				StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
					return &kmsservice.StatusResponse{Healthz: "ok", Version: "v2", KeyID: "key-1"}, nil
				},
				EncryptFn: func(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
					return &kmsservice.EncryptResponse{Ciphertext: []byte("ciphertext"), KeyID: "key-1"}, nil
				},
				DecryptFn: func(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error) {
					return []byte("wrong-plaintext"), nil
				},
			},
			expectErr: "decrypt roundtrip mismatch",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			target := newTestChecker(scenario.service)

			status, err := target.checkInternal(context.Background())

			if scenario.expectErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if scenario.expectErr != "" && (err == nil || !strings.Contains(err.Error(), scenario.expectErr)) {
				t.Fatalf("expected error containing %q, got: %v", scenario.expectErr, err)
			}
			if scenario.expectErr == "" && status == nil {
				t.Fatal("expected status on success")
			}
			if scenario.expectErr == "" && status.KeyID != "key-1" {
				t.Fatalf("expected keyID key-1, got %q", status.KeyID)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	svc := healthyFakeService()
	originalEncrypt := svc.EncryptFn
	encryptCalls := 0
	svc.EncryptFn = func(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
		encryptCalls++
		if encryptCalls == 1 {
			return nil, fmt.Errorf("temporary network error")
		}
		return originalEncrypt(ctx, uid, data)
	}

	checker := newTestChecker(svc)
	checker.randReader = bytes.NewReader(bytes.Repeat([]byte{0xAB}, 64))
	if _, err := checker.check(context.Background()); err != nil {
		t.Fatalf("expected second attempt to succeed: %v", err)
	}
	if encryptCalls != 2 {
		t.Fatalf("expected two encrypt calls, got %d", encryptCalls)
	}
}

func TestCheckReturnsLastError(t *testing.T) {
	svc := healthyFakeService()
	calls := 0
	svc.EncryptFn = func(context.Context, string, []byte) (*kmsservice.EncryptResponse, error) {
		calls++
		return nil, fmt.Errorf("encrypt error %d", calls)
	}

	checker := newTestChecker(svc)
	checker.randReader = bytes.NewReader(bytes.Repeat([]byte{0xAB}, 64))
	_, err := checker.check(context.Background())
	if calls != 2 || err == nil || !strings.Contains(err.Error(), "encrypt error 2") {
		t.Fatalf("expected the second encrypt error after two attempts, got %d attempts and %v", calls, err)
	}
}

func TestCheckStatusErrorReporting(t *testing.T) {
	connectionErr := errors.New("connection refused")
	tests := []struct {
		name            string
		caller          string
		statusErr       error
		statusResponse  *kmsservice.StatusResponse
		statusTimeout   time.Duration
		statusInterval  time.Duration
		wantErr         error
		wantErrContains string
		wantStatusCalls int
	}{
		{
			name:            "unreachable KMS, caller active",
			caller:          "active",
			statusErr:       connectionErr,
			statusTimeout:   100 * time.Millisecond,
			statusInterval:  time.Second,
			wantErr:         connectionErr,
			wantStatusCalls: 2,
		},
		{
			name:            "unhealthy KMS, caller active",
			caller:          "active",
			statusResponse:  &kmsservice.StatusResponse{Healthz: "not-ready", Version: "v2", KeyID: "key-1"},
			statusTimeout:   100 * time.Millisecond,
			statusInterval:  time.Second,
			wantErrContains: `last status: healthz="not-ready", version="v2", keyID="key-1"`,
			wantStatusCalls: 2,
		},
		{
			name:            "caller canceled before check",
			caller:          "canceled before call",
			wantErr:         context.Canceled,
			wantStatusCalls: 0,
		},
		{
			name:            "caller canceled after status error",
			caller:          "cancel on status",
			statusErr:       connectionErr,
			wantErr:         context.Canceled,
			wantStatusCalls: 1,
		},
		{
			name:            "caller deadline during status call",
			caller:          "deadline during status",
			statusErr:       connectionErr,
			statusTimeout:   time.Second,
			wantErr:         context.DeadlineExceeded,
			wantStatusCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if tt.caller == "deadline during status" {
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			if tt.caller == "canceled before call" {
				cancel()
			}

			statusCalls := 0
			svc := &fakeService{
				StatusFn: func(callCtx context.Context) (*kmsservice.StatusResponse, error) {
					statusCalls++
					if tt.caller == "deadline during status" {
						<-callCtx.Done()
					}
					if tt.caller == "cancel on status" {
						cancel()
					}
					if tt.statusErr != nil {
						return nil, tt.statusErr
					}
					if tt.statusResponse != nil {
						return tt.statusResponse, nil
					}
					return &kmsservice.StatusResponse{Healthz: "ok"}, nil
				},
			}
			checker := newTestChecker(svc)
			if tt.statusTimeout > 0 {
				checker.statusTimeout = tt.statusTimeout
			}
			if tt.statusInterval > 0 {
				checker.statusInterval = tt.statusInterval
			}

			status, err := checker.check(ctx)
			if status != nil || err == nil || (tt.wantErr != nil && !errors.Is(err, tt.wantErr)) || statusCalls != tt.wantStatusCalls {
				t.Fatalf("got status %+v, error %v, status calls %d; want nil status, error matching %v, status calls %d",
					status, err, statusCalls, tt.wantErr, tt.wantStatusCalls)
			}
			if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErrContains)
			}
		})
	}
}

func TestCheckCancellationDuringLastAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := healthyFakeService()
	calls := 0
	svc.EncryptFn = func(context.Context, string, []byte) (*kmsservice.EncryptResponse, error) {
		calls++
		if calls == 2 {
			cancel()
		}
		return nil, fmt.Errorf("temporary network error")
	}

	checker := newTestChecker(svc)
	checker.randReader = bytes.NewReader(bytes.Repeat([]byte{0xAB}, 64))
	_, err := checker.check(ctx)
	if calls != 2 || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation during the second attempt, got %d attempts and %v", calls, err)
	}
}

func TestCheckCancellationBeforeRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := healthyFakeService()
	calls := 0
	svc.EncryptFn = func(context.Context, string, []byte) (*kmsservice.EncryptResponse, error) {
		calls++
		cancel()
		return nil, fmt.Errorf("temporary network error")
	}

	_, err := newTestChecker(svc).check(ctx)
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation before retry, got %d attempts and %v", calls, err)
	}
}

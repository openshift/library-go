package preflight

import (
	"bytes"
	"context"
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
			expectErr: "context deadline exceeded",
		},
		{
			name: "persistent unhealthy status exceeds timeout",
			service: &fakeService{
				StatusFn: func(ctx context.Context) (*kmsservice.StatusResponse, error) {
					return &kmsservice.StatusResponse{Healthz: "not-ready"}, nil
				},
			},
			expectErr: "context deadline exceeded",
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
	if calls != 2 || err != context.Canceled {
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
	if calls != 1 || err != context.Canceled {
		t.Fatalf("expected cancellation before retry, got %d attempts and %v", calls, err)
	}
}

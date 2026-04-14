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

func TestCheck(t *testing.T) {
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

			err := target.check(context.Background())

			if scenario.expectErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if scenario.expectErr != "" && (err == nil || !strings.Contains(err.Error(), scenario.expectErr)) {
				t.Fatalf("expected error containing %q, got: %v", scenario.expectErr, err)
			}
		})
	}
}

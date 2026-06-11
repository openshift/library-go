package preflight

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	kmsapi "k8s.io/kms/apis/v2"
)

type mockPlugin struct {
	kmsapi.UnimplementedKeyManagementServiceServer
	StatusFn  func(context.Context, *kmsapi.StatusRequest) (*kmsapi.StatusResponse, error)
	EncryptFn func(context.Context, *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error)
	DecryptFn func(context.Context, *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error)
}

func (m *mockPlugin) Status(ctx context.Context, req *kmsapi.StatusRequest) (*kmsapi.StatusResponse, error) {
	return m.StatusFn(ctx, req)
}

func (m *mockPlugin) Encrypt(ctx context.Context, req *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
	return m.EncryptFn(ctx, req)
}

func (m *mockPlugin) Decrypt(ctx context.Context, req *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
	return m.DecryptFn(ctx, req)
}

func healthyPlugin() *mockPlugin {
	return &mockPlugin{
		StatusFn: func(context.Context, *kmsapi.StatusRequest) (*kmsapi.StatusResponse, error) {
			return &kmsapi.StatusResponse{Healthz: "ok", Version: "v2", KeyId: "key-1"}, nil
		},
		EncryptFn: func(_ context.Context, req *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
			ciphertext := []byte(base64.StdEncoding.EncodeToString(req.Plaintext))
			return &kmsapi.EncryptResponse{Ciphertext: ciphertext, KeyId: "key-1"}, nil
		},
		DecryptFn: func(_ context.Context, req *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
			plaintext, err := base64.StdEncoding.DecodeString(string(req.Ciphertext))
			if err != nil {
				return nil, err
			}
			return &kmsapi.DecryptResponse{Plaintext: plaintext}, nil
		},
	}
}

func startMockPlugin(t *testing.T, plugin kmsapi.KeyManagementServiceServer) string {
	t.Helper()
	endpoint, sockPath := tempSocket(t)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	server := grpc.NewServer()
	kmsapi.RegisterKeyManagementServiceServer(server, plugin)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	return endpoint
}

// os.MkdirTemp, not t.TempDir: the latter embeds the long subtest name and
// unix socket paths are capped at ~108 bytes.
func tempSocket(t *testing.T) (endpoint, sockPath string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kms-preflight")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath = filepath.Join(dir, "kms.sock")
	return "unix://" + sockPath, sockPath
}

func testOptions(endpoint string) *options {
	return &options{
		kmsCallTimeout: 5 * time.Second,
		endpoint:       endpoint,
		// short so the status-poll cases fail in well under a second
		statusTimeout:  200 * time.Millisecond,
		statusInterval: 20 * time.Millisecond,
	}
}

// TestRunE2E covers run()'s wiring over a real socket, independently of where checker lives.
func TestRunE2E(t *testing.T) {
	tests := []struct {
		name string
		// plugin nil means: start no server, point run() at a dead socket.
		plugin    *mockPlugin
		expectErr string
	}{
		{
			name:   "happy path",
			plugin: healthyPlugin(),
		},
		{
			name: "healthy after transient status error",
			plugin: func() *mockPlugin {
				p := healthyPlugin()
				var calls atomic.Int32
				p.StatusFn = func(context.Context, *kmsapi.StatusRequest) (*kmsapi.StatusResponse, error) {
					if calls.Add(1) == 1 {
						return nil, fmt.Errorf("connection refused")
					}
					return &kmsapi.StatusResponse{Healthz: "ok", Version: "v2", KeyId: "key-1"}, nil
				}
				return p
			}(),
		},
		{
			name: "persistent unhealthy status exceeds timeout",
			plugin: func() *mockPlugin {
				p := healthyPlugin()
				p.StatusFn = func(context.Context, *kmsapi.StatusRequest) (*kmsapi.StatusResponse, error) {
					return &kmsapi.StatusResponse{Healthz: "not-ready"}, nil
				}
				return p
			}(),
			expectErr: "context deadline exceeded",
		},
		{
			name: "encrypt error",
			plugin: func() *mockPlugin {
				p := healthyPlugin()
				p.EncryptFn = func(context.Context, *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
					return nil, fmt.Errorf("key not found")
				}
				return p
			}(),
			expectErr: "encrypt call failed",
		},
		{
			name: "encrypt returns plaintext unchanged",
			plugin: func() *mockPlugin {
				p := healthyPlugin()
				p.EncryptFn = func(_ context.Context, req *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
					return &kmsapi.EncryptResponse{Ciphertext: req.Plaintext, KeyId: "key-1"}, nil
				}
				return p
			}(),
			expectErr: "encrypt returned plaintext unchanged",
		},
		{
			name: "decrypt error",
			plugin: func() *mockPlugin {
				p := healthyPlugin()
				p.DecryptFn = func(context.Context, *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
					return nil, fmt.Errorf("decryption failed")
				}
				return p
			}(),
			expectErr: "decrypt call failed",
		},
		{
			name: "decrypt roundtrip mismatch",
			plugin: func() *mockPlugin {
				p := healthyPlugin()
				p.DecryptFn = func(context.Context, *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
					return &kmsapi.DecryptResponse{Plaintext: []byte("wrong-plaintext")}, nil
				}
				return p
			}(),
			expectErr: "decrypt roundtrip mismatch",
		},
		{
			name:      "dead socket exceeds timeout",
			plugin:    nil,
			expectErr: "context deadline exceeded",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var endpoint string
			if tc.plugin != nil {
				endpoint = startMockPlugin(t, tc.plugin)
			} else {
				endpoint, _ = tempSocket(t)
			}

			err := testOptions(endpoint).run(context.Background())

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.expectErr, err)
			}
		})
	}
}

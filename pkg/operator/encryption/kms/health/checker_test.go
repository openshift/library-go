package health

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

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

func TestChecker_CheckStatus(t *testing.T) {
	fixed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &Checker{
		plugins: []plugin{
			{keyID: "1", service: &fakeService{resp: &kmsservice.StatusResponse{Healthz: "ok", KeyID: "kek-abc"}}},
			{keyID: "2", service: &fakeService{err: fmt.Errorf("connection refused")}},
			{keyID: "3", service: &fakeService{resp: &kmsservice.StatusResponse{Healthz: "degraded"}}},
		},
		now: func() time.Time { return fixed },
	}

	got := c.CheckStatus(context.Background())
	want := []PluginHealthCondition{
		{KeyID: "1", KEKID: "kek-abc", Status: "healthy", LastChecked: fixed},
		{KeyID: "2", Status: "error", Detail: "connection refused", LastChecked: fixed},
		{KeyID: "3", Status: "unhealthy", Detail: "degraded", LastChecked: fixed},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CheckStatus():\n got:  %+v\n want: %+v", got, want)
	}
}

func Test_keyIDFromSocket(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/var/run/kmsplugin/kms-1.sock", "1"},
		{"/var/run/kmsplugin/kms-2.sock", "2"},
		{"kms-42.sock", "42"},
		{"plugin.sock", "plugin"},
		{"/tmp/my-custom-provider.sock", "provider"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := keyIDFromSocket(tt.path); got != tt.want {
				t.Errorf("keyIDFromSocket(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

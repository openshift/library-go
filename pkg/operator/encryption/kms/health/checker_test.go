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
		{KeyID: "1", KEKID: "kek-abc", Status: StatusHealthy, LastChecked: fixed},
		{KeyID: "2", Status: StatusError, Detail: "connection refused", LastChecked: fixed},
		{KeyID: "3", Status: StatusUnhealthy, Detail: "degraded", LastChecked: fixed},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CheckStatus():\n got:  %+v\n want: %+v", got, want)
	}
}

func Test_keyIDFromEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		want     string
		wantErr  bool
	}{
		{"unix:///var/run/kmsplugin/kms-1.sock", "1", false},
		{"unix:///var/run/kmsplugin/kms-2.sock", "2", false},
		{"unix:///tmp/kms-42.sock", "42", false},
		{"unix:///var/run/kmsplugin/plugin.sock", "", true},
		{"/var/run/kmsplugin/kms-1.sock", "", true},
		{"tcp://localhost:8080", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			got, err := keyIDFromEndpoint(tt.endpoint)
			if (err != nil) != tt.wantErr {
				t.Errorf("keyIDFromEndpoint(%q) error = %v, wantErr %v", tt.endpoint, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("keyIDFromEndpoint(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

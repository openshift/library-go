package health

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	kmsservice "k8s.io/kms/pkg/service"
)

const (
	StatusHealthy   = "healthy"
	StatusUnhealthy = "unhealthy"
	StatusError     = "error"
)

type PluginHealthCondition struct {
	KeyID       string    `json:"keyID"`
	KEKID       string    `json:"kekID,omitempty"`
	Status      string    `json:"status"`
	LastChecked time.Time `json:"lastChecked"`
	Detail      string    `json:"detail,omitempty"`
}

type plugin struct {
	keyID   string
	service kmsservice.Service
}

type Checker struct {
	plugins []plugin
	now     func() time.Time
}

// NewChecker creates a Checker that probes KMS plugins at the given UDS endpoints.
// Each endpoint must be a unix:// URI matching the kmsEndpointFormat convention
// (e.g. "unix:///var/run/kmsplugin/kms-1.sock").
func NewChecker(ctx context.Context, endpoints []string, timeout time.Duration) (*Checker, error) {
	c := Checker{
		plugins: make([]plugin, 0, len(endpoints)),
		now:     time.Now,
	}

	for _, endpoint := range endpoints {
		keyID, err := keyIDFromEndpoint(endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
		}

		service, err := kms.NewGRPCService(ctx, endpoint, "kms-health-monitor", timeout)
		if err != nil {
			return nil, fmt.Errorf("dial KMS plugin at %q: %w", endpoint, err)
		}

		c.plugins = append(c.plugins, plugin{
			keyID:   keyID,
			service: service,
		})
	}

	return &c, nil
}

const udsScheme = "unix://"

// keyIDFromEndpoint extracts the numeric keyID from a KMS endpoint URI.
// The endpoint must follow the convention "unix:///var/run/kmsplugin/kms-{keyID}.sock".
func keyIDFromEndpoint(endpoint string) (string, error) {
	if !strings.HasPrefix(endpoint, udsScheme) {
		return "", fmt.Errorf("expected %s scheme", udsScheme)
	}
	socketPath := strings.TrimPrefix(endpoint, udsScheme)
	name := strings.TrimSuffix(filepath.Base(socketPath), filepath.Ext(socketPath))
	id, valid := state.NameToKeyID(name)
	if !valid {
		return "", fmt.Errorf("cannot extract numeric keyID from %q", name)
	}
	return fmt.Sprintf("%d", id), nil
}

func (c *Checker) CheckStatus(ctx context.Context) []PluginHealthCondition {
	conditions := make([]PluginHealthCondition, 0, len(c.plugins))

	for _, p := range c.plugins {
		cond := PluginHealthCondition{
			KeyID:       p.keyID,
			LastChecked: c.now(),
		}

		resp, err := p.service.Status(ctx)
		switch {
		case err != nil:
			cond.Status = StatusError
			cond.Detail = err.Error()
		case resp.Healthz == kms.HealthzOK:
			cond.Status = StatusHealthy
			cond.KEKID = resp.KeyID
		default:
			cond.Status = StatusUnhealthy
			cond.Detail = resp.Healthz
		}

		conditions = append(conditions, cond)
	}
	return conditions
}

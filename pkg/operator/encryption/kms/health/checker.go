package health

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	k8senvelopekmsv2 "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/kmsv2"
	kmsservice "k8s.io/kms/pkg/service"
)

type plugin struct {
	keyID   string
	service kmsservice.Service
}

type Checker struct {
	plugins []plugin
	now     func() time.Time
}

func NewChecker(ctx context.Context, udsPaths []string, timeout time.Duration) (*Checker, error) {
	c := Checker{
		plugins: make([]plugin, 0, len(udsPaths)),
		now:     time.Now,
	}

	for _, socket := range udsPaths {
		service, err := k8senvelopekmsv2.NewGRPCService(
			ctx,
			"unix://"+socket,
			providerName,
			timeout,
		)
		if err != nil {
			return nil, fmt.Errorf("dial KMS plugin at %q: %w", socket, err)
		}

		c.plugins = append(c.plugins, plugin{
			keyID:   keyIDFromSocket(socket),
			service: service,
		})
	}

	return &c, nil
}

func keyIDFromSocket(path string) string {
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if i := strings.LastIndex(name, "-"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// CheckStatus checks the KMS plugin health via UDS. It never reports an error,
// it encodes the error into a Condition.
func (c *Checker) CheckStatus(ctx context.Context) []PluginHealthCondition {
	conditions := make([]PluginHealthCondition, 0, len(c.plugins))

	// Safe to parallelise: each plugin probes an independent socket / has a unique index in slice.
	for _, p := range c.plugins {
		cond := PluginHealthCondition{
			KeyID:       p.keyID,
			LastChecked: c.now(),
		}

		resp, err := p.service.Status(ctx)
		switch {
		case err != nil:
			cond.Status = "error"
			cond.Detail = err.Error()
		case resp.Healthz == "ok":
			cond.Status = "healthy"
			cond.KEKID = resp.KeyID
		default:
			cond.Status = "unhealthy"
			cond.Detail = resp.Healthz
		}

		conditions = append(conditions, cond)
	}
	return conditions
}

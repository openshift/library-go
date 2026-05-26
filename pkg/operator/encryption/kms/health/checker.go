package health

import (
	"context"
	"fmt"
	"time"

	k8senvelopekmsv2 "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/kmsv2"
	kmsservice "k8s.io/kms/pkg/service"
)

type Checker struct {
	services []kmsservice.Service
	now      func() time.Time
}

func NewChecker(ctx context.Context, udsPaths []string, timeout time.Duration) (*Checker, error) {
	c := Checker{
		services: make([]kmsservice.Service, 0, len(udsPaths)),
		now:      time.Now,
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

		c.services = append(c.services, service)
	}

	return &c, nil
}

func (c *Checker) CheckStatus(ctx context.Context) error {
	for _, service := range c.services {
		_, err := service.Status(ctx)
		if err != nil {
			return fmt.Errorf("check kms plugin status: %w", err)
		}
	}
	return nil
}

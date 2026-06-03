package kms

import (
	"context"
	"time"

	k8senvelopekmsv2 "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/kmsv2"
	kmsservice "k8s.io/kms/pkg/service"
)

// HealthzOK is the value the KMS plugin returns when healthy.
// See https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/kms/apis/v2/api.proto#L39
const HealthzOK = "ok"

// NewGRPCService creates a KMS v2 gRPC service client connected to the given endpoint.
func NewGRPCService(ctx context.Context, endpoint, providerName string, timeout time.Duration) (kmsservice.Service, error) {
	return k8senvelopekmsv2.NewGRPCService(ctx, endpoint, providerName, timeout)
}

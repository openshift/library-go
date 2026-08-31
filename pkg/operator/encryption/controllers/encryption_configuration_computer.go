package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
)

// EncryptionConfigurationComputer computes the encryption configuration secret
// passed to the KMS preflight deployer right before it creates a new deployment.
type EncryptionConfigurationComputer interface {
	ComputeEncryptionConfiguration(ctx context.Context) (*corev1.Secret, error)
}

// NoopEncryptionConfigurationComputer is a placeholder EncryptionConfigurationComputer
// that returns nil until a real implementation is available.
type NoopEncryptionConfigurationComputer struct{}

var _ EncryptionConfigurationComputer = NoopEncryptionConfigurationComputer{}

func (NoopEncryptionConfigurationComputer) ComputeEncryptionConfiguration(_ context.Context) (*corev1.Secret, error) {
	return nil, nil
}

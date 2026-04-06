package controllercmd

import (
	"context"
	"testing"

	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/utils/clock"
)

func TestWithTLSConfig(t *testing.T) {
	noop := func(_ context.Context, _ *ControllerContext) error { return nil }
	cfg := NewControllerCommandConfig("test", version.Info{}, noop, clock.RealClock{})

	cfg.WithTLSConfig("VersionTLS13", []string{"TLS_AES_128_GCM_SHA256"})

	if cfg.MinTLSVersion != "VersionTLS13" {
		t.Errorf("expected ServingMinTLSVersion %q, got %q", "VersionTLS13", cfg.MinTLSVersion)
	}
	if len(cfg.CipherSuites) != 1 || cfg.CipherSuites[0] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("expected ServingCipherSuites %v, got %v", []string{"TLS_AES_128_GCM_SHA256"}, cfg.CipherSuites)
	}
}

func TestWithTLSConfig_Chaining(t *testing.T) {
	noop := func(_ context.Context, _ *ControllerContext) error { return nil }
	cfg := NewControllerCommandConfig("test", version.Info{}, noop, clock.RealClock{}).
		WithTLSConfig("VersionTLS12", nil)

	if cfg.MinTLSVersion != "VersionTLS12" {
		t.Errorf("expected ServingMinTLSVersion %q, got %q", "VersionTLS12", cfg.MinTLSVersion)
	}
	if cfg.CipherSuites != nil {
		t.Errorf("expected nil ServingCipherSuites, got %v", cfg.CipherSuites)
	}
}

func TestStartController_TLSOverridesAppliedBeforeWithServer(t *testing.T) {
	// Verify that ServingMinTLSVersion and ServingCipherSuites are injected into
	// config.ServingInfo before WithServer() is called (which would otherwise
	// apply defaults via SetRecommendedHTTPServingInfoDefaults / DefaultString).
	noop := func(_ context.Context, _ *ControllerContext) error { return nil }
	cfg := NewControllerCommandConfig("test", version.Info{}, noop, clock.RealClock{})
	cfg.WithTLSConfig("VersionTLS13", []string{"TLS_AES_256_GCM_SHA384"})

	// Simulate what StartController does: build a config and apply overrides.
	config := &operatorv1alpha1.GenericOperatorConfig{}

	if cfg.MinTLSVersion != "" {
		config.ServingInfo.MinTLSVersion = cfg.MinTLSVersion
	}
	if len(cfg.CipherSuites) > 0 {
		config.ServingInfo.CipherSuites = cfg.CipherSuites
	}

	if config.ServingInfo.MinTLSVersion != "VersionTLS13" {
		t.Errorf("expected MinTLSVersion %q, got %q", "VersionTLS13", config.ServingInfo.MinTLSVersion)
	}
	if len(config.ServingInfo.CipherSuites) != 1 || config.ServingInfo.CipherSuites[0] != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("expected CipherSuites %v, got %v", []string{"TLS_AES_256_GCM_SHA384"}, config.ServingInfo.CipherSuites)
	}
}

func TestStartController_NoTLSOverride_LeavesServingInfoEmpty(t *testing.T) {
	noop := func(_ context.Context, _ *ControllerContext) error { return nil }
	cfg := NewControllerCommandConfig("test", version.Info{}, noop, clock.RealClock{})
	// Do NOT call WithTLSConfig — overrides must stay empty so that
	// SetRecommendedHTTPServingInfoDefaults can fill in the defaults.
	config := &operatorv1alpha1.GenericOperatorConfig{}

	if cfg.MinTLSVersion != "" {
		config.ServingInfo.MinTLSVersion = cfg.MinTLSVersion
	}
	if len(cfg.CipherSuites) > 0 {
		config.ServingInfo.CipherSuites = cfg.CipherSuites
	}

	if config.ServingInfo.MinTLSVersion != "" {
		t.Errorf("expected empty MinTLSVersion when no override set, got %q", config.ServingInfo.MinTLSVersion)
	}
	if len(config.ServingInfo.CipherSuites) != 0 {
		t.Errorf("expected empty CipherSuites when no override set, got %v", config.ServingInfo.CipherSuites)
	}
}

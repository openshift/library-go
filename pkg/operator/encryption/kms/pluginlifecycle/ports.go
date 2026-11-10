package pluginlifecycle

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// Host-network port ranges reserved for KMS plugin sidecars on control-plane nodes.
// Adjacent to kube-apiserver check-endpoints (17697). See openshift/enhancements
// host-port-registry.
//
// Layout (10 ports each; 17710–17719 left free between operand health and metrics):
//
//	operand health:     17700–17709
//	operand metrics:    17720–17729
//	preflight health:   17730–17739
//	preflight metrics:  17740–17749
const (
	hostNetworkHealthPortBase  = 17700
	hostNetworkMetricsPortBase = 17720
	hostNetworkPortRangeSize   = 10

	preflightHostNetworkHealthPortBase  = 17730
	preflightHostNetworkMetricsPortBase = 17740

	// Defaults from vault-kube-kms when not on the host network.
	defaultHealthPort  = 8081
	defaultMetricsPort = 9090
)

// pluginPorts holds the TCP ports a single KMS plugin sidecar listens on.
// A non-positive health or metrics port disables that endpoint on the plugin.
type pluginPorts struct {
	health   int32
	metrics  int32
	hostPort bool
}

func (p pluginPorts) healthEnabled() bool  { return p.health > 0 }
func (p pluginPorts) metricsEnabled() bool { return p.metrics > 0 }

// Preflight on hostNetwork uses a dedicated range (17730+/17740+) so it does
// not collide with a live API server's operand ports (17700+/17720+).
func portsForPodSpecAtIndex(index int, podSpec *corev1.PodSpec, preflight bool) (pluginPorts, error) {
	if preflight {
		return portsForIndex(index, podSpec.HostNetwork, preflightHostNetworkHealthPortBase, preflightHostNetworkMetricsPortBase, "preflight")
	}

	return portsForIndex(index, podSpec.HostNetwork, hostNetworkHealthPortBase, hostNetworkMetricsPortBase, "operand")
}

func portsForIndex(index int, hostNetwork bool, healthBase, metricsBase int, kind string) (pluginPorts, error) {
	if index < 0 {
		return pluginPorts{}, fmt.Errorf("plugin index must be non-negative, got %d", index)
	}
	if hostNetwork {
		if index >= hostNetworkPortRangeSize {
			return pluginPorts{}, fmt.Errorf("too many KMS plugins for host-network %s port range: index %d exceeds max %d (ports %d-%d / %d-%d)",
				kind, index, hostNetworkPortRangeSize-1,
				healthBase, healthBase+hostNetworkPortRangeSize-1,
				metricsBase, metricsBase+hostNetworkPortRangeSize-1)
		}
		return pluginPorts{
			health:   int32(healthBase + index),
			metrics:  int32(metricsBase + index),
			hostPort: hostNetwork,
		}, nil
	}
	return pluginPorts{
		health:   int32(defaultHealthPort + index),
		metrics:  int32(defaultMetricsPort + index),
		hostPort: hostNetwork,
	}, nil
}

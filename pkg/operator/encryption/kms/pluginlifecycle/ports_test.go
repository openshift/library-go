package pluginlifecycle

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestPortsForPodSpecAtIndex(t *testing.T) {
	tests := []struct {
		name      string
		index     int
		podSpec   *corev1.PodSpec
		preflight bool
		want      pluginPorts
		wantErr   string
	}{
		{
			name:      "operand host network index 0",
			index:     0,
			podSpec:   &corev1.PodSpec{HostNetwork: true},
			preflight: false,
			want:      pluginPorts{health: 17700, metrics: 17720, hostPort: true},
		},
		{
			name:      "operand host network index 1",
			index:     1,
			podSpec:   &corev1.PodSpec{HostNetwork: true},
			preflight: false,
			want:      pluginPorts{health: 17701, metrics: 17721, hostPort: true},
		},
		{
			name:      "operand host network index 9",
			index:     9,
			podSpec:   &corev1.PodSpec{HostNetwork: true},
			preflight: false,
			want:      pluginPorts{health: 17709, metrics: 17729, hostPort: true},
		},
		{
			name:      "operand host network rejects overflow",
			index:     10,
			podSpec:   &corev1.PodSpec{HostNetwork: true},
			preflight: false,
			wantErr:   "too many KMS plugins",
		},
		{
			name:      "operand pod network index 0",
			index:     0,
			podSpec:   &corev1.PodSpec{HostNetwork: false},
			preflight: false,
			want:      pluginPorts{health: 8081, metrics: 9090, hostPort: false},
		},
		{
			name:      "operand pod network index 1",
			index:     1,
			podSpec:   &corev1.PodSpec{HostNetwork: false},
			preflight: false,
			want:      pluginPorts{health: 8082, metrics: 9091, hostPort: false},
		},
		{
			name:      "preflight host network index 0",
			index:     0,
			podSpec:   &corev1.PodSpec{HostNetwork: true},
			preflight: true,
			want:      pluginPorts{health: 17730, metrics: 17740, hostPort: true},
		},
		{
			name:      "preflight host network index 1",
			index:     1,
			podSpec:   &corev1.PodSpec{HostNetwork: true},
			preflight: true,
			want:      pluginPorts{health: 17731, metrics: 17741, hostPort: true},
		},
		{
			name:      "preflight host network index 9",
			index:     9,
			podSpec:   &corev1.PodSpec{HostNetwork: true},
			preflight: true,
			want:      pluginPorts{health: 17739, metrics: 17749, hostPort: true},
		},
		{
			name:      "preflight host network rejects overflow",
			index:     10,
			podSpec:   &corev1.PodSpec{HostNetwork: true},
			preflight: true,
			wantErr:   "too many KMS plugins",
		},
		{
			name:      "preflight pod network uses same defaults as operands",
			index:     0,
			podSpec:   &corev1.PodSpec{HostNetwork: false},
			preflight: true,
			want:      pluginPorts{health: 8081, metrics: 9090, hostPort: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := portsForPodSpecAtIndex(tt.index, tt.podSpec, tt.preflight)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

package preflight

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    options
		wantErr error
	}{
		{
			name: "valid single socket",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-1.sock"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
		},
		{
			name: "valid multiple sockets",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-1.sock", "unix:///var/run/kmsplugin/kms-2.sock"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
		},
		{
			name: "no sockets",
			opts: options{
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-sockets is required, at least one"),
		},
		{
			name: "empty socket entry",
			opts: options{
				kmsSockets:     []string{""},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-sockets entry %q must match %s", "", kmsSocketPattern),
		},
		{
			name: "duplicate sockets",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-1.sock", "unix:///var/run/kmsplugin/kms-1.sock"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-sockets entry %q is duplicated", "unix:///var/run/kmsplugin/kms-1.sock"),
		},
		{
			name: "socket missing unix scheme",
			opts: options{
				kmsSockets:     []string{"/var/run/kmsplugin/kms-1.sock"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-sockets entry %q must match %s", "/var/run/kmsplugin/kms-1.sock", kmsSocketPattern),
		},
		{
			name: "socket scheme without path",
			opts: options{
				kmsSockets:     []string{"unix://"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-sockets entry %q must match %s", "unix://", kmsSocketPattern),
		},
		{
			name: "socket wrong directory",
			opts: options{
				kmsSockets:     []string{"unix:///tmp/kms-1.sock"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-sockets entry %q must match %s", "unix:///tmp/kms-1.sock", kmsSocketPattern),
		},
		{
			name: "socket non-numeric index",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-x.sock"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-sockets entry %q must match %s", "unix:///var/run/kmsplugin/kms-x.sock", kmsSocketPattern),
		},
		{
			name: "socket missing .sock suffix",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-1"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-sockets entry %q must match %s", "unix:///var/run/kmsplugin/kms-1", kmsSocketPattern),
		},
		{
			name: "socket with surrounding whitespace",
			opts: options{
				kmsSockets:     []string{" unix:///var/run/kmsplugin/kms-1.sock "},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-sockets entry %q must match %s", " unix:///var/run/kmsplugin/kms-1.sock ", kmsSocketPattern),
		},
		{
			name: "kms-call-timeout zero",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-1.sock"},
				kmsCallTimeout: 0,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-call-timeout must be greater than 0"),
		},
		{
			name: "kms-call-timeout negative",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-1.sock"},
				kmsCallTimeout: -time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--kms-call-timeout must be greater than 0"),
		},
		{
			name: "config-hash empty",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-1.sock"},
				kmsCallTimeout: 10 * time.Second,
				podName:        "kms-preflight",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--config-hash is required"),
		},
		{
			name: "pod-name empty",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-1.sock"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podNamespace:   "openshift-config-managed",
			},
			wantErr: fmt.Errorf("--pod-name is required"),
		},
		{
			name: "pod-namespace empty",
			opts: options{
				kmsSockets:     []string{"unix:///var/run/kmsplugin/kms-1.sock"},
				kmsCallTimeout: 10 * time.Second,
				configHash:     "abc123",
				podName:        "kms-preflight",
			},
			wantErr: fmt.Errorf("--pod-namespace is required"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.validate()
			require.Equal(t, tc.wantErr, err)
		})
	}
}

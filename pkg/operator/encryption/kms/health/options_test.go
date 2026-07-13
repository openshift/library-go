package health

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
)

// validOptions returns an options value that passes validate. Each test case
// mutates a single field so the failure under test is unambiguous.
func validOptions() *options {
	return &options{
		KMSSockets:   []string{"unix:///var/run/kmsplugin/kms-1.sock"},
		Interval:     30 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		NodeName:     "node-1",
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*options)
		wantErr bool
	}{
		{
			name:   "valid",
			mutate: func(*options) {},
		},
		{
			name:    "no sockets",
			mutate:  func(o *options) { o.KMSSockets = nil },
			wantErr: true,
		},
		{
			name:    "empty socket entry",
			mutate:  func(o *options) { o.KMSSockets = []string{""} },
			wantErr: true,
		},
		{
			name:   "multiple valid sockets",
			mutate: func(o *options) { o.KMSSockets = append(o.KMSSockets, "unix:///var/run/kmsplugin/kms-2.sock") },
		},
		{
			name:    "duplicate sockets",
			mutate:  func(o *options) { o.KMSSockets = append(o.KMSSockets, o.KMSSockets[0]) },
			wantErr: true,
		},
		{
			name:    "socket missing unix scheme",
			mutate:  func(o *options) { o.KMSSockets = []string{"/var/run/kmsplugin/kms-1.sock"} },
			wantErr: true,
		},
		{
			name:    "socket scheme without path",
			mutate:  func(o *options) { o.KMSSockets = []string{"unix://"} },
			wantErr: true,
		},
		{
			name:    "socket wrong directory",
			mutate:  func(o *options) { o.KMSSockets = []string{"unix:///tmp/kms-1.sock"} },
			wantErr: true,
		},
		{
			name:    "socket non-numeric index",
			mutate:  func(o *options) { o.KMSSockets = []string{"unix:///var/run/kmsplugin/kms-x.sock"} },
			wantErr: true,
		},
		{
			name:    "socket missing .sock suffix",
			mutate:  func(o *options) { o.KMSSockets = []string{"unix:///var/run/kmsplugin/kms-1"} },
			wantErr: true,
		},
		{
			name:    "socket with surrounding whitespace",
			mutate:  func(o *options) { o.KMSSockets = []string{" unix:///var/run/kmsplugin/kms-1.sock "} },
			wantErr: true,
		},
		{
			name:    "interval zero",
			mutate:  func(o *options) { o.Interval = 0 },
			wantErr: true,
		},
		{
			name:    "interval negative",
			mutate:  func(o *options) { o.Interval = -time.Second },
			wantErr: true,
		},
		{
			name:    "read timeout zero",
			mutate:  func(o *options) { o.ReadTimeout = 0 },
			wantErr: true,
		},
		{
			name:    "write timeout zero",
			mutate:  func(o *options) { o.WriteTimeout = 0 },
			wantErr: true,
		},
		{
			name:    "node name empty",
			mutate:  func(o *options) { o.NodeName = "" },
			wantErr: true,
		},
		{
			name:   "long node name",
			mutate: func(o *options) { o.NodeName = strings.Repeat("n", 253) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := validOptions()
			tc.mutate(o)

			err := o.validate()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFieldManagerForNode(t *testing.T) {
	const nodeName = "node-1"
	want := fmt.Sprintf("%s-%x", Subcommand, sha256.Sum256([]byte(nodeName)))

	require.Equal(t, want, fieldManagerForNode(nodeName))
	require.Equal(t, fieldManagerForNode(nodeName), fieldManagerForNode(nodeName))
	require.NotEqual(t, fieldManagerForNode("node-1"), fieldManagerForNode("node-2"))
	require.LessOrEqual(t, len(fieldManagerForNode(nodeName)), metav1validation.FieldManagerMaxLength)
	require.LessOrEqual(t, len(fieldManagerForNode(strings.Repeat("n", 253))), metav1validation.FieldManagerMaxLength)
}

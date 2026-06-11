package pluginlifecycle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseUnsupportedKMSConfig(t *testing.T) {
	tests := []struct {
		name             string
		raw              []byte
		expectedLogLevel string
		expectError      bool
	}{
		{
			name:             "nil input returns empty config",
			raw:              nil,
			expectedLogLevel: "",
		},
		{
			name:             "empty input returns empty config",
			raw:              []byte{},
			expectedLogLevel: "",
		},
		{
			name:             "JSON with log level",
			raw:              []byte(`{"encryption":{"kms":{"vault":{"logLevel":"debug-extended"}}}}`),
			expectedLogLevel: "debug-extended",
		},
		{
			name:             "YAML with log level",
			raw:              []byte("encryption:\n  kms:\n    vault:\n      logLevel: trace\n"),
			expectedLogLevel: "trace",
		},
		{
			name:             "unrelated fields are ignored",
			raw:              []byte(`{"encryption":{"reason":"test"}}`),
			expectedLogLevel: "",
		},
		{
			name:             "malformed JSON is handled gracefully",
			raw:              []byte(`{not json`),
			expectedLogLevel: "",
		},
		{
			name:        "unparsable input returns error",
			raw:         []byte{0x00, 0x01, 0x02},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := parseUnsupportedKMSConfig(tt.raw)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedLogLevel, config.Encryption.KMS.Vault.LogLevel)
		})
	}
}

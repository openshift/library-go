package crypto

import "testing"

func TestECDSAKeyPairGeneratorSecurityLevel(t *testing.T) {
	testCases := []struct {
		name  string
		curve ECDSACurve
		want  SecurityLevel
	}{
		{
			name:  "P256",
			curve: P256,
			want:  SecurityLevel{ClassicalBits: 128},
		},
		{
			name:  "P384",
			curve: P384,
			want:  SecurityLevel{ClassicalBits: 192},
		},
		{
			name:  "P521",
			curve: P521,
			want:  SecurityLevel{ClassicalBits: 256},
		},
		{
			name:  "unknown curve has no strength",
			curve: "P224",
			want:  SecurityLevel{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ECDSAKeyPairGenerator{Curve: tc.curve}.SecurityLevel()
			if got != tc.want {
				t.Errorf("SecurityLevel() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

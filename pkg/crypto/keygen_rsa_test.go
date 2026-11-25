package crypto

import "testing"

func TestKeySpecSecurityLevelRSA(t *testing.T) {
	testCases := []struct {
		name string
		bits int
		want SecurityLevel
	}{
		{
			name: "zero value has no strength",
			bits: 0,
			want: SecurityLevel{},
		},
		{
			name: "RSA-2048",
			bits: 2048,
			want: SecurityLevel{ClassicalBits: 112},
		},
		{
			name: "RSA-3072",
			bits: 3072,
			want: SecurityLevel{ClassicalBits: 128},
		},
		{
			name: "RSA-4096",
			bits: 4096,
			want: SecurityLevel{ClassicalBits: 152},
		},
		{
			name: "RSA-5120",
			bits: 5120,
			want: SecurityLevel{ClassicalBits: 168},
		},
		{
			name: "RSA-6144",
			bits: 6144,
			want: SecurityLevel{ClassicalBits: 176},
		},
		{
			name: "RSA-7168",
			bits: 7168,
			want: SecurityLevel{ClassicalBits: 192},
		},
		{
			name: "RSA-8192",
			bits: 8192,
			want: SecurityLevel{ClassicalBits: 200},
		},
		{
			name: "size between NIST tabulated sizes rounds to the nearest multiple of eight",
			bits: 3000,
			want: SecurityLevel{ClassicalBits: 128},
		},
		{
			name: "above the table is not capped",
			bits: 16384,
			want: SecurityLevel{ClassicalBits: 272},
		},
		{
			name: "smaller than any NIST tabulated size is still estimated",
			bits: 1024,
			want: SecurityLevel{ClassicalBits: 80},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: tc.bits}.SecurityLevel()
			if got != tc.want {
				t.Errorf("SecurityLevel() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

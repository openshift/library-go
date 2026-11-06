package crypto

import (
	"errors"
	"io/fs"
	"slices"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestIsFIPSEnabled(t *testing.T) {
	readResult := func(data string, err error) func(string) ([]byte, error) {
		return func(string) ([]byte, error) {
			return []byte(data), err
		}
	}

	tests := []struct {
		name              string
		nativeFIPSEnabled bool
		readFile          func(string) ([]byte, error)
		want              bool
	}{
		{
			name:              "native Go FIPS only",
			nativeFIPSEnabled: true,
			readFile:          readResult("0", nil),
			want:              true,
		},
		{
			name:     "host FIPS only",
			readFile: readResult("1\n", nil),
			want:     true,
		},
		{
			name:              "native and host FIPS",
			nativeFIPSEnabled: true,
			readFile:          readResult("1", nil),
			want:              true,
		},
		{
			name:     "neither mode",
			readFile: readResult("0", nil),
			want:     false,
		},
		{
			name:     "host FIPS signal unavailable",
			readFile: readResult("", fs.ErrNotExist),
			want:     false,
		},
		{
			name:     "host FIPS signal read error",
			readFile: readResult("", errors.New("read failed")),
			want:     false,
		},
		{
			name:     "host FIPS file malformed",
			readFile: readResult("enabled", nil),
			want:     false,
		},
		{
			name:     "host FIPS file has unsupported value",
			readFile: readResult("2", nil),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFIPSEnabled(tt.nativeFIPSEnabled, tt.readFile); got != tt.want {
				t.Errorf("isFIPSEnabled() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestIsFIPSEnabledNativeModeDoesNotReadHostSignal(t *testing.T) {
	readHostSignal := false
	got := isFIPSEnabled(true, func(string) ([]byte, error) {
		readHostSignal = true
		return nil, errors.New("should not read host FIPS signal")
	})
	if !got {
		t.Fatal("isFIPSEnabled() = false, want true")
	}
	if readHostSignal {
		t.Error("isFIPSEnabled() read host FIPS signal when native Go FIPS was enabled")
	}
}

// TestFIPSApprovedTLSGroups pins the FIPS allowlist: only the three NIST
// P-curves are approved. X25519 and every ML-KEM post-quantum hybrid are not.
// See the KNOWN DIVERGENCE note in tls_fips.go for why.
func TestFIPSApprovedTLSGroups(t *testing.T) {
	perGroup := []struct {
		name         string
		group        configv1.TLSGroup
		wantApproved bool
	}{
		{"secp256r1 is approved", configv1.TLSGroupSecP256r1, true},
		{"secp384r1 is approved", configv1.TLSGroupSecP384r1, true},
		{"secp521r1 is approved", configv1.TLSGroupSecP521r1, true},
		{"X25519 is not approved", configv1.TLSGroupX25519, false},
		{"X25519MLKEM768 hybrid is not approved", configv1.TLSGroupX25519MLKEM768, false},
		{"SecP256r1MLKEM768 hybrid is not approved", configv1.TLSGroupSecP256r1MLKEM768, false},
		{"SecP384r1MLKEM1024 hybrid is not approved", configv1.TLSGroupSecP384r1MLKEM1024, false},
		{"unknown group is not approved", configv1.TLSGroup("UnknownFutureGroup"), false},
	}
	for _, tc := range perGroup {
		t.Run(tc.name, func(t *testing.T) {
			got := FIPSApprovedTLSGroups([]configv1.TLSGroup{tc.group})
			gotApproved := len(got) == 1
			if gotApproved != tc.wantApproved {
				t.Errorf("fipsApprovedTLSGroups(%q) = %v, want approved=%v", tc.group, got, tc.wantApproved)
			}
		})
	}

	t.Run("filters a mixed list preserving order", func(t *testing.T) {
		in := []configv1.TLSGroup{
			configv1.TLSGroupX25519MLKEM768,
			configv1.TLSGroupSecP384r1,
			configv1.TLSGroupX25519,
			configv1.TLSGroupSecP256r1,
		}
		want := []configv1.TLSGroup{configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP256r1}
		if got := FIPSApprovedTLSGroups(in); !slices.Equal(got, want) {
			t.Errorf("fipsApprovedTLSGroups(%q) = %q, want %q", in, got, want)
		}
	})

	t.Run("empty input yields empty output", func(t *testing.T) {
		if got := FIPSApprovedTLSGroups(nil); len(got) != 0 {
			t.Errorf("fipsApprovedTLSGroups(nil) = %q, want empty", got)
		}
	})
}

func TestGetSecurityProfileGroupsFiltersHostFIPS(t *testing.T) {
	allGroups := []configv1.TLSGroup{
		configv1.TLSGroupX25519,
		configv1.TLSGroupSecP256r1,
		configv1.TLSGroupSecP384r1,
		configv1.TLSGroupSecP521r1,
		configv1.TLSGroupX25519MLKEM768,
		configv1.TLSGroupSecP256r1MLKEM768,
		configv1.TLSGroupSecP384r1MLKEM1024,
	}
	profile := &configv1.TLSProfileSpec{Groups: allGroups}
	fipsEnabled := isFIPSEnabled(false, func(string) ([]byte, error) {
		return []byte("1\n"), nil
	})

	want := []string{"secp256r1", "secp384r1", "secp521r1"}
	if got := getSecurityProfileGroups(profile, fipsEnabled); !slices.Equal(got, want) {
		t.Errorf("getSecurityProfileGroups() = %q, want %q", got, want)
	}
}

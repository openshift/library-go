package crypto

import (
	"testing"
)

func TestKeySpecValidate(t *testing.T) {
	testCases := []struct {
		name    string
		spec    KeySpec
		wantErr string
	}{
		{
			name: "valid RSA",
			spec: KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048},
		},
		{
			name: "valid ECDSA",
			spec: KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384},
		},
		{
			name:    "zero value",
			spec:    KeySpec{},
			wantErr: "key algorithm is required",
		},
		{
			name:    "unknown algorithm",
			spec:    KeySpec{Algorithm: "EdDSA"},
			wantErr: `unknown key algorithm: "EdDSA"`,
		},
		{
			name:    "RSA below the floor",
			spec:    KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 1024},
			wantErr: "invalid RSA key size 1024: must be at least 2048 bits",
		},
		{
			name:    "RSA with a curve set",
			spec:    KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048, ECDSACurve: P256},
			wantErr: "RSA key spec must not set an ECDSA curve",
		},
		{
			name:    "ECDSA with an unknown curve",
			spec:    KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: "P224"},
			wantErr: `invalid ECDSA key spec: unsupported ECDSA curve: "P224"`,
		},
		{
			name:    "ECDSA with RSA bits set",
			spec:    KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256, RSABits: 2048},
			wantErr: "ECDSA key spec must not set RSA bits",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			if err.Error() != tc.wantErr {
				t.Errorf("Validate() error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestKeySpecKeyPairGeneratorRejectsInvalidSpecs(t *testing.T) {
	for _, spec := range []KeySpec{
		{},
		{Algorithm: RSAKeyAlgorithm, RSABits: 1024},
		{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: "bogus"},
		{Algorithm: "EdDSA"},
	} {
		if g, err := spec.KeyPairGenerator(); err == nil {
			t.Errorf("KeySpec%+v.KeyPairGenerator() = %v, want error", spec, g)
		}
	}
}

func TestKeySpecString(t *testing.T) {
	testCases := []struct {
		spec KeySpec
		want string
	}{
		{KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 3072}, "RSA 3072"},
		{KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384}, "ECDSA P384"},
		{KeySpec{}, "no key"},
	}
	for _, tc := range testCases {
		if got := tc.spec.String(); got != tc.want {
			t.Errorf("KeySpec%+v.String() = %q, want %q", tc.spec, got, tc.want)
		}
	}
}

func TestKeySpecFromPublicKeyRoundTrip(t *testing.T) {
	for _, spec := range allKeySpecs {
		t.Run(spec.String(), func(t *testing.T) {
			pub, _, err := mustGenerator(spec).GenerateKeyPair()
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}
			got, err := KeySpecFromPublicKey(pub)
			if err != nil {
				t.Fatalf("KeySpecFromPublicKey() error = %v", err)
			}
			if got != spec {
				t.Errorf("KeySpecFromPublicKey() = %+v, want %+v", got, spec)
			}
		})
	}
}

func TestKeySpecFromPublicKeyUnsupported(t *testing.T) {
	var pub interface{} = 42
	if _, err := KeySpecFromPublicKey(pub); err == nil {
		t.Error("KeySpecFromPublicKey(int) = nil error, want error")
	}
}

func TestStrongerKeySpec(t *testing.T) {
	rsa2048 := KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048} // 112 bits
	rsa3072 := KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 3072} // 128 bits
	ecP256 := KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256}
	ecP384 := KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384}
	zero := KeySpec{}

	testCases := []struct {
		name string
		a    KeySpec
		b    KeySpec
		want KeySpec
	}{
		{name: "a stronger", a: ecP384, b: ecP256, want: ecP384},
		{name: "b stronger", a: rsa2048, b: rsa3072, want: rsa3072},
		{name: "equal strength prefers ECDSA in a", a: ecP256, b: rsa3072, want: ecP256},
		{name: "equal strength prefers ECDSA in b", a: rsa3072, b: ecP256, want: ecP256},
		{name: "equal strength RSA keeps a", a: rsa2048, b: rsa2048, want: rsa2048},
		{name: "zero spec loses", a: zero, b: rsa2048, want: rsa2048},
		{name: "zero spec loses as b", a: ecP256, b: zero, want: ecP256},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StrongerKeySpec(tc.a, tc.b); got != tc.want {
				t.Errorf("StrongerKeySpec(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

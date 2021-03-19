package crypto

import (
	"fmt"
	"reflect"
	"testing"
)

func TestCheckRSAKeyPair(t *testing.T) {
	var (
		rsaPublicKey1 = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0
FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/
3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB
-----END PUBLIC KEY-----
`

		rsaPrivKey1 = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----
`

		rsaPublicKey2 = `
-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgG3nScV2wLxaS3JaEHJrepzbXmql
nh0BDYdr4GRjVR6EeC1E0edO1LiiwI/aU7xbXa0wHEI4kr/MnRDIlV+7L/6FLqob
PH8fg5HM0K2dE2vaEWIb8saRWs8r49tqeChiHsPEGeJeofKgeXw0XrEW6+l7QQO5
vH+y1RdSulDn33KlAgMBAAE=
-----END PUBLIC KEY-----
`

		multipleKeys = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVx
wTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFnc
CzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0T
p0GbMJDyR4e9T04ZZwIDAQAB
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAh14+qIRu+CdE6wlyg4WMsc3j
80W5sbZccH4dPxoEGlWMa8B2A+olOAy5qw8KoU3Xl1yuND8QvB3Xb499GGIX0aqN
OTVwaSKxTZDSGnoJipZsxhxzDpHi6rn/pAdE4jnkqfaqujZbnTyHRhNdvy7jVO7d
s16gDilgo+8DEAxQfQIDAQAB
-----END PUBLIC KEY-----
`
	)

	keyPairTests := []struct {
		name        string
		pubKey      string
		privKey     string
		expectedErr error
	}{
		{
			name:        "matching keys",
			pubKey:      rsaPublicKey1,
			privKey:     rsaPrivKey1,
			expectedErr: nil,
		},
		{
			name:        "multiple keys",
			pubKey:      multipleKeys,
			privKey:     rsaPrivKey1,
			expectedErr: nil,
		},
		{
			name:        "not matching keys",
			pubKey:      rsaPublicKey2,
			privKey:     rsaPrivKey1,
			expectedErr: fmt.Errorf("key pair do not match"),
		},
		{
			name:        "fake public key",
			pubKey:      "fake key",
			privKey:     rsaPrivKey1,
			expectedErr: fmt.Errorf("data does not contain any valid RSA or ECDSA public keys"),
		},
		{
			name:        "fake private key",
			pubKey:      rsaPublicKey1,
			privKey:     "fake key",
			expectedErr: fmt.Errorf("data does not contain a valid RSA or ECDSA private key"),
		},
	}
	for _, tc := range keyPairTests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckRSAKeyPair([]byte(tc.pubKey), []byte(tc.privKey))
			if !reflect.DeepEqual(err, tc.expectedErr) {
				t.Fatalf("expected error %v got %v", tc.expectedErr, err)
			}
		})
	}

	t.Run("generated keypair", func(t *testing.T) {
		pubKey, privKey, err := GenerateRSAKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		err = CheckRSAKeyPair(pubKey, privKey)
		if err != nil {
			t.Fatal(err)
		}
	})
}

package resourcesynccontroller

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"testing"
)

const (
	exampleCrt = `
-----BEGIN CERTIFICATE-----
MIIDuTCCAqGgAwIBAgIUZYD30F0sJl7HqxE7gAequtxk/HowDQYJKoZIhvcNAQEL
BQAwgaExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJTQzEVMBMGA1UEBwwMRGVmYXVs
dCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBhbnkgTHRkMRAwDgYDVQQLDAdU
ZXN0IENBMRowGAYDVQQDDBF3d3cuZXhhbXBsZWNhLmNvbTEiMCAGCSqGSIb3DQEJ
ARYTZXhhbXBsZUBleGFtcGxlLmNvbTAeFw0yMjAxMjgwMjU0MDlaFw0zMjAxMjYw
MjU0MDlaMHwxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTELMAkGA1UECAwCU0Mx
CzAJBgNVBAYTAlVTMSIwIAYJKoZIhvcNAQkBFhNleGFtcGxlQGV4YW1wbGUuY29t
MRAwDgYDVQQKDAdFeGFtcGxlMRAwDgYDVQQLDAdFeGFtcGxlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA71W7gdEnM+Nm4/SA/4jEJ2SPQfVjkCMsIYGO
WrLLHq23HkMGstQoPyBnjLY8LmkKQsNhhWGRMWQz6+yGKgI1gh8huhfocuw+HODE
K3ugP/3DlaVEQlIQbVzwxDx+K78UqZHecQAJfvakuS/JThxsMf8/pqLuhjAf+t9N
k0CO8Z6mNVALtSvyQ+e+zjmzepVtu6WmtJ+8zW9dBQEmg0QCfWFd06836LrfixLk
vTRgCn0lzTuj7rSuGjY45JDIvKK4jZGQJKsYN59Wxg1d2CEoXBUJOJjecVdS3NhY
ubHNdcm+6Equ5ZmyVEkBmv462rOcednsHU6Ggt/vWSe05EOPVQIDAQABow0wCzAJ
BgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCHI+fkEr27bJ2IMtFuHpSLpFF3
E4R5oVHt8XjflwKmuclyyLa8Z7nXnuvQLHa4jwf0tWUixsmtOyQN4tBI/msMk2PF
+ao2amcPoIo2lAg63+jFsIzkr2MEXBPu09wwt86e3XCoqmqT1Psnihh+Ys9KIPnc
wMr9muGkOh03O61vo71iaV17UKeGM4bzod333pSQIXLdYnoOuvmKdCsnD00lADoI
93DmG/4oYR/mD93QjxPFPDxDxR4isvWGoj7iXx7CFkN7PR9B3IhZt+T//ddeau3y
kXK0iSxOhyaqHvl15hHQ8tKPBBJRSDVU4qmaqAYWRXr65yxBoelHhTJQ6Gt4
-----END CERTIFICATE-----
`
)

func TestCombineCABundleConfigMaps(t *testing.T) {
	type Test struct {
		name          string
		dstlocation   ResourceLocation
		srclocation   ResourceLocation
		cm            *corev1.ConfigMap
		expectedError bool
	}
	tests := []Test{
		{
			name:        "not found the cm in the cm lister",
			dstlocation: ResourceLocation{Namespace: "test-ca-1", Name: "test-ca"},
			srclocation: ResourceLocation{Namespace: "test-ca-2", Name: "test-ca"},
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ca", Namespace: "test-ca-3"},
				Data: map[string]string{
					"ca-bundle.crt": exampleCrt,
				},
			},
			expectedError: true,
		},
		{
			name:        "found cm in the cm lister",
			dstlocation: ResourceLocation{Namespace: "test-ca-1", Name: "test-ca"},
			srclocation: ResourceLocation{Namespace: "test-ca-2", Name: "test-ca"},
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ca", Namespace: "test-ca-2"},
				Data: map[string]string{
					"ca-bundle.crt": exampleCrt,
				},
			},
			expectedError: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := indexer.Add(test.cm); err != nil {
				t.Fatal(err.Error())
			}
			lister := corev1listers.NewConfigMapLister(indexer)
			_, err := CombineCABundleConfigMaps(test.dstlocation, lister, test.srclocation)
			if test.expectedError && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

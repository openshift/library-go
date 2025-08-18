package certgraphanalysis

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/openshift/library-go/pkg/certs/cert-inspection/certgraphapi"
)

func newCertKeyPair(name, pubKeyModulus string, secretLocs []certgraphapi.InClusterSecretLocation, onDiskLocs []certgraphapi.OnDiskCertKeyPairLocation, inMemoryLocs []certgraphapi.InClusterPodLocation) *certgraphapi.CertKeyPair {
	return &certgraphapi.CertKeyPair{
		Name: name,
		Spec: certgraphapi.CertKeyPairSpec{
			CertMetadata: certgraphapi.CertKeyMetadata{
				CertIdentifier: certgraphapi.CertIdentifier{
					PubkeyModulus: pubKeyModulus,
				},
			},
			SecretLocations:   secretLocs,
			OnDiskLocations:   onDiskLocs,
			InMemoryLocations: inMemoryLocs,
		},
	}
}

func TestDeduplicateCertKeyPairs(t *testing.T) {
	tests := []struct {
		name     string
		input    []*certgraphapi.CertKeyPair
		expected []*certgraphapi.CertKeyPair
		panics   bool
	}{
		{
			name:     "Empty input",
			input:    []*certgraphapi.CertKeyPair{},
			expected: []*certgraphapi.CertKeyPair{},
		},
		{
			name: "No duplicates",
			input: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", nil, nil, nil),
				newCertKeyPair("cert2", "mod2", nil, nil, nil),
			},
			expected: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", nil, nil, nil),
				newCertKeyPair("cert2", "mod2", nil, nil, nil),
			},
		},
		{
			name: "Exact duplicates",
			input: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns1", Name: "sec1"}}, nil, nil),
				newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns1", Name: "sec1"}}, nil, nil),
			},
			expected: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns1", Name: "sec1"}}, nil, nil),
			},
		},
		{
			name: "Duplicates with different locations merged",
			input: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns1", Name: "sec1"}}, nil, nil),
				newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns2", Name: "sec2"}}, nil, nil),
			},
			expected: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns1", Name: "sec1"}, {Namespace: "ns2", Name: "sec2"}}, nil, nil),
			},
		},
		{
			name: "Duplicates with all location types merged",
			input: []*certgraphapi.CertKeyPair{
				newCertKeyPair("certA", "modX",
					[]certgraphapi.InClusterSecretLocation{{Namespace: "nsA", Name: "secA"}},
					[]certgraphapi.OnDiskCertKeyPairLocation{{Cert: certgraphapi.OnDiskLocation{Path: "/path/to/certA.crt"}, Key: certgraphapi.OnDiskLocation{Path: "/path/to/certA.key"}}},
					[]certgraphapi.InClusterPodLocation{{Namespace: "nsP", Name: "podA"}}),
				newCertKeyPair("certA-dup", "modX",
					[]certgraphapi.InClusterSecretLocation{{Namespace: "nsB", Name: "secB"}},
					[]certgraphapi.OnDiskCertKeyPairLocation{{Cert: certgraphapi.OnDiskLocation{Path: "/path/to/certB.crt"}, Key: certgraphapi.OnDiskLocation{Path: "/path/to/certB.key"}}},
					[]certgraphapi.InClusterPodLocation{{Namespace: "nsQ", Name: "podB"}}),
			},
			expected: []*certgraphapi.CertKeyPair{
				newCertKeyPair("certA", "modX",
					[]certgraphapi.InClusterSecretLocation{{Namespace: "nsA", Name: "secA"}, {Namespace: "nsB", Name: "secB"}},
					[]certgraphapi.OnDiskCertKeyPairLocation{
						{Cert: certgraphapi.OnDiskLocation{Path: "/path/to/certA.crt"}, Key: certgraphapi.OnDiskLocation{Path: "/path/to/certA.key"}},
						{Cert: certgraphapi.OnDiskLocation{Path: "/path/to/certB.crt"}, Key: certgraphapi.OnDiskLocation{Path: "/path/to/certB.key"}},
					},
					[]certgraphapi.InClusterPodLocation{{Namespace: "nsP", Name: "podA"}, {Namespace: "nsQ", Name: "podB"}}),
			},
		},
		{
			name: "Different PubkeyModulus",
			input: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", nil, nil, nil),
				newCertKeyPair("cert2", "mod2", nil, nil, nil),
			},
			expected: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", nil, nil, nil),
				newCertKeyPair("cert2", "mod2", nil, nil, nil),
			},
		},
		{
			name: "Mixed duplicates and unique",
			input: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns1", Name: "sec1"}}, nil, nil),
				newCertKeyPair("cert2", "mod2", nil, nil, nil),
				newCertKeyPair("cert1-dup", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns3", Name: "sec3"}}, nil, nil),
			},
			expected: []*certgraphapi.CertKeyPair{
				newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns1", Name: "sec1"}, {Namespace: "ns3", Name: "sec3"}}, nil, nil),
				newCertKeyPair("cert2", "mod2", nil, nil, nil),
			},
		},
		{
			name:   "Input slice contains nil CertKeyPair",
			input:  []*certgraphapi.CertKeyPair{nil},
			panics: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.panics {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("The code did not panic as expected")
					}
				}()
			}

			result := deduplicateCertKeyPairs(test.input)

			if !test.panics {
				if len(result) != len(test.expected) {
					t.Fatalf("Expected %d items, got %d. Result: %+v, Expected: %+v", len(test.expected), len(result), result, test.expected)
				}
				for i := range result {
					// Use reflect.DeepEqual for comparing CertKeyPair structs more thoroughly
					diff := cmp.Diff(result[i], test.expected[i])
					if diff != "" {
						t.Errorf("Mismatch at index %d. diff: %s", i, diff)
					}
				}
			}
		})
	}
}

func TestDeduplicateCertKeyPairList(t *testing.T) {
	tests := []struct {
		name     string
		input    *certgraphapi.CertKeyPairList
		expected *certgraphapi.CertKeyPairList
	}{
		{
			name:     "Empty list",
			input:    &certgraphapi.CertKeyPairList{Items: []certgraphapi.CertKeyPair{}},
			expected: &certgraphapi.CertKeyPairList{Items: []certgraphapi.CertKeyPair{}},
		},
		{
			name: "List with duplicates",
			input: &certgraphapi.CertKeyPairList{
				Items: []certgraphapi.CertKeyPair{
					*newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns1", Name: "sec1"}}, nil, nil),
					*newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns2", Name: "sec2"}}, nil, nil),
				},
			},
			expected: &certgraphapi.CertKeyPairList{
				Items: []certgraphapi.CertKeyPair{
					*newCertKeyPair("cert1", "mod1", []certgraphapi.InClusterSecretLocation{{Namespace: "ns1", Name: "sec1"}, {Namespace: "ns2", Name: "sec2"}}, nil, nil),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := deduplicateCertKeyPairList(test.input)
			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("Test %q failed. Expected %+v, got %+v", test.name, test.expected, result)
			}
		})
	}
}

package certgraphanalysis

import (
	"context"
	"fmt"
	"strings"
	"testing"

	certgraphapi "github.com/openshift/library-go/pkg/certs/cert-inspection/certgraphapi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
)

func TestCreateInMemoryPKIList(t *testing.T) {
	tests := []struct {
		name                         string
		details                      []InMemoryCertDetail
		initialPods                  []*corev1.Pod
		expectError                  bool
		expectedCount                int
		expectedCertKeyPairs         []certgraphapi.CertKeyPair
		expectedInMemoryCertKeyPairs []certgraphapi.PKIRegistryInMemoryCertKeyPair
	}{
		{
			name:                         "Empty details",
			details:                      []InMemoryCertDetail{},
			initialPods:                  []*corev1.Pod{},
			expectError:                  false,
			expectedCount:                0,
			expectedCertKeyPairs:         []certgraphapi.CertKeyPair{},
			expectedInMemoryCertKeyPairs: []certgraphapi.PKIRegistryInMemoryCertKeyPair{},
		},
		{
			name: "Single valid detail, one pod",
			details: []InMemoryCertDetail{
				{
					Namespace:     "test-ns",
					NamePrefix:    "test-cert",
					Description:   "Test certificate",
					LabelSelector: labels.Set(map[string]string{"app": "test"}).AsSelector(),
					Validity:      "1y",
					CertInfo: certgraphapi.PKIRegistryCertKeyPairInfo{
						Description: "Test certificate info",
					},
				},
			},
			initialPods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-ns",
						Name:      "pod-0",
						Labels:    map[string]string{"app": "test"},
					},
				},
			},
			expectError:   false,
			expectedCount: 1,
			expectedCertKeyPairs: []certgraphapi.CertKeyPair{
				{
					Name:        "test-cert-0::1",
					Description: "Test certificate",
					Spec: certgraphapi.CertKeyPairSpec{
						InMemoryLocations: []certgraphapi.InClusterPodLocation{
							{
								Namespace: "test-ns",
								Name:      "test-cert-0",
							},
						},
						CertMetadata: certgraphapi.CertKeyMetadata{
							ValidityDuration: "1y",
							CertIdentifier: certgraphapi.CertIdentifier{
								PubkeyModulus: "in-memory-test-cert-0",
							},
						},
					},
				},
			},
			expectedInMemoryCertKeyPairs: []certgraphapi.PKIRegistryInMemoryCertKeyPair{
				{
					PodLocation: certgraphapi.InClusterPodLocation{
						Namespace: "test-ns",
						Name:      "test-cert-0",
					},
					CertKeyInfo: certgraphapi.PKIRegistryCertKeyPairInfo{
						Description: "Test certificate info",
					},
				},
			},
		},
		{
			name: "Single valid detail, two pods",
			details: []InMemoryCertDetail{
				{
					Namespace:     "test-ns",
					NamePrefix:    "test-cert",
					Description:   "Test certificate",
					LabelSelector: labels.Set(map[string]string{"app": "test"}).AsSelector(),
					Validity:      "2y",
					CertInfo: certgraphapi.PKIRegistryCertKeyPairInfo{
						Description: "Another test cert info",
					},
				},
			},
			initialPods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-ns",
						Name:      "pod-0",
						Labels:    map[string]string{"app": "test"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-ns",
						Name:      "pod-1",
						Labels:    map[string]string{"app": "test"},
					},
				},
			},
			expectError:   false,
			expectedCount: 2,
			expectedCertKeyPairs: []certgraphapi.CertKeyPair{
				{
					Name:        "test-cert-0::1",
					Description: "Test certificate",
					Spec: certgraphapi.CertKeyPairSpec{
						InMemoryLocations: []certgraphapi.InClusterPodLocation{
							{
								Namespace: "test-ns",
								Name:      "test-cert-0",
							},
						},
						CertMetadata: certgraphapi.CertKeyMetadata{
							ValidityDuration: "2y",
							CertIdentifier: certgraphapi.CertIdentifier{
								PubkeyModulus: "in-memory-test-cert-0",
							},
						},
					},
				},
				{
					Name:        "test-cert-1::1",
					Description: "Test certificate",
					Spec: certgraphapi.CertKeyPairSpec{
						InMemoryLocations: []certgraphapi.InClusterPodLocation{
							{
								Namespace: "test-ns",
								Name:      "test-cert-1",
							},
						},
						CertMetadata: certgraphapi.CertKeyMetadata{
							ValidityDuration: "2y",
							CertIdentifier: certgraphapi.CertIdentifier{
								PubkeyModulus: "in-memory-test-cert-1",
							},
						},
					},
				},
			},
			expectedInMemoryCertKeyPairs: []certgraphapi.PKIRegistryInMemoryCertKeyPair{
				{
					PodLocation: certgraphapi.InClusterPodLocation{
						Namespace: "test-ns",
						Name:      "test-cert-0",
					},
					CertKeyInfo: certgraphapi.PKIRegistryCertKeyPairInfo{
						Description: "Another test cert info",
					},
				},
				{
					PodLocation: certgraphapi.InClusterPodLocation{
						Namespace: "test-ns",
						Name:      "test-cert-1",
					},
					CertKeyInfo: certgraphapi.PKIRegistryCertKeyPairInfo{
						Description: "Another test cert info",
					},
				},
			},
		},
		{
			name: "No matching pods - returns no error, zero certs",
			details: []InMemoryCertDetail{
				{
					Namespace:     "test-ns",
					NamePrefix:    "no-match-cert",
					Description:   "No matching pods certificate",
					LabelSelector: labels.Set(map[string]string{"app": "no-match"}).AsSelector(),
					Validity:      "1y",
				},
			},
			initialPods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-ns",
						Name:      "pod-0",
						Labels:    map[string]string{"app": "other"},
					},
				},
			},
			expectError:                  false,
			expectedCount:                0,
			expectedCertKeyPairs:         []certgraphapi.CertKeyPair{},
			expectedInMemoryCertKeyPairs: []certgraphapi.PKIRegistryInMemoryCertKeyPair{},
		},
		{
			name: "Pod listing error in addInMemoryCertificateStub",
			details: []InMemoryCertDetail{
				{
					Namespace:     "error-ns",
					NamePrefix:    "error-cert",
					Description:   "Cert for error case",
					LabelSelector: labels.Set(map[string]string{"app": "error"}).AsSelector(),
					Validity:      "3h",
				},
			},
			initialPods:                  []*corev1.Pod{}, // No pods, but the error should come from the list call itself
			expectError:                  true,
			expectedCount:                0,
			expectedCertKeyPairs:         []certgraphapi.CertKeyPair{},
			expectedInMemoryCertKeyPairs: []certgraphapi.PKIRegistryInMemoryCertKeyPair{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.TODO()
			clientObjects := []runtime.Object{}
			for _, pod := range test.initialPods {
				clientObjects = append(clientObjects, pod)
			}
			kubeClient := fake.NewSimpleClientset(clientObjects...)

			// Add reactor for the error case
			if test.name == "Pod listing error in addInMemoryCertificateStub" {
				kubeClient.PrependReactor("list", "pods", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
					listAction := action.(clientgotesting.ListAction)
					if listAction.GetNamespace() == "error-ns" {
						return true, nil, fmt.Errorf("simulated pod list error for namespace %s", listAction.GetNamespace())
					}
					return false, nil, nil
				})
			}

			result, err := CreateInMemoryPKIList(ctx, kubeClient, test.details)

			if test.expectError {
				if err == nil {
					t.Errorf("expected an error but got none")
				} else if !strings.Contains(err.Error(), "simulated pod list error") {
					t.Errorf("expected error to contain 'simulated pod list error', but got: %v", err)
				}
			} else if err != nil {
				t.Errorf("did not expect an error but got: %v", err)
			}

			if len(result.CertKeyPairs.Items) != test.expectedCount {
				t.Errorf("expected %d items in result.CertKeyPairs.Items, but got %d", test.expectedCount, len(result.CertKeyPairs.Items))
			}
			if len(result.InMemoryResourceData.CertKeyPairs) != test.expectedCount {
				t.Errorf("expected %d items in result.InMemoryResourceData.CertKeyPairs, but got %d", test.expectedCount, len(result.InMemoryResourceData.CertKeyPairs))
			}

			// Detailed assertions for CertKeyPairs.Items
			for i, expectedCert := range test.expectedCertKeyPairs {
				if i >= len(result.CertKeyPairs.Items) {
					t.Errorf("expected CertKeyPair at index %d, but none found", i)
					continue
				}
				actualCert := result.CertKeyPairs.Items[i]
				if actualCert.Name != expectedCert.Name {
					t.Errorf("CertKeyPair %d: expected Name %q, got %q", i, expectedCert.Name, actualCert.Name)
				}
				if actualCert.Description != expectedCert.Description {
					t.Errorf("CertKeyPair %d: expected Description %q, got %q", i, expectedCert.Description, actualCert.Description)
				}
				if len(actualCert.Spec.InMemoryLocations) != len(expectedCert.Spec.InMemoryLocations) {
					t.Errorf("CertKeyPair %d: expected %d InMemoryLocations, got %d", i, len(expectedCert.Spec.InMemoryLocations), len(actualCert.Spec.InMemoryLocations))
				} else {
					for j, expectedLoc := range expectedCert.Spec.InMemoryLocations {
						actualLoc := actualCert.Spec.InMemoryLocations[j]
						if actualLoc.Namespace != expectedLoc.Namespace {
							t.Errorf("CertKeyPair %d, location %d: expected Namespace %q, got %q", i, j, expectedLoc.Namespace, actualLoc.Namespace)
						}
						if actualLoc.Name != expectedLoc.Name {
							t.Errorf("CertKeyPair %d, location %d: expected Name %q, got %q", i, j, expectedLoc.Name, actualLoc.Name)
						}
					}
				}
				if actualCert.Spec.CertMetadata.ValidityDuration != expectedCert.Spec.CertMetadata.ValidityDuration {
					t.Errorf("CertKeyPair %d: expected ValidityDuration %q, got %q", i, expectedCert.Spec.CertMetadata.ValidityDuration, actualCert.Spec.CertMetadata.ValidityDuration)
				}
				if actualCert.Spec.CertMetadata.CertIdentifier.PubkeyModulus != expectedCert.Spec.CertMetadata.CertIdentifier.PubkeyModulus {
					t.Errorf("CertKeyPair %d: expected PubkeyModulus %q, got %q", i, expectedCert.Spec.CertMetadata.CertIdentifier.PubkeyModulus, actualCert.Spec.CertMetadata.CertIdentifier.PubkeyModulus)
				}
			}

			// Detailed assertions for InMemoryResourceData.CertKeyPairs
			for i, expectedInMemoryCert := range test.expectedInMemoryCertKeyPairs {
				if i >= len(result.InMemoryResourceData.CertKeyPairs) {
					t.Errorf("expected InMemoryCertKeyPair at index %d, but none found", i)
					continue
				}
				actualInMemoryCert := result.InMemoryResourceData.CertKeyPairs[i]
				if actualInMemoryCert.PodLocation.Namespace != expectedInMemoryCert.PodLocation.Namespace {
					t.Errorf("InMemoryCertKeyPair %d: expected PodLocation.Namespace %q, got %q", i, expectedInMemoryCert.PodLocation.Namespace, actualInMemoryCert.PodLocation.Namespace)
				}
				if actualInMemoryCert.PodLocation.Name != expectedInMemoryCert.PodLocation.Name {
					t.Errorf("InMemoryCertKeyPair %d: expected PodLocation.Name %q, got %q", i, expectedInMemoryCert.PodLocation.Name, actualInMemoryCert.PodLocation.Name)
				}
				if actualInMemoryCert.CertKeyInfo.Description != expectedInMemoryCert.CertKeyInfo.Description {
					t.Errorf("InMemoryCertKeyPair %d: expected CertKeyInfo.Description %q, got %q", i, expectedInMemoryCert.CertKeyInfo.Description, actualInMemoryCert.CertKeyInfo.Description)
				}
			}
		})
	}
}

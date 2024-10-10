package manifestclienttest

import (
	"context"
	"os"
	"path/filepath"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	applyconfigv1 "github.com/openshift/client-go/config/applyconfigurations/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/openshift/library-go/pkg/manifestclient"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"net/http"
	"testing"
)

func TestSimpleWritesChecks(t *testing.T) {
	tests := []struct {
		name   string
		testFn func(*testing.T, *http.Client)
	}{
		{
			name: "CREATE-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}

				mutationObj := &configv1.FeatureGate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "new-item",
					},
				}
				resultingObj, err := configClient.ConfigV1().FeatureGates().Create(context.TODO(), mutationObj, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(resultingObj.Name) == 0 {
					t.Fatal(spew.Sdump(resultingObj))
				}
			},
		},
		{
			name: "CREATE-crd-not-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}

				mutationObj := &configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "new-item",
					},
				}
				resultingObj, err := configClient.ConfigV1().APIServers().Create(context.TODO(), mutationObj, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(resultingObj.Name) == 0 {
					t.Fatal(spew.Sdump(resultingObj))
				}
			},
		},
		{
			name: "UPDATE-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}

				mutationObj := &configv1.FeatureGate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "new-item",
					},
				}
				resultingObj, err := configClient.ConfigV1().FeatureGates().Update(context.TODO(), mutationObj, metav1.UpdateOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(resultingObj.Name) == 0 {
					t.Fatal(spew.Sdump(resultingObj))
				}
			},
		},
		{
			name: "UPDATE-STATUS-crd-in-dataset-with-options",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}

				mutationObj := &configv1.FeatureGate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "new-item",
					},
				}
				resultingObj, err := configClient.ConfigV1().FeatureGates().UpdateStatus(context.TODO(), mutationObj, metav1.UpdateOptions{FieldValidation: "Strict"})
				if err != nil {
					t.Fatal(err)
				}
				if len(resultingObj.Name) == 0 {
					t.Fatal(spew.Sdump(resultingObj))
				}
			},
		},
		{
			name: "APPLY-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}

				applyConfig := applyconfigv1.FeatureGate("new-item")
				resultingObj, err := configClient.ConfigV1().FeatureGates().Apply(context.TODO(), applyConfig, metav1.ApplyOptions{
					Force:        true,
					FieldManager: "the-client",
				})
				if err != nil {
					t.Fatal(err)
				}
				if len(resultingObj.Name) == 0 {
					t.Fatal(spew.Sdump(resultingObj))
				}
			},
		},
		{
			name: "APPLY-STATUS-crd-in-dataset-with-options",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}

				applyConfig := applyconfigv1.FeatureGate("new-item").
					WithStatus(
						applyconfigv1.FeatureGateStatus().
							WithConditions(
								applymetav1.Condition().
									WithType("condition-foo").
									WithStatus(metav1.ConditionTrue),
							),
					)
				resultingObj, err := configClient.ConfigV1().FeatureGates().ApplyStatus(context.TODO(), applyConfig, metav1.ApplyOptions{
					Force:        true,
					FieldManager: "the-client",
				})
				if err != nil {
					t.Fatal(err)
				}
				if len(resultingObj.Name) == 0 {
					t.Fatal(spew.Sdump(resultingObj))
				}
			},
		},
		{
			name: "DELETE-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}

				err = configClient.ConfigV1().FeatureGates().Delete(context.TODO(), "cluster", metav1.DeleteOptions{
					PropagationPolicy: ptr.To(metav1.DeletePropagationForeground),
				})
				if err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, roundTripperTest := range defaultRoundTrippers(t) {
		t.Run(roundTripperTest.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					mutationTrackingClient := roundTripperTest.getClient()
					test.testFn(t, mutationTrackingClient.GetHTTPClient())
					actualMutations := mutationTrackingClient.GetMutations()
					actualRequests := actualMutations.AllRequests()

					expectedRequests, err := manifestclient.ReadEmbeddedMutationDirectory(packageTestData, filepath.Join("testdata", "mutation-tests", test.name))
					if err != nil {
						t.Fatal(err)
					}

					const updateEnvVar = "UPDATE_MUTATION_TEST_DATA"
					if os.Getenv(updateEnvVar) == "true" {
						mutationDir := filepath.Join("testdata", "mutation-tests", test.name)
						err := manifestclient.WriteMutationDirectory(mutationDir, actualMutations.AllRequests()...)
						if err != nil {
							t.Fatal(err)
						} else {
							t.Logf("Updated data")
						}
					}

					if !manifestclient.AreAllSerializedRequestsEquivalent(actualRequests, expectedRequests.AllRequests()) {
						t.Logf("Re-run with `UPDATE_MUTATION_TEST_DATA=true` to write new expected test data")
						t.Fatal(cmp.Diff(actualRequests, expectedRequests.AllRequests()))
					}
				})
			}
		})
	}
}

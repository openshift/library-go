package manifestclienttest

import (
	"context"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

	configv1 "github.com/openshift/api/config/v1"
	applyconfigv1 "github.com/openshift/client-go/config/applyconfigurations/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/openshift/library-go/pkg/manifestclient"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
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
			name: "UPDATE-crd-in-dataset-with-controller-name",
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
				ctx := manifestclient.WithControllerInstanceNameFromContext(context.TODO(), "fooController")
				resultingObj, err := configClient.ConfigV1().FeatureGates().Update(ctx, mutationObj, metav1.UpdateOptions{})
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
			name: "PATCH-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) {
				configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}

				ctx := manifestclient.WithControllerInstanceNameFromContext(context.TODO(), "fooController")

				resultingObj, err := configClient.ConfigV1().FeatureGates().Patch(
					ctx,
					"instance-name",
					types.JSONPatchType,
					[]byte("json-patch"),
					metav1.PatchOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(resultingObj.Name) == 0 {
					t.Fatal(spew.Sdump(resultingObj))
				}

				resultingObj, err = configClient.ConfigV1().FeatureGates().Patch(
					ctx,
					"instance-name",
					types.JSONPatchType,
					[]byte("json-patch"),
					metav1.PatchOptions{},
					"status")
				if err != nil {
					t.Fatal(err)
				}
				if len(resultingObj.Name) == 0 {
					t.Fatal(spew.Sdump(resultingObj))
				}

				// the dynamic client uses unstructured.UnstructuredJSONScheme decoder,
				// which requires type info for decoding.
				// TODO: refactor the test to exercise both clients.
				dynamicClient, err := dynamic.NewForConfigAndClient(&rest.Config{}, httpClient)
				if err != nil {
					t.Fatal(err)
				}
				unstructuredResultingObj, err := dynamicClient.Resource(configv1.GroupVersion.WithResource("featuregates")).Patch(
					ctx,
					"instance-name",
					types.JSONPatchType,
					[]byte("json-patch"),
					metav1.PatchOptions{},
				)
				if err != nil {
					t.Fatal(err)
				}
				resultingObj = &configv1.FeatureGate{}
				if err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredResultingObj.Object, &resultingObj); err != nil {
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

					testFS, err := fs.Sub(packageTestData, filepath.Join("testdata", "mutation-tests", test.name))
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
						t.Errorf("updated. now re-run your test")
					}

					expectedRequests, err := manifestclient.ReadEmbeddedMutationDirectory(testFS)
					if err != nil {
						t.Fatal(err)
					}

					if !manifestclient.AreAllSerializedRequestsEquivalent(actualRequests, expectedRequests.AllRequests()) {
						t.Logf("Re-run with `UPDATE_MUTATION_TEST_DATA=true` to write new expected test data")
						t.Log(expectedRequests.AllRequests())
						t.Fatal(cmp.Diff(actualRequests, expectedRequests.AllRequests()))
					}
				})
			}
		})
	}
}

package manifestclienttest

import (
	"bytes"
	"context"
	"k8s.io/utils/ptr"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	applyconfigv1 "github.com/openshift/client-go/config/applyconfigurations/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/openshift/library-go/pkg/manifestclient"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/rest"
	"net/http"
	"sigs.k8s.io/yaml"
	"testing"
)

func featureGateYAMLBytesOrDie(obj *configv1.FeatureGate) []byte {
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		panic(err)
	}
	unstructuredObj["apiVersion"] = "config.openshift.io/v1"
	unstructuredObj["kind"] = "FeatureGate"
	retBytes, err := yaml.Marshal(unstructuredObj)
	if err != nil {
		panic(err)
	}
	return retBytes
}

func apiserverYAMLBytesOrDie(obj *configv1.APIServer) []byte {
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		panic(err)
	}
	unstructuredObj["apiVersion"] = "config.openshift.io/v1"
	unstructuredObj["kind"] = "APIServer"
	retBytes, err := yaml.Marshal(unstructuredObj)
	if err != nil {
		panic(err)
	}
	return retBytes
}
func TestSimpleWritesChecks(t *testing.T) {
	tests := []struct {
		name   string
		testFn func(*testing.T, *http.Client) (location manifestclient.ActionMetadata, expectedBodyBytes, expectedOptionsBytes []byte)
	}{
		{
			name: "CREATE-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.ActionMetadata, []byte, []byte) {
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

				return manifestclient.ActionMetadata{
						Action: manifestclient.ActionCreate,
						GVR: schema.GroupVersionResource{
							Group:    "config.openshift.io",
							Version:  "v1",
							Resource: "featuregates",
						},
						Namespace: "",
						Name:      "new-item",
					},
					featureGateYAMLBytesOrDie(mutationObj),
					[]byte("{}\n")
			},
		},
		{
			name: "CREATE-crd-not-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.ActionMetadata, []byte, []byte) {
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

				return manifestclient.ActionMetadata{
						Action: manifestclient.ActionCreate,
						GVR: schema.GroupVersionResource{
							Group:    "config.openshift.io",
							Version:  "v1",
							Resource: "apiservers",
						},
						Namespace: "",
						Name:      "new-item",
					},
					apiserverYAMLBytesOrDie(mutationObj),
					[]byte("{}\n")
			},
		},
		{
			name: "UPDATE-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.ActionMetadata, []byte, []byte) {
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

				return manifestclient.ActionMetadata{
						Action: manifestclient.ActionUpdate,
						GVR: schema.GroupVersionResource{
							Group:    "config.openshift.io",
							Version:  "v1",
							Resource: "featuregates",
						},
						Namespace: "",
						Name:      "new-item",
					},
					featureGateYAMLBytesOrDie(mutationObj),
					[]byte("{}\n")
			},
		},
		{
			name: "UPDATE-STATUS-crd-in-dataset-with-options",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.ActionMetadata, []byte, []byte) {
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

				return manifestclient.ActionMetadata{
						Action: manifestclient.ActionUpdateStatus,
						GVR: schema.GroupVersionResource{
							Group:    "config.openshift.io",
							Version:  "v1",
							Resource: "featuregates",
						},
						Namespace: "",
						Name:      "new-item",
					},
					featureGateYAMLBytesOrDie(mutationObj),
					[]byte("fieldValidation: Strict\n")
			},
		},
		{
			name: "APPLY-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.ActionMetadata, []byte, []byte) {
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

				applyBytes, err := yaml.Marshal(applyConfig)
				if err != nil {
					t.Fatal(err)
				}

				return manifestclient.ActionMetadata{
						Action: manifestclient.ActionApply,
						GVR: schema.GroupVersionResource{
							Group:    "config.openshift.io",
							Version:  "v1",
							Resource: "featuregates",
						},
						Namespace: "",
						Name:      "new-item",
					},
					applyBytes,
					[]byte("fieldManager: the-client\nforce: true\n")
			},
		},
		{
			name: "APPLY-STATUS-crd-in-dataset-with-options",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.ActionMetadata, []byte, []byte) {
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

				applyBytes, err := yaml.Marshal(applyConfig)
				if err != nil {
					t.Fatal(err)
				}

				return manifestclient.ActionMetadata{
						Action: manifestclient.ActionApplyStatus,
						GVR: schema.GroupVersionResource{
							Group:    "config.openshift.io",
							Version:  "v1",
							Resource: "featuregates",
						},
						Namespace: "",
						Name:      "new-item",
					},
					applyBytes,
					[]byte("fieldManager: the-client\nforce: true\n")
			},
		},
		{
			name: "DELETE-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.ActionMetadata, []byte, []byte) {
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

				return manifestclient.ActionMetadata{
						Action: manifestclient.ActionDelete,
						GVR: schema.GroupVersionResource{
							Group:    "config.openshift.io",
							Version:  "v1",
							Resource: "featuregates",
						},
						Namespace: "",
						Name:      "cluster",
					},
					[]byte("apiVersion: config.openshift.io/v1\nkind: DeleteOptions\npropagationPolicy: Foreground\n"),
					[]byte("{}\n")
			},
		},
	}

	for _, roundTripperTest := range defaultRoundTrippers(t) {
		t.Run(roundTripperTest.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					mutationTrackingClient := roundTripperTest.getClient()
					expectedMetadata, expectedBodyBytes, expectedOptionsBytes := test.testFn(t, mutationTrackingClient.GetHTTPClient())
					mutations := mutationTrackingClient.GetMutations()
					serializedRequests := mutations.MutationsForMetadata(expectedMetadata)
					if len(serializedRequests) != 1 {
						t.Fatal(spew.Sdump(mutations))
					}
					if !bytes.Equal(serializedRequests[0].Body, expectedBodyBytes) {
						t.Fatal(cmp.Diff(string(serializedRequests[0].Body), string(expectedBodyBytes)))
					}
					if !bytes.Equal(serializedRequests[0].Options, expectedOptionsBytes) {
						t.Fatal(cmp.Diff(string(serializedRequests[0].Options), string(expectedOptionsBytes)))
					}
				})
			}
		})
	}
}

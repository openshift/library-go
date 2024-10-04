package manifestclienttest

import (
	"context"

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
	"k8s.io/utils/ptr"
	"net/http"
	"sigs.k8s.io/yaml"
	"testing"
)

var (
	featureGateGVR = schema.GroupVersionResource{
		Group:    "config.openshift.io",
		Version:  "v1",
		Resource: "featuregates",
	}
	featureGateGVK = schema.GroupVersionKind{
		Group:   "config.openshift.io",
		Version: "v1",
		Kind:    "FeatureGate",
	}
	apiserverGVR = schema.GroupVersionResource{
		Group:    "config.openshift.io",
		Version:  "v1",
		Resource: "apiservers",
	}
	apiserverGVK = schema.GroupVersionKind{
		Group:   "config.openshift.io",
		Version: "v1",
		Kind:    "APIServer",
	}
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
		testFn func(*testing.T, *http.Client) (action manifestclient.Action, serializedRequests []manifestclient.SerializedRequestish)
	}{
		{
			name: "CREATE-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.Action, []manifestclient.SerializedRequestish) {
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

				return manifestclient.ActionCreate,
					[]manifestclient.SerializedRequestish{
						manifestclient.SerializedRequest{
							ResourceType: featureGateGVR,
							KindType:     featureGateGVK,
							Namespace:    "",
							Name:         "new-item",
							Options:      []byte("{}\n"),
							Body:         featureGateYAMLBytesOrDie(mutationObj),
						},
					}
			},
		},
		{
			name: "CREATE-crd-not-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.Action, []manifestclient.SerializedRequestish) {
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

				return manifestclient.ActionCreate,
					[]manifestclient.SerializedRequestish{
						manifestclient.SerializedRequest{
							ResourceType: apiserverGVR,
							KindType:     apiserverGVK,
							Namespace:    "",
							Name:         "new-item",
							Options:      []byte("{}\n"),
							Body:         apiserverYAMLBytesOrDie(mutationObj),
						},
					}
			},
		},
		{
			name: "UPDATE-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.Action, []manifestclient.SerializedRequestish) {
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

				return manifestclient.ActionUpdate,
					[]manifestclient.SerializedRequestish{
						manifestclient.SerializedRequest{
							ResourceType: featureGateGVR,
							KindType:     featureGateGVK,
							Namespace:    "",
							Name:         "new-item",
							Options:      []byte("{}\n"),
							Body:         featureGateYAMLBytesOrDie(mutationObj),
						},
					}
			},
		},
		{
			name: "UPDATE-STATUS-crd-in-dataset-with-options",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.Action, []manifestclient.SerializedRequestish) {
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

				return manifestclient.ActionUpdateStatus,
					[]manifestclient.SerializedRequestish{
						manifestclient.SerializedRequest{
							ResourceType: featureGateGVR,
							KindType:     featureGateGVK,
							Namespace:    "",
							Name:         "new-item",
							Options:      []byte("fieldValidation: Strict\n"),
							Body:         featureGateYAMLBytesOrDie(mutationObj),
						},
					}

			},
		},
		{
			name: "APPLY-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.Action, []manifestclient.SerializedRequestish) {
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

				return manifestclient.ActionApply,
					[]manifestclient.SerializedRequestish{
						manifestclient.SerializedRequest{
							ResourceType: featureGateGVR,
							KindType:     featureGateGVK,
							Namespace:    "",
							Name:         "new-item",
							Options:      []byte("fieldManager: the-client\nforce: true\n"),
							Body:         applyBytes,
						},
					}
			},
		},
		{
			name: "APPLY-STATUS-crd-in-dataset-with-options",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.Action, []manifestclient.SerializedRequestish) {
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

				return manifestclient.ActionApplyStatus,
					[]manifestclient.SerializedRequestish{
						manifestclient.SerializedRequest{
							ResourceType: featureGateGVR,
							KindType:     featureGateGVK,
							Namespace:    "",
							Name:         "new-item",
							Options:      []byte("fieldManager: the-client\nforce: true\n"),
							Body:         applyBytes,
						},
					}
			},
		},
		{
			name: "DELETE-crd-in-dataset",
			testFn: func(t *testing.T, httpClient *http.Client) (manifestclient.Action, []manifestclient.SerializedRequestish) {
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

				return manifestclient.ActionDelete,
					[]manifestclient.SerializedRequestish{
						manifestclient.SerializedRequest{
							ResourceType: featureGateGVR,
							KindType: schema.GroupVersionKind{
								Group:   "config.openshift.io",
								Version: "v1",
								Kind:    "DeleteOptions",
							},
							Namespace: "",
							Name:      "cluster",
							Options:   []byte("{}\n"),
							Body:      []byte("apiVersion: config.openshift.io/v1\nkind: DeleteOptions\npropagationPolicy: Foreground\n"),
						},
					}
			},
		},
	}

	for _, roundTripperTest := range defaultRoundTrippers(t) {
		t.Run(roundTripperTest.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					mutationTrackingClient := roundTripperTest.getClient()
					expectedAction, expectedSerializedRequests := test.testFn(t, mutationTrackingClient.GetHTTPClient())
					mutations := mutationTrackingClient.GetMutations()
					actualSerializedRequestsForAction := mutations.MutationsForAction(expectedAction)

					actualSerializedRequests := []manifestclient.TrackedSerializedRequest{}
					for _, resourceActions := range actualSerializedRequestsForAction.ResourceToTracker {
						for _, namespaceActions := range resourceActions.NamespaceToTracker {
							for _, nameActions := range namespaceActions.NameToTracker {
								actualSerializedRequests = append(actualSerializedRequests, nameActions.SerializedRequests...)
							}
						}
					}

					if !manifestclient.AreAllSerializedRequestsEquivalent(actualSerializedRequests, expectedSerializedRequests) {
						t.Fatal(cmp.Diff(actualSerializedRequests, expectedSerializedRequests))
					}
				})
			}
		})
	}
}

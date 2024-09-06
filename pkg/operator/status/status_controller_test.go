package status

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/client-go/config/clientset/versioned/fake"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/stretchr/testify/assert"

	"github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestDegraded(t *testing.T) {

	threeMinutesAgo := metav1.NewTime(time.Now().Add(-3 * time.Minute))
	fiveSecondsAgo := metav1.NewTime(time.Now().Add(-2 * time.Second))
	yesterday := metav1.NewTime(time.Now().Add(-24 * time.Hour))

	testCases := []struct {
		name             string
		conditions       []operatorv1.OperatorCondition
		expectedType     configv1.ClusterStatusConditionType
		expectedStatus   configv1.ConditionStatus
		expectedMessages []string
		expectedReason   string
	}{
		{
			name:           "no data",
			conditions:     []operatorv1.OperatorCondition{},
			expectedStatus: configv1.ConditionUnknown,
			expectedReason: "NoData",
		},
		{
			name: "one not failing/within threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: fiveSecondsAgo, Message: "a message from type a"},
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: "AsExpected",
			expectedMessages: []string{
				"TypeADegraded: a message from type a",
			},
		},
		{
			name: "one not failing/beyond threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: threeMinutesAgo, Message: "a message from type a"},
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: "AsExpected",
			expectedMessages: []string{
				"TypeADegraded: a message from type a",
			},
		},
		{
			name: "one failing/within threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type a"},
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: "AsExpected",
			expectedMessages: []string{
				"TypeADegraded: a message from type a",
			},
		},
		{
			name: "one failing/beyond threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionTrue, Message: "a message from type a", LastTransitionTime: threeMinutesAgo},
			},
			expectedStatus: configv1.ConditionTrue,
			expectedReason: "TypeA",
			expectedMessages: []string{
				"TypeADegraded: a message from type a",
			},
		},
		{
			name: "two present/one failing/within threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type a"},
				{Type: "TypeBDegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: yesterday},
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: "AsExpected",
			expectedMessages: []string{
				"TypeADegraded: a message from type a",
			},
		},
		{
			name: "two present/one failing/beyond threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: threeMinutesAgo, Message: "a message from type a"},
				{Type: "TypeBDegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: yesterday},
			},
			expectedStatus: configv1.ConditionTrue,
			expectedReason: "TypeA",
			expectedMessages: []string{
				"TypeADegraded: a message from type a",
			},
		},
		{
			name: "two present/second one failing/within threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: yesterday},
				{Type: "TypeBDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type b"},
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: "AsExpected",
			expectedMessages: []string{
				"TypeBDegraded: a message from type b",
			},
		},
		{
			name: "two present/second one failing/beyond threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: yesterday},
				{Type: "TypeBDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: threeMinutesAgo, Message: "a message from type b"},
			},
			expectedStatus: configv1.ConditionTrue,
			expectedReason: "TypeB",
			expectedMessages: []string{
				"TypeBDegraded: a message from type b",
			},
		},
		{
			name: "many present/some failing/all within threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: yesterday},
				{Type: "TypeBDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type b\nanother message from type b"},
				{Type: "TypeCDegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: threeMinutesAgo, Message: "a message from type c"},
				{Type: "TypeDDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type d"},
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: "AsExpected",
			expectedMessages: []string{
				"TypeBDegraded: a message from type b",
				"TypeBDegraded: another message from type b",
				"TypeCDegraded: a message from type c",
				"TypeDDegraded: a message from type d",
			},
		},
		{
			name: "many present/some failing/all within custom threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: yesterday},
				{Type: "TypeBDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type b\nanother message from type b"},
				{Type: "TypeCDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: threeMinutesAgo, Message: "a message from type c"},
				{Type: "TypeDDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type d"},
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: "AsExpected",
			expectedMessages: []string{
				"TypeBDegraded: a message from type b",
				"TypeBDegraded: another message from type b",
				"TypeCDegraded: a message from type c",
				"TypeDDegraded: a message from type d",
			},
		},
		{
			name: "many present/some failing/some within threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: yesterday},
				{Type: "TypeBDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type b\nanother message from type b"},
				{Type: "TypeCDegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: threeMinutesAgo, Message: "a message from type c"},
				{Type: "TypeDDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: threeMinutesAgo, Message: "a message from type d"},
			},
			expectedStatus: configv1.ConditionTrue,
			expectedReason: "TypeB::TypeD",
			expectedMessages: []string{
				"TypeBDegraded: a message from type b",
				"TypeBDegraded: another message from type b",
				"TypeDDegraded: a message from type d",
			},
		},
		{
			name: "many present/some failing/some beyond custom threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: yesterday},
				{Type: "TypeBDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type b\nanother message from type b"},
				{Type: "TypeCDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: threeMinutesAgo, Message: "a message from type c"},
				{Type: "TypeDDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: threeMinutesAgo, Message: "a message from type d"},
			},
			expectedStatus: configv1.ConditionTrue,
			expectedReason: "TypeB::TypeC::TypeD",
			expectedMessages: []string{
				"TypeBDegraded: a message from type b",
				"TypeBDegraded: another message from type b",
				"TypeCDegraded: a message from type c",
				"TypeDDegraded: a message from type d",
			},
		},
		{
			name: "many present/some failing/all beyond threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeADegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: yesterday},
				{Type: "TypeBDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: threeMinutesAgo, Message: "a message from type b\nanother message from type b"},
				{Type: "TypeCDegraded", Status: operatorv1.ConditionFalse, LastTransitionTime: threeMinutesAgo, Message: "a message from type c"},
				{Type: "TypeDDegraded", Status: operatorv1.ConditionTrue, LastTransitionTime: threeMinutesAgo, Message: "a message from type d"},
			},
			expectedStatus: configv1.ConditionTrue,
			expectedReason: "TypeB::TypeD",
			expectedMessages: []string{
				"TypeBDegraded: a message from type b",
				"TypeBDegraded: another message from type b",
				"TypeDDegraded: a message from type d",
			},
		},
		{
			name: "one progressing/within threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeAProgressing", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a message from type a"},
			},
			expectedType:   configv1.OperatorProgressing,
			expectedStatus: configv1.ConditionTrue,
			expectedReason: "TypeA",
			expectedMessages: []string{
				"TypeAProgressing: a message from type a",
			},
		},
		{
			name: "one EvaluationConditionDetected in conditions",
			conditions: []operatorv1.OperatorCondition{
				{
					Type:               string(configv1.EvaluationConditionsDetected),
					Status:             operatorv1.ConditionTrue,
					LastTransitionTime: fiveSecondsAgo,
					Message:            "a message from evaluation detection",
					Reason:             "PodSecurityReadinessController",
				},
			},
			expectedType:   configv1.EvaluationConditionsDetected,
			expectedStatus: configv1.ConditionTrue,
			expectedReason: "_PodSecurityReadinessController",
			expectedMessages: []string{
				"EvaluationConditionsDetected: a message from evaluation detection",
			},
		},
		{
			name: "one not available/within threshold",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeAAvailable", Status: operatorv1.ConditionFalse, LastTransitionTime: fiveSecondsAgo, Message: "a message from type a"},
			},
			expectedType:   configv1.OperatorAvailable,
			expectedStatus: configv1.ConditionFalse,
			expectedReason: "TypeA",
			expectedMessages: []string{
				"TypeAAvailable: a message from type a",
			},
		},
		{
			name: "two present/one available/one unknown",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeAAvailable", Status: operatorv1.ConditionTrue, LastTransitionTime: fiveSecondsAgo, Message: "a is great"},
				{Type: "TypeBAvailable", Status: operatorv1.ConditionUnknown, LastTransitionTime: fiveSecondsAgo, Message: "b is confused"},
			},
			expectedType:   configv1.OperatorAvailable,
			expectedStatus: configv1.ConditionUnknown,
			expectedReason: "TypeB",
			expectedMessages: []string{
				"TypeBAvailable: b is confused",
			},
		},
		{
			name: "two present/one unavailable/one unknown",
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeAAvailable", Status: operatorv1.ConditionFalse, LastTransitionTime: fiveSecondsAgo, Message: "a is bad", Reason: "Something"},
				{Type: "TypeBAvailable", Status: operatorv1.ConditionUnknown, LastTransitionTime: fiveSecondsAgo, Message: "b is confused"},
			},
			expectedType:   configv1.OperatorAvailable,
			expectedStatus: configv1.ConditionFalse,
			expectedReason: "TypeA_Something::TypeB",
			expectedMessages: []string{
				"TypeAAvailable: a is bad",
				"TypeBAvailable: b is confused",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, condition := range tc.conditions {
				if condition.LastTransitionTime == (metav1.Time{}) {
					t.Fatal("LastTransitionTime not set.")
				}
			}
			if tc.expectedType == "" {
				tc.expectedType = configv1.OperatorDegraded
			}
			clusterOperator := &configv1.ClusterOperator{
				ObjectMeta: metav1.ObjectMeta{Name: "OPERATOR_NAME", ResourceVersion: "12"},
			}
			clusterOperatorClient := fake.NewSimpleClientset(clusterOperator)

			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			indexer.Add(clusterOperator)

			statusClient := &statusClient{
				t: t,
				status: operatorv1.OperatorStatus{
					Conditions: tc.conditions,
				},
			}
			controller := &StatusSyncer{
				clusterOperatorName:   "OPERATOR_NAME",
				clusterOperatorClient: clusterOperatorClient.ConfigV1(),
				clusterOperatorLister: configv1listers.NewClusterOperatorLister(indexer),
				operatorClient:        statusClient,
				versionGetter:         NewVersionGetter(),
			}
			controller = controller.WithDegradedInertia(MustNewInertia(
				2*time.Minute,
				InertiaCondition{
					ConditionTypeMatcher: regexp.MustCompile("^TypeCDegraded$"),
					Duration:             5 * time.Minute,
				},
				InertiaCondition{
					ConditionTypeMatcher: regexp.MustCompile("^TypeDDegraded$"),
					Duration:             time.Minute,
				},
			).Inertia)
			if err := controller.Sync(context.TODO(), factory.NewSyncContext("test", events.NewInMemoryRecorder("status"))); err != nil {
				t.Errorf("unexpected sync error: %v", err)
				return
			}
			result, _ := clusterOperatorClient.ConfigV1().ClusterOperators().Get(context.TODO(), "OPERATOR_NAME", metav1.GetOptions{})

			var expectedCondition *configv1.ClusterOperatorStatusCondition
			if tc.expectedStatus != "" {
				expectedCondition = &configv1.ClusterOperatorStatusCondition{
					Type:   tc.expectedType,
					Status: configv1.ConditionStatus(string(tc.expectedStatus)),
				}
				if len(tc.expectedMessages) > 0 {
					expectedCondition.Message = strings.Join(tc.expectedMessages, "\n")
				}
				if len(tc.expectedReason) > 0 {
					expectedCondition.Reason = tc.expectedReason
				}
			}

			for i := range result.Status.Conditions {
				result.Status.Conditions[i].LastTransitionTime = metav1.Time{}
			}

			actual := v1helpers.FindStatusCondition(result.Status.Conditions, tc.expectedType)
			if !reflect.DeepEqual(expectedCondition, actual) {
				t.Error(diff.ObjectDiff(expectedCondition, actual))
			}
		})
	}
}

func TestRelatedObjects(t *testing.T) {
	// save typing
	ref := func(name string) configv1.ObjectReference {
		return configv1.ObjectReference{
			Group:     "A",
			Resource:  "A",
			Namespace: "A",
			Name:      name,
		}
	}

	testCases := []struct {
		name       string
		hasDynamic bool
		staticRO   []configv1.ObjectReference
		dynamicRO  []configv1.ObjectReference
		existingRO []configv1.ObjectReference
		expected   []configv1.ObjectReference
	}{
		{
			name:       "static",
			hasDynamic: false,
			staticRO:   []configv1.ObjectReference{ref("A")},
			existingRO: []configv1.ObjectReference{ref("B")},
			expected:   []configv1.ObjectReference{ref("A")},
		},
		{
			name:       "dynamic",
			hasDynamic: true,
			dynamicRO:  []configv1.ObjectReference{ref("A")},
			existingRO: []configv1.ObjectReference{ref("B")},
			expected:   []configv1.ObjectReference{ref("A")},
		},
		{
			name:       "dynamic and static",
			hasDynamic: true,
			dynamicRO:  []configv1.ObjectReference{ref("A")},
			staticRO:   []configv1.ObjectReference{ref("B")},
			existingRO: []configv1.ObjectReference{ref("C")},
			expected:   []configv1.ObjectReference{ref("A"), ref("B")},
		},
		{
			name:       "dynamic unset",
			hasDynamic: true,
			dynamicRO:  nil,
			existingRO: []configv1.ObjectReference{ref("C")},
			expected:   []configv1.ObjectReference{ref("C")},
		},
		{
			name:       "dynamic unset static existing",
			hasDynamic: true,
			dynamicRO:  nil,
			staticRO:   []configv1.ObjectReference{ref("B")},
			existingRO: []configv1.ObjectReference{ref("C")},
			expected:   []configv1.ObjectReference{ref("B"), ref("C")},
		},
	}
	for idx, tc := range testCases {
		t.Run(fmt.Sprintf("%d/%s", idx, tc.name), func(t *testing.T) {

			clusterOperator := &configv1.ClusterOperator{
				ObjectMeta: metav1.ObjectMeta{Name: "OPERATOR_NAME", ResourceVersion: "12"},
				Status: configv1.ClusterOperatorStatus{
					RelatedObjects: tc.existingRO,
				},
			}
			clusterOperatorClient := fake.NewSimpleClientset(clusterOperator)

			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			indexer.Add(clusterOperator)

			statusClient := &statusClient{
				t:      t,
				status: operatorv1.OperatorStatus{},
			}
			controller := &StatusSyncer{
				clusterOperatorName:   "OPERATOR_NAME",
				clusterOperatorClient: clusterOperatorClient.ConfigV1(),
				clusterOperatorLister: configv1listers.NewClusterOperatorLister(indexer),
				operatorClient:        statusClient,
				versionGetter:         NewVersionGetter(),
				relatedObjects:        tc.staticRO,
			}
			controller = controller.WithDegradedInertia(MustNewInertia(
				2*time.Minute,
				InertiaCondition{
					ConditionTypeMatcher: regexp.MustCompile("^TypeCDegraded$"),
					Duration:             5 * time.Minute,
				},
				InertiaCondition{
					ConditionTypeMatcher: regexp.MustCompile("^TypeDDegraded$"),
					Duration:             time.Minute,
				},
			).Inertia)

			if tc.hasDynamic {
				controller.WithRelatedObjectsFunc(func() (bool, []configv1.ObjectReference) {
					if tc.dynamicRO == nil {
						return false, nil
					}
					return true, tc.dynamicRO
				})
			}

			if err := controller.Sync(context.TODO(), factory.NewSyncContext("test", events.NewInMemoryRecorder("status"))); err != nil {
				t.Errorf("unexpected sync error: %v", err)
				return
			}
			result, _ := clusterOperatorClient.ConfigV1().ClusterOperators().Get(context.TODO(), "OPERATOR_NAME", metav1.GetOptions{})
			assert.ElementsMatch(t, tc.expected, result.Status.RelatedObjects)
		})
	}

}

func TestVersions(t *testing.T) {
	foo1 := configv1.OperandVersion{
		Name:    "foo",
		Version: "1",
	}
	bar1 := configv1.OperandVersion{
		Name:    "bar",
		Version: "1",
	}
	bar2 := configv1.OperandVersion{
		Name:    "bar",
		Version: "2",
	}

	testCases := []struct {
		name             string
		allowRemoval     bool
		initialVersions  []configv1.OperandVersion
		getterVersions   map[string]string
		expectedVersions []configv1.OperandVersion
	}{
		{
			name:             "empty version",
			initialVersions:  []configv1.OperandVersion{},
			getterVersions:   map[string]string{},
			expectedVersions: []configv1.OperandVersion{},
		},
		{
			name:             "version added",
			initialVersions:  []configv1.OperandVersion{},
			getterVersions:   map[string]string{"foo": "1", "bar": "2"},
			expectedVersions: []configv1.OperandVersion{foo1, bar2},
		},
		{
			name:             "version changed",
			initialVersions:  []configv1.OperandVersion{foo1, bar1},
			getterVersions:   map[string]string{"foo": "1", "bar": "2"},
			expectedVersions: []configv1.OperandVersion{foo1, bar2},
		},
		{
			name:             "no version changed",
			initialVersions:  []configv1.OperandVersion{foo1, bar2},
			getterVersions:   map[string]string{"foo": "1", "bar": "2"},
			expectedVersions: []configv1.OperandVersion{foo1, bar2},
		},
		{
			name:             "non-removable version removed",
			initialVersions:  []configv1.OperandVersion{foo1, bar1},
			getterVersions:   map[string]string{"foo": "1"},
			expectedVersions: []configv1.OperandVersion{foo1, bar1},
		},
		{
			name:             "no version changed (removable)",
			allowRemoval:     true,
			initialVersions:  []configv1.OperandVersion{foo1, bar2},
			getterVersions:   map[string]string{"foo": "1", "bar": "2"},
			expectedVersions: []configv1.OperandVersion{foo1, bar2},
		},
		{
			name:             "removable version removed",
			allowRemoval:     true,
			initialVersions:  []configv1.OperandVersion{foo1, bar1},
			getterVersions:   map[string]string{"foo": "1"},
			expectedVersions: []configv1.OperandVersion{foo1},
		},
	}
	for idx, tc := range testCases {
		t.Run(fmt.Sprintf("%d/%s", idx, tc.name), func(t *testing.T) {

			clusterOperator := &configv1.ClusterOperator{
				ObjectMeta: metav1.ObjectMeta{Name: "OPERATOR_NAME", ResourceVersion: "12"},
				Status: configv1.ClusterOperatorStatus{
					Versions: tc.initialVersions,
				},
			}
			clusterOperatorClient := fake.NewSimpleClientset(clusterOperator)

			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			indexer.Add(clusterOperator)

			statusClient := &statusClient{
				t:      t,
				status: operatorv1.OperatorStatus{},
			}
			versionGetter := NewVersionGetter()
			for operand, v := range tc.getterVersions {
				versionGetter.SetVersion(operand, v)
			}

			controller := &StatusSyncer{
				clusterOperatorName:   "OPERATOR_NAME",
				clusterOperatorClient: clusterOperatorClient.ConfigV1(),
				clusterOperatorLister: configv1listers.NewClusterOperatorLister(indexer),
				operatorClient:        statusClient,
				versionGetter:         versionGetter,
			}
			if tc.allowRemoval {
				controller = controller.WithVersionRemoval()
			}
			if err := controller.Sync(context.TODO(), factory.NewSyncContext("test", events.NewInMemoryRecorder("status"))); err != nil {
				t.Errorf("unexpected sync error: %v", err)
				return
			}
			result, _ := clusterOperatorClient.ConfigV1().ClusterOperators().Get(context.TODO(), "OPERATOR_NAME", metav1.GetOptions{})
			assert.ElementsMatch(t, tc.expectedVersions, result.Status.Versions)
		})
	}
}

// OperatorStatusProvider
type statusClient struct {
	t      *testing.T
	spec   operatorv1.OperatorSpec
	status operatorv1.OperatorStatus
}

func (c *statusClient) Informer() cache.SharedIndexInformer {
	c.t.Log("Informer called")
	return nil
}

func (c *statusClient) GetObjectMeta() (*metav1.ObjectMeta, error) {
	panic("missing")
}

func (c *statusClient) GetOperatorState() (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	return &c.spec, &c.status, "", nil
}

func (c *statusClient) GetOperatorStateWithQuorum(ctx context.Context) (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	return c.GetOperatorState()
}

func (c *statusClient) UpdateOperatorSpec(context.Context, string, *operatorv1.OperatorSpec) (spec *operatorv1.OperatorSpec, resourceVersion string, err error) {
	panic("missing")
}

func (c *statusClient) UpdateOperatorStatus(context.Context, string, *operatorv1.OperatorStatus) (status *operatorv1.OperatorStatus, err error) {
	panic("missing")
}

func (c *statusClient) ApplyOperatorSpec(ctx context.Context, fieldManager string, applyConfiguration *applyoperatorv1.OperatorSpecApplyConfiguration) (err error) {
	panic("missing")
}

func (c *statusClient) ApplyOperatorStatus(ctx context.Context, fieldManager string, applyConfiguration *applyoperatorv1.OperatorStatusApplyConfiguration) (err error) {
	panic("missing")
}

func TestSkipOperatorStatusChangedEvent(t *testing.T) {
	testCases := []struct {
		name         string
		original     configv1.ClusterOperatorStatus
		updated      configv1.ClusterOperatorStatus
		skipExpected bool
	}{
		{
			name: "skip, happy",
			original: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "\ufeffTest", Type: configv1.OperatorAvailable},
					{Message: "\ufeffTest", Type: configv1.OperatorProgressing},
					{Message: "\ufeffTest", Type: configv1.OperatorDegraded},
					{Message: "\ufeffTest", Type: configv1.OperatorUpgradeable},
				},
			},
			updated: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "Test", Type: configv1.OperatorAvailable},
					{Message: "Test", Type: configv1.OperatorProgressing},
					{Message: "Test", Type: configv1.OperatorDegraded},
					{Message: "Test", Type: configv1.OperatorUpgradeable},
				},
			},
			skipExpected: true,
		},
		{
			name: "no skip, something else changed",
			original: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "\ufeffTest", Type: configv1.OperatorAvailable},
					{Message: "\ufeffTest", Type: configv1.OperatorProgressing},
					{Message: "\ufeffTest", Type: configv1.OperatorDegraded},
					{Message: "\ufeffTest", Type: configv1.OperatorUpgradeable},
				},
				Versions: []configv1.OperandVersion{{Name: "TEST", Version: "1.0"}},
			},
			updated: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "Test", Type: configv1.OperatorAvailable},
					{Message: "Test", Type: configv1.OperatorProgressing},
					{Message: "Test", Type: configv1.OperatorDegraded},
					{Message: "Test", Type: configv1.OperatorUpgradeable},
				},
				Versions: []configv1.OperandVersion{{Name: "TEST", Version: "2.0"}},
			},
			skipExpected: false,
		},
		{
			name: "skip, partial challenge",
			original: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "\ufeffTest", Type: configv1.OperatorAvailable},
					{Message: "\ufeffTest", Type: configv1.OperatorProgressing},
					{Message: "Test", Type: configv1.OperatorDegraded},
					{Message: "\ufeffTest", Type: configv1.OperatorUpgradeable},
				},
			},
			updated: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "Test", Type: configv1.OperatorAvailable},
					{Message: "Test", Type: configv1.OperatorProgressing},
					{Message: "Test", Type: configv1.OperatorDegraded},
					{Message: "Test", Type: configv1.OperatorUpgradeable},
				},
			},
			skipExpected: true,
		},
		{
			name: "no skip, partial challenge response",
			original: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "\ufeffTest", Type: configv1.OperatorAvailable},
					{Message: "\ufeffTest", Type: configv1.OperatorProgressing},
					{Message: "\ufeffTest", Type: configv1.OperatorDegraded},
					{Message: "\ufeffTest", Type: configv1.OperatorUpgradeable},
				},
			},
			updated: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "Test", Type: configv1.OperatorAvailable},
					{Message: "Test", Type: configv1.OperatorProgressing},
					{Message: "\ufeffTest", Type: configv1.OperatorDegraded},
					{Message: "Test", Type: configv1.OperatorUpgradeable},
				},
			},
			skipExpected: false,
		},
		{
			name: "no skip, non-standard type",
			original: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "\ufeffTest", Type: configv1.OperatorAvailable},
					{Message: "\ufeffTest", Type: configv1.OperatorProgressing},
					{Message: "\ufeffTest", Type: configv1.OperatorDegraded},
					{Message: "\ufeffTest", Type: configv1.OperatorUpgradeable},
					{Message: "\ufeffTest", Type: "NonStandard"},
				},
			},
			updated: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "Test", Type: configv1.OperatorAvailable},
					{Message: "Test", Type: configv1.OperatorProgressing},
					{Message: "Test", Type: configv1.OperatorDegraded},
					{Message: "Test", Type: configv1.OperatorUpgradeable},
					{Message: "Test", Type: "NonStandard"},
				},
			},
			skipExpected: false,
		},
		{
			name: "no skip, non challenge response",
			original: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "Test", Type: configv1.OperatorAvailable},
					{Message: "Test", Type: configv1.OperatorProgressing},
					{Message: "Test", Type: configv1.OperatorDegraded},
					{Message: "Test", Type: configv1.OperatorUpgradeable},
				},
			},
			updated: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "Test", Type: configv1.OperatorAvailable},
					{Message: "Test", Type: configv1.OperatorProgressing},
					{Message: "Test", Type: configv1.OperatorDegraded},
					{Message: "Skip", Type: configv1.OperatorUpgradeable},
				},
			},
			skipExpected: false,
		},
		{
			name: "no skip, non-trivial response",
			original: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "\ufeffTest", Type: configv1.OperatorAvailable},
					{Message: "\ufeffTest", Type: configv1.OperatorProgressing},
					{Message: "\ufeffTest", Type: configv1.OperatorDegraded},
					{Message: "\ufeffTest", Type: configv1.OperatorUpgradeable},
				},
			},
			updated: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{Message: "Test", Type: configv1.OperatorAvailable},
					{Message: "Test", Type: configv1.OperatorProgressing},
					{Message: "Test", Type: configv1.OperatorDegraded},
					{Message: "TestUpdated", Type: configv1.OperatorUpgradeable},
				},
			},
			skipExpected: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipExpected != skipOperatorStatusChangedEvent(tc.original, tc.updated) {
				t.Errorf("expected: %v, got: %v", tc.skipExpected, !tc.skipExpected)
			}
		})
	}
}

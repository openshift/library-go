package apiservice

import (
	"context"
	"fmt"
	"time"

	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	kubeaggregatorfake "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	"k8s.io/kube-aggregator/pkg/client/informers/externalversions"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestAvailableStatus(t *testing.T) {
	testCases := []struct {
		name                               string
		expectedStatus                     operatorv1.ConditionStatus
		expectedReasons                    []string
		expectedMessages                   []string
		existingAPIServices                []runtime.Object
		apiServiceReactor                  kubetesting.ReactionFunc
		daemonReactor                      kubetesting.ReactionFunc
		preconditionsForEnabledAPIServices apiServicesPreconditionFuncType
	}{
		{
			name:           "Default",
			expectedStatus: operatorv1.ConditionTrue,
		},
		{
			name:             "APIServiceCreateFailure",
			expectedStatus:   operatorv1.ConditionFalse,
			expectedReasons:  []string{"Error"},
			expectedMessages: []string{"TEST ERROR: fail to create apiservice"},

			apiServiceReactor: func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetVerb() != "create" {
					return false, nil, nil
				}
				if action.(kubetesting.CreateAction).GetObject().(*apiregistrationv1.APIService).Name == "v1.build.openshift.io" {
					return true, nil, fmt.Errorf("TEST ERROR: fail to create apiservice")
				}
				return false, nil, nil
			},
		},
		{
			name:             "APIServiceGetFailure",
			expectedStatus:   operatorv1.ConditionFalse,
			expectedReasons:  []string{"Error"},
			expectedMessages: []string{"TEST ERROR: fail to get apiservice"},

			existingAPIServices: []runtime.Object{
				runtime.Object(newAPIService("build.openshift.io", "v1")),
				runtime.Object(newAPIService("apps.openshift.io", "v1")),
			},
			apiServiceReactor: func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetVerb() == "get" && action.(kubetesting.GetAction).GetName() == "v1.build.openshift.io" {
					return true, nil, fmt.Errorf("TEST ERROR: fail to get apiservice")
				}
				return false, nil, nil
			},
		},
		{
			name:             "APIServiceNotAvailable",
			expectedStatus:   operatorv1.ConditionFalse,
			expectedReasons:  []string{"Error"},
			expectedMessages: []string{"apiservices.apiregistration.k8s.io/v1.build.openshift.io: not available: TEST MESSAGE"},

			existingAPIServices: []runtime.Object{
				runtime.Object(newAPIService("build.openshift.io", "v1")),
				runtime.Object(newAPIService("apps.openshift.io", "v1")),
			},
			apiServiceReactor: func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetVerb() == "get" && action.(kubetesting.GetAction).GetName() == "v1.build.openshift.io" {
					return true, &apiregistrationv1.APIService{
						ObjectMeta: metav1.ObjectMeta{Name: "v1.build.openshift.io", Annotations: map[string]string{"service.alpha.openshift.io/inject-cabundle": "true"}},
						Spec: apiregistrationv1.APIServiceSpec{
							Group:                "build.openshift.io",
							Version:              "v1",
							Service:              &apiregistrationv1.ServiceReference{Namespace: "target-namespace", Name: "api"},
							GroupPriorityMinimum: 9900,
							VersionPriority:      15,
						},
						Status: apiregistrationv1.APIServiceStatus{
							Conditions: []apiregistrationv1.APIServiceCondition{
								{Type: apiregistrationv1.Available, Status: apiregistrationv1.ConditionFalse, Message: "TEST MESSAGE"},
							},
						},
					}, nil
				}
				return false, nil, nil
			},
		},
		{
			name:            "MultipleAPIServiceNotAvailable",
			expectedStatus:  operatorv1.ConditionFalse,
			expectedReasons: []string{"Error"},
			expectedMessages: []string{
				"apiservices.apiregistration.k8s.io/v1.apps.openshift.io: not available: TEST MESSAGE",
				"apiservices.apiregistration.k8s.io/v1.build.openshift.io: not available: TEST MESSAGE",
			},

			existingAPIServices: []runtime.Object{
				runtime.Object(newAPIService("build.openshift.io", "v1")),
				runtime.Object(newAPIService("apps.openshift.io", "v1")),
			},
			apiServiceReactor: func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetVerb() != "get" {
					return false, nil, nil
				}

				switch action.(kubetesting.GetAction).GetName() {
				case "v1.build.openshift.io":
					fallthrough
				case "v1.apps.openshift.io":
					return true, &apiregistrationv1.APIService{
						ObjectMeta: metav1.ObjectMeta{Name: action.(kubetesting.GetAction).GetName(), Annotations: map[string]string{"service.alpha.openshift.io/inject-cabundle": "true"}},
						Spec: apiregistrationv1.APIServiceSpec{
							Group:                action.GetResource().Group,
							Version:              action.GetResource().Version,
							Service:              &apiregistrationv1.ServiceReference{Namespace: "target-namespace", Name: "api"},
							GroupPriorityMinimum: 9900,
							VersionPriority:      15,
						},
						Status: apiregistrationv1.APIServiceStatus{
							Conditions: []apiregistrationv1.APIServiceCondition{
								{Type: apiregistrationv1.Available, Status: apiregistrationv1.ConditionFalse, Message: "TEST MESSAGE"},
							},
						},
					}, nil
				default:
					return false, nil, nil
				}
			},
		},
		{
			name: "PreconditionsError",
			preconditionsForEnabledAPIServices: func([]*apiregistrationv1.APIService) (bool, error) {
				return false, fmt.Errorf("dummy error")
			},
			expectedStatus:  operatorv1.ConditionFalse,
			expectedReasons: []string{"ErrorCheckingPrecondition"},
			expectedMessages: []string{
				"dummy error",
			},
		},
		{
			name: "PreconditionsErrorEvenWhenStatusTrue",
			preconditionsForEnabledAPIServices: func([]*apiregistrationv1.APIService) (bool, error) {
				return true, fmt.Errorf("dummy error")
			},
			expectedStatus:  operatorv1.ConditionFalse,
			expectedReasons: []string{"ErrorCheckingPrecondition"},
			expectedMessages: []string{
				"dummy error",
			},
		},
		{
			name: "PreconditionsNotReady",
			preconditionsForEnabledAPIServices: func([]*apiregistrationv1.APIService) (bool, error) {
				return false, nil
			},
			expectedStatus:  operatorv1.ConditionFalse,
			expectedReasons: []string{"PreconditionNotReady"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			kubeClient := fake.NewSimpleClientset()
			kubeAggregatorClient := kubeaggregatorfake.NewSimpleClientset(tc.existingAPIServices...)
			if tc.apiServiceReactor != nil {
				kubeAggregatorClient.PrependReactor("*", "apiservices", tc.apiServiceReactor)
			}

			eventRecorder := events.NewInMemoryRecorder("")
			fakeOperatorClient := operatorv1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)
			fakeAuthOperatorIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			{
				authOperator := &operatorv1.Authentication{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec:       operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
					Status:     operatorv1.AuthenticationStatus{OperatorStatus: operatorv1.OperatorStatus{}},
				}

				err := fakeAuthOperatorIndexer.Add(authOperator)
				if err != nil {
					t.Fatal(err)
				}
			}
			operator := &APIServiceController{
				preconditionsForEnabledAPIServices: func([]*apiregistrationv1.APIService) (bool, error) { return true, nil },
				kubeClient:                         kubeClient,
				operatorClient:                     fakeOperatorClient,
				apiregistrationv1Client:            kubeAggregatorClient.ApiregistrationV1(),
				getAPIServicesToManageFn: func() (enabled []*apiregistrationv1.APIService, disabled []*apiregistrationv1.APIService, err error) {
					return []*apiregistrationv1.APIService{
						{
							ObjectMeta: metav1.ObjectMeta{Name: "v1.apps.openshift.io"},
							Spec:       apiregistrationv1.APIServiceSpec{Group: "apps.openshift.io", Version: "v1", Service: &apiregistrationv1.ServiceReference{}},
						},
						{
							ObjectMeta: metav1.ObjectMeta{Name: "v1.build.openshift.io"},
							Spec:       apiregistrationv1.APIServiceSpec{Group: "build.openshift.io", Version: "v1", Service: &apiregistrationv1.ServiceReference{}},
						},
					}, nil, nil
				},
			}
			if tc.preconditionsForEnabledAPIServices != nil {
				operator.preconditionsForEnabledAPIServices = tc.preconditionsForEnabledAPIServices
			}

			_ = operator.sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))

			_, resultStatus, _, err := fakeOperatorClient.GetOperatorState()
			if err != nil {
				t.Fatal(err)
			}
			condition := operatorv1helpers.FindOperatorCondition(resultStatus.Conditions, "APIServicesAvailable")
			if condition == nil {
				t.Fatal("APIServicesAvailable condition not found")
			}
			if condition.Status != tc.expectedStatus {
				t.Error(diff.ObjectGoPrintSideBySide(condition.Status, tc.expectedStatus))
			}
			expectedReasons := strings.Join(tc.expectedReasons, "\n")
			if len(expectedReasons) > 0 && condition.Reason != expectedReasons {
				t.Error(diff.ObjectGoPrintSideBySide(condition.Reason, expectedReasons))
			}
			if len(tc.expectedMessages) > 0 {
				actualMessages := strings.Split(condition.Message, "\n")
				a := make([]string, len(tc.expectedMessages))
				b := make([]string, len(actualMessages))
				copy(a, tc.expectedMessages)
				copy(b, actualMessages)
				sort.Strings(a)
				sort.Strings(b)
				if !equality.Semantic.DeepEqual(a, b) {
					t.Error("\n" + diff.ObjectDiff(a, b))
				}
			}
		})
	}

}

func TestDisabledAPIService(t *testing.T) {
	existingAPIServices := []runtime.Object{
		runtime.Object(newAPIService("build.openshift.io", "v1")),
		runtime.Object(newAPIService("apps.openshift.io", "v1")),
	}
	apiServiceReactorOverride := func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
		return false, nil, nil
	}
	apiServiceReactor := func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
		return apiServiceReactorOverride(action)
	}

	kubeClient := fake.NewSimpleClientset()
	kubeAggregatorClient := kubeaggregatorfake.NewSimpleClientset(existingAPIServices...)
	if apiServiceReactor != nil {
		kubeAggregatorClient.PrependReactor("*", "apiservices", apiServiceReactor)
	}

	eventRecorder := events.NewInMemoryRecorder("")
	fakeOperatorClient := operatorv1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)
	fakeAuthOperatorIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	{
		authOperator := &operatorv1.Authentication{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec:       operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
			Status:     operatorv1.AuthenticationStatus{OperatorStatus: operatorv1.OperatorStatus{}},
		}

		err := fakeAuthOperatorIndexer.Add(authOperator)
		if err != nil {
			t.Fatal(err)
		}
	}

	informerFactory := externalversions.NewSharedInformerFactory(kubeAggregatorClient, 10*time.Minute)

	operator := &APIServiceController{
		preconditionsForEnabledAPIServices: func([]*apiregistrationv1.APIService) (bool, error) { return true, nil },
		kubeClient:                         kubeClient,
		operatorClient:                     fakeOperatorClient,
		apiregistrationv1Client:            kubeAggregatorClient.ApiregistrationV1(),
		apiservicelister:                   informerFactory.Apiregistration().V1().APIServices().Lister(),
	}

	stopCh := make(chan struct{})
	defer close(stopCh)
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	// Both APIs enabled
	operator.getAPIServicesToManageFn = func() (enabled []*apiregistrationv1.APIService, disabled []*apiregistrationv1.APIService, err error) {
		return []*apiregistrationv1.APIService{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "v1.apps.openshift.io"},
				Spec:       apiregistrationv1.APIServiceSpec{Group: "apps.openshift.io", Version: "v1", Service: &apiregistrationv1.ServiceReference{}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "v1.build.openshift.io"},
				Spec:       apiregistrationv1.APIServiceSpec{Group: "build.openshift.io", Version: "v1", Service: &apiregistrationv1.ServiceReference{}},
			},
		}, nil, nil
	}

	_ = operator.sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))

	list, err := kubeAggregatorClient.ApiregistrationV1().APIServices().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	services := sets.New[string]()
	for _, item := range list.Items {
		t.Logf("Found %q APIService", item.Spec.Group)
		services.Insert(item.Spec.Group)
	}

	if !services.Has("apps.openshift.io") || !services.Has("build.openshift.io") {
		t.Fatalf("At least one of ['apps.openshift.io', 'build.openshift.io'] APIServices is missing")
	}

	_, resultStatus, _, err := fakeOperatorClient.GetOperatorState()
	if err != nil {
		t.Fatal(err)
	}
	condition := operatorv1helpers.FindOperatorCondition(resultStatus.Conditions, "APIServicesDegraded")
	if condition == nil {
		t.Fatal("APIServicesDegraded condition not found")
	}
	t.Logf("condition: %v\n", condition)

	if condition.Status != operatorv1.ConditionFalse {
		t.Error(diff.ObjectGoPrintSideBySide(condition.Status, operatorv1.ConditionFalse))
	}

	// build API disabled and deleted
	operator.getAPIServicesToManageFn = func() (enabled []*apiregistrationv1.APIService, disabled []*apiregistrationv1.APIService, err error) {
		return []*apiregistrationv1.APIService{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v1.apps.openshift.io"},
					Spec:       apiregistrationv1.APIServiceSpec{Group: "apps.openshift.io", Version: "v1", Service: &apiregistrationv1.ServiceReference{}},
				},
			}, []*apiregistrationv1.APIService{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v1.build.openshift.io"},
					Spec:       apiregistrationv1.APIServiceSpec{Group: "build.openshift.io", Version: "v1", Service: &apiregistrationv1.ServiceReference{}},
				},
			}, nil
	}

	_ = operator.sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))

	list, err = kubeAggregatorClient.ApiregistrationV1().APIServices().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}

	services = sets.New[string]()
	for _, item := range list.Items {
		t.Logf("Found %q APIService", item.Spec.Group)
		services.Insert(item.Spec.Group)
	}

	if !services.Has("apps.openshift.io") {
		t.Fatalf("Missing 'apps.openshift.io' APIServices")
	}

	if services.Has("build.openshift.io") {
		t.Fatalf("Found unexpected 'build.openshift.io' APIService")
	}

	_, resultStatus, _, err = fakeOperatorClient.GetOperatorState()
	if err != nil {
		t.Fatal(err)
	}
	condition = operatorv1helpers.FindOperatorCondition(resultStatus.Conditions, "APIServicesDegraded")
	if condition == nil {
		t.Fatal("APIServicesDegraded condition not found")
	}
	t.Logf("condition: %v\n", condition)
	if condition.Status != operatorv1.ConditionFalse {
		t.Error(diff.ObjectGoPrintSideBySide(condition.Status, operatorv1.ConditionFalse))
	}

	// build API disabled but not deleted
	_, err = kubeAggregatorClient.ApiregistrationV1().APIServices().Create(context.TODO(), newAPIService("build.openshift.io", "v1"), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Unable to create a build APIService: %v", err)
	}
	apiServiceReactorOverride = func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
		if action.GetVerb() == "delete" && action.(kubetesting.DeleteAction).GetName() == "v1.build.openshift.io" {
			return true, nil, fmt.Errorf("unable to delete v1.build.openshift.io")
		}
		return false, nil, nil
	}

	// creating the api services needs some time to propagate to the informer
	time.Sleep(time.Millisecond)
	_ = operator.sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))

	list, err = kubeAggregatorClient.ApiregistrationV1().APIServices().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}

	services = sets.New[string]()
	for _, item := range list.Items {
		t.Logf("Found %q APIService", item.Spec.Group)
		services.Insert(item.Spec.Group)
	}

	_, resultStatus, _, err = fakeOperatorClient.GetOperatorState()
	if err != nil {
		t.Fatal(err)
	}
	condition = operatorv1helpers.FindOperatorCondition(resultStatus.Conditions, "APIServicesDegraded")
	if condition == nil {
		t.Fatal("APIServicesDegraded condition not found")
	}
	t.Logf("condition: %v\n", condition)
	if condition.Status != operatorv1.ConditionTrue {
		t.Error(diff.ObjectGoPrintSideBySide(condition.Status, operatorv1.ConditionTrue))
	}

}

func TestPreconditionsForEnabledAPIServices(t *testing.T) {
	var (
		bootstrapComplete = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "bootstrap", Namespace: "kube-system"},
			Data:       map[string]string{"status": "complete"},
		}
	)

	scenarios := []struct {
		name                       string
		existingBootstrapConfigMap *corev1.ConfigMap
		existingAPIServices        []*apiregistrationv1.APIService
		existingEndpoints          []*corev1.Endpoints

		expectedStatus bool
	}{
		{
			name: "EmptyAPIServices, NoBootstrapConfigMap",
		},
		{
			name: "EmptyAPIServices, NoStatusInBootstrapConfigMap",
			existingBootstrapConfigMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "bootstrap", Namespace: "kube-system"},
				Data:       map[string]string{"noStatus": "complete"},
			},
		},
		{
			name: "EmptyAPIServices, StatusNotCompleteBootstrapConfigMap",
			existingBootstrapConfigMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "bootstrap", Namespace: "kube-system"},
				Data:       map[string]string{"status": "progressing"},
			},
		},
		{
			name:                       "EmptyAPIServices, CompleteBootstrapConfigMap",
			existingBootstrapConfigMap: bootstrapComplete,
			expectedStatus:             true,
		},
		{
			name:                       "UnreadyAPIServices, CompleteBootstrapConfigMap",
			existingBootstrapConfigMap: bootstrapComplete,
			existingAPIServices: []*apiregistrationv1.APIService{
				newAPIService("build.openshift.io", "v1"),
			},
			existingEndpoints: []*corev1.Endpoints{
				func() *corev1.Endpoints {
					s := newAPIService("build.openshift.io", "v1")
					e := &corev1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      s.Spec.Service.Name,
							Namespace: s.Spec.Service.Namespace,
						},
					}
					return e
				}(),
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			configMapIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			if scenario.existingBootstrapConfigMap != nil {
				if err := configMapIndexer.Add(scenario.existingBootstrapConfigMap); err != nil {
					t.Fatal(err)
				}
			}
			configMapLister := corev1listers.NewConfigMapLister(configMapIndexer)
			endpointIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			for _, endpoint := range scenario.existingEndpoints {
				if err := endpointIndexer.Add(endpoint); err != nil {
					t.Fatal(err)
				}
			}
			endpointLister := corev1listers.NewEndpointsLister(endpointIndexer)

			target := preconditionsForEnabledAPIServices(endpointLister, configMapLister)

			actualStatus, actualError := target(scenario.existingAPIServices)
			if actualStatus != scenario.expectedStatus {
				t.Fatalf("unexpected status = %v, expected = %v", actualStatus, scenario.expectedStatus)
			}
			if actualError != nil {
				t.Fatalf("unexpected err =%v", actualError)
			}
		})
	}
}

func newAPIService(group, version string) *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: version + "." + group, Annotations: map[string]string{"service.alpha.openshift.io/inject-cabundle": "true"}},
		Spec:       apiregistrationv1.APIServiceSpec{Group: group, Version: version, Service: &apiregistrationv1.ServiceReference{Namespace: "target-namespace", Name: "api"}, GroupPriorityMinimum: 9900, VersionPriority: 15},
		Status:     apiregistrationv1.APIServiceStatus{Conditions: []apiregistrationv1.APIServiceCondition{{Type: apiregistrationv1.Available, Status: apiregistrationv1.ConditionTrue}}},
	}
}

package resourcesynccontroller

import (
	"context"
	clocktesting "k8s.io/utils/clock/testing"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	ktesting "k8s.io/client-go/testing"

	"github.com/openshift/library-go/pkg/operator/events/eventstesting"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/events"
)

func TestSyncSecret(t *testing.T) {
	kubeClient := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "config", Name: "foo"},
			Type:       corev1.SecretTypeOpaque,
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "to-remove"},
			Type:       corev1.SecretTypeOpaque,
		},
	)

	destinationSecretCreated := make(chan struct{})
	destinationSecretEmptySourceChecked := false
	destinationSecretEmptySourceCheckedMutex := sync.Mutex{}

	kubeClient.PrependReactor("create", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		actual, isCreate := action.(ktesting.CreateAction)
		if !isCreate {
			return false, nil, nil
		}
		secret, isSecret := actual.GetObject().(*corev1.Secret)
		if !isSecret {
			return false, nil, nil
		}
		if secret.Name == "foo" && secret.Namespace == "operator" {
			close(destinationSecretCreated)
		}
		return false, nil, nil
	})

	deleteSecretCounterMutex := sync.Mutex{}
	deleteSecretCounter := 0

	kubeClient.PrependReactor("delete", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		deleteSecretCounterMutex.Lock()
		defer deleteSecretCounterMutex.Unlock()
		deleteSecretCounter++
		return false, nil, nil
	})

	kubeClient.PrependReactor("get", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		actual, isGet := action.(ktesting.GetAction)
		if !isGet {
			return false, nil, nil
		}
		if actual.GetNamespace() == "operator" {
			switch actual.GetName() {
			case "empty-source":
				destinationSecretEmptySourceCheckedMutex.Lock()
				destinationSecretEmptySourceChecked = true
				destinationSecretEmptySourceCheckedMutex.Unlock()
			}
		}
		return false, nil, nil
	})

	secretInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("config"))
	operatorInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("operator"))
	fakeStaticPodOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{
			ManagementState: operatorv1.Managed,
		},
		&operatorv1.OperatorStatus{},
		nil,
	)
	eventRecorder := eventstesting.NewTestingEventRecorder(t)
	c := NewResourceSyncController(
		"testing-instance",
		fakeStaticPodOperatorClient,
		v1helpers.NewFakeKubeInformersForNamespaces(map[string]informers.SharedInformerFactory{
			"config":   secretInformers,
			"operator": operatorInformers,
		}),
		kubeClient.CoreV1(),
		kubeClient.CoreV1(),
		eventRecorder,
	)

	c.configMapGetter = kubeClient.CoreV1()
	c.secretGetter = kubeClient.CoreV1()

	ctx, ctxCancel := context.WithCancel(context.TODO())
	defer ctxCancel()

	go secretInformers.Start(ctx.Done())
	go operatorInformers.Start(ctx.Done())
	go c.Run(ctx, 1)

	// The source secret was removed (404) but the destination exists. This should increase the "deleteSecretCounter"
	if err := c.SyncSecret(ResourceLocation{Namespace: "operator", Name: "to-remove"}, ResourceLocation{Namespace: "config", Name: "removed"}); err != nil {
		t.Fatal(err)
	}

	// The source secret exists, but the destination does not. This should close the "destinationSecretCreated" channel
	if err := c.SyncSecret(ResourceLocation{Namespace: "operator", Name: "foo"}, ResourceLocation{Namespace: "config", Name: "foo"}); err != nil {
		t.Fatal(err)
	}

	// The source resource location is not set and the destination does not exists. This should close the "destinationSecretEmptySourceChecked" and
	// should not increase the deleteSecretCounter (this is special case in resource sync controller.
	if err := c.SyncSecret(ResourceLocation{Namespace: "operator", Name: "empty-source"}, ResourceLocation{}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-destinationSecretCreated:
	case <-time.After(20 * time.Second):
		t.Fatal("timeout while waiting for destination secret to be created")
	}

	if err := wait.PollImmediate(10*time.Millisecond, 10*time.Second, func() (done bool, err error) {
		destinationSecretEmptySourceCheckedMutex.Lock()
		defer destinationSecretEmptySourceCheckedMutex.Unlock()
		return destinationSecretEmptySourceChecked, nil
	}); err != nil {
		t.Fatal("timeout while waiting for destination secret 'empty-source' to be checked for existence")
	}

	if err := wait.PollImmediate(10*time.Millisecond, 10*time.Second, func() (done bool, err error) {
		deleteSecretCounterMutex.Lock()
		defer deleteSecretCounterMutex.Unlock()
		return deleteSecretCounter > 0, nil
	}); err != nil {
		t.Fatalf("expected a delete calls for this test, got %d", deleteSecretCounter)
	}
}

func TestSyncConfigMap(t *testing.T) {
	kubeClient := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "foo"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "foo"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "config", Name: "bar"},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "config-managed", Name: "pear"},
		},
	)

	configInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("config"))
	configManagedInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("config-managed"))
	operatorInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("operator"))

	fakeStaticPodOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{
			ManagementState: operatorv1.Managed,
		},
		&operatorv1.OperatorStatus{},
		nil,
	)
	eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))

	kubeInformersForNamespaces := v1helpers.NewFakeKubeInformersForNamespaces(map[string]informers.SharedInformerFactory{"other": configInformers})

	c := NewResourceSyncController(
		"testing-instance",
		fakeStaticPodOperatorClient,
		v1helpers.NewFakeKubeInformersForNamespaces(map[string]informers.SharedInformerFactory{
			"config":         configInformers,
			"config-managed": configManagedInformers,
			"operator":       operatorInformers,
		}),
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		eventRecorder,
	)
	c.configMapGetter = kubeClient.CoreV1()
	c.secretGetter = kubeClient.CoreV1()

	// sync ones for namespaces we don't have
	if err := c.SyncSecret(ResourceLocation{Namespace: "other", Name: "foo"}, ResourceLocation{Namespace: "operator", Name: "foo"}); err == nil || err.Error() != `not watching namespace "other"` {
		t.Error(err)
	}
	if err := c.SyncSecret(ResourceLocation{Namespace: "config", Name: "foo"}, ResourceLocation{Namespace: "other", Name: "foo"}); err == nil || err.Error() != `not watching namespace "other"` {
		t.Error(err)
	}
	if err := c.SyncConfigMap(ResourceLocation{Namespace: "other", Name: "foo"}, ResourceLocation{Namespace: "operator", Name: "foo"}); err == nil || err.Error() != `not watching namespace "other"` {
		t.Error(err)
	}
	if err := c.SyncConfigMap(ResourceLocation{Namespace: "config", Name: "foo"}, ResourceLocation{Namespace: "other", Name: "foo"}); err == nil || err.Error() != `not watching namespace "other"` {
		t.Error(err)
	}

	// register
	kubeClient.ClearActions()
	if err := c.SyncSecret(ResourceLocation{Namespace: "operator", Name: "foo"}, ResourceLocation{Namespace: "config", Name: "bar"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SyncConfigMap(ResourceLocation{Namespace: "operator", Name: "apple"}, ResourceLocation{Namespace: "config-managed", Name: "pear"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.TODO(), c.syncCtx); err != nil {
		t.Fatal(err)
	}
	if _, err := kubeClient.CoreV1().Secrets("operator").Get(context.TODO(), "foo", metav1.GetOptions{}); err != nil {
		t.Error(err)
	}
	if _, err := kubeClient.CoreV1().ConfigMaps("operator").Get(context.TODO(), "apple", metav1.GetOptions{}); err != nil {
		t.Error(err)
	}

	// clear
	kubeClient.ClearActions()
	if err := c.SyncSecret(ResourceLocation{Namespace: "operator", Name: "foo"}, ResourceLocation{}); err != nil {
		t.Fatal(err)
	}
	if err := c.SyncConfigMap(ResourceLocation{Namespace: "operator", Name: "apple"}, ResourceLocation{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.TODO(), c.syncCtx); err != nil {
		t.Fatal(err)
	}
	if _, err := kubeClient.CoreV1().Secrets("operator").Get(context.TODO(), "foo", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Error(err)
	}
	if _, err := kubeClient.CoreV1().ConfigMaps("operator").Get(context.TODO(), "apple", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Error(err)
	}
}

func TestSyncConditionally(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fn         preconditionsFulfilled
		expectSync bool
	}{
		{
			name:       "should sync when condition is fulfilled",
			fn:         conditionFulfilled,
			expectSync: true,
		},
		{
			name:       "should not sync when condition is not fulfilled",
			fn:         conditionNotFulfilled,
			expectSync: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset(
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "config", Name: "secret"},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "config", Name: "configmap"},
				},
			)

			configInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("config"))
			operatorInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("operator"))

			fakeStaticPodOperatorClient := v1helpers.NewFakeOperatorClient(
				&operatorv1.OperatorSpec{
					ManagementState: operatorv1.Managed,
				},
				&operatorv1.OperatorStatus{},
				nil,
			)
			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))

			c := NewResourceSyncController(
				"testing-instance",
				fakeStaticPodOperatorClient,
				v1helpers.NewFakeKubeInformersForNamespaces(map[string]informers.SharedInformerFactory{
					"config":   configInformers,
					"operator": operatorInformers,
				}),
				kubeClient.CoreV1(),
				kubeClient.CoreV1(),
				eventRecorder,
			)
			c.configMapGetter = kubeClient.CoreV1()
			c.secretGetter = kubeClient.CoreV1()

			if err := c.SyncSecretConditionally(ResourceLocation{Namespace: "operator", Name: "secret"}, ResourceLocation{Namespace: "config", Name: "secret"}, tc.fn); err != nil {
				t.Fatal(err)
			}
			if err := c.SyncConfigMapConditionally(ResourceLocation{Namespace: "operator", Name: "configmap"}, ResourceLocation{Namespace: "config", Name: "configmap"}, tc.fn); err != nil {
				t.Fatal(err)
			}
			if err := c.Sync(context.TODO(), c.syncCtx); err != nil {
				t.Fatal(err)
			}

			expectedGetErr := func(err error) bool { return err == nil }
			if !tc.expectSync {
				expectedGetErr = func(err error) bool { return apierrors.IsNotFound(err) }
			}
			if _, err := kubeClient.CoreV1().Secrets("operator").Get(context.TODO(), "secret", metav1.GetOptions{}); !expectedGetErr(err) {
				t.Error(err)
			}
			if _, err := kubeClient.CoreV1().ConfigMaps("operator").Get(context.TODO(), "configmap", metav1.GetOptions{}); !expectedGetErr(err) {
				t.Error(err)
			}
		})
	}
}

func conditionFulfilled() (bool, error) { return true, nil }

func conditionNotFulfilled() (bool, error) { return false, nil }

func TestServeHTTP(t *testing.T) {
	c := &ResourceSyncController{
		secretSyncRules: syncRules{
			{Namespace: "foo", Name: "cat"}:  {ResourceLocation: ResourceLocation{Namespace: "bar", Name: "cat"}},
			{Namespace: "test", Name: "dog"}: {ResourceLocation: ResourceLocation{Namespace: "othertest", Name: "dog"}},
			{Namespace: "foo", Name: "dog"}:  {ResourceLocation: ResourceLocation{Namespace: "bar", Name: "dog"}},
		},
		configMapSyncRules: syncRules{
			{Namespace: "a", Name: "b"}:   {ResourceLocation: ResourceLocation{Namespace: "foo", Name: "bar"}},
			{Namespace: "a", Name: "c"}:   {ResourceLocation: ResourceLocation{Namespace: "foo", Name: "barc"}},
			{Namespace: "bar", Name: "b"}: {ResourceLocation: ResourceLocation{Namespace: "foo", Name: "baz"}},
		},
	}

	expected := `{"secrets":[` +
		`{"destination":{"namespace":"foo","name":"cat"},"source":{"namespace":"bar","name":"cat"}},` +
		`{"destination":{"namespace":"foo","name":"dog"},"source":{"namespace":"bar","name":"dog"}},` +
		`{"destination":{"namespace":"test","name":"dog"},"source":{"namespace":"othertest","name":"dog"}}` +
		`],"configs":[` +
		`{"destination":{"namespace":"a","name":"b"},"source":{"namespace":"foo","name":"bar"}},` +
		`{"destination":{"namespace":"a","name":"c"},"source":{"namespace":"foo","name":"barc"}},` +
		`{"destination":{"namespace":"bar","name":"b"},"source":{"namespace":"foo","name":"baz"}}` +
		`]}`

	handler := NewDebugHandler(c)
	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, &http.Request{})
	if writer.Body == nil {
		t.Fatal("expected a body")
	}
	response := writer.Body.String()
	if response != expected {
		t.Errorf("Expected:%+v\n Got: %+v\n", expected, response)
	}
}

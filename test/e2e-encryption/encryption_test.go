package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
	"sigs.k8s.io/yaml"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/operator/encryption"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers/migrators"
	"github.com/openshift/library-go/pkg/operator/encryption/crypto"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/genericoperatorclient"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/test/library"
)

func TestEncryptionIntegration(tt *testing.T) {
	// in terminal print logs immediately
	var t T = tt
	fi, _ := os.Stdin.Stat()
	if (fi.Mode() & os.ModeCharDevice) != 0 {
		t = fmtLogger{tt}
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	ctx := context.Background()

	component := strings.ToLower(library.GenerateNameForTest(tt, ""))

	kubeConfig, err := library.NewClientConfigForTest()
	require.NoError(t, err)

	// kube clients
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)
	kubeInformers := v1helpers.NewKubeInformersForNamespaces(kubeClient, "openshift-config-managed")
	apiextensionsClient, err := v1.NewForConfig(kubeConfig)
	require.NoError(t, err)

	// create ExtensionTest operator CRD
	var operatorCRD apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal([]byte(encryptionTestOperatorCRD), &operatorCRD))
	crd, err := apiextensionsClient.CustomResourceDefinitions().Create(ctx, &operatorCRD, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		t.Logf("CRD %s already existing, ignoring error", operatorCRD.Name)
	} else {
		require.NoError(t, err)
	}
	defer apiextensionsClient.CustomResourceDefinitions().Delete(ctx, crd.Name, metav1.DeleteOptions{})

	t.Logf("Waiting for CRD to be ready")
	err = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
		oCRD, crdErr := apiextensionsClient.CustomResourceDefinitions().Get(ctx, operatorCRD.Name, metav1.GetOptions{})
		if crdErr != nil {
			return false, crdErr
		}

		for _, condition := range oCRD.Status.Conditions {
			if condition.Type == apiextensionsv1.Established {
				operatorCRD = *oCRD
				return condition.Status == apiextensionsv1.ConditionTrue, nil
			}
		}
		return false, nil
	})
	require.NoError(t, err)

	// create operator client and create instance with ManagementState="Managed"
	operatorGVR := schema.GroupVersionResource{Group: operatorCRD.Spec.Group, Version: "v1", Resource: operatorCRD.Spec.Names.Plural}
	operatorGVK := schema.GroupVersionKind{Group: operatorCRD.Spec.Group, Version: "v1", Kind: operatorCRD.Spec.Names.Kind}
	clk := clock.RealClock{}

	// minimal extract functions returning empty configurations
	extractApplySpec := func(obj *unstructured.Unstructured, fieldManager string) (*applyoperatorv1.OperatorSpecApplyConfiguration, error) {
		return applyoperatorv1.OperatorSpec(), nil
	}

	extractApplyStatus := func(obj *unstructured.Unstructured, fieldManager string) (*applyoperatorv1.OperatorStatusApplyConfiguration, error) {
		return applyoperatorv1.OperatorStatus(), nil
	}

	operatorClient, operatorInformer, err := genericoperatorclient.NewClusterScopedOperatorClient(clk, kubeConfig, operatorGVR, operatorGVK, extractApplySpec, extractApplyStatus)
	require.NoError(t, err)
	dynamicClient, err := dynamic.NewForConfig(kubeConfig)
	require.NoError(t, err)
	err = wait.PollUntilContextTimeout(ctx, time.Second, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := dynamicClient.Resource(operatorGVR).Create(ctx, &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "operator.openshift.io/v1",
				"kind":       "EncryptionTest",
				"metadata": map[string]interface{}{
					"name": "cluster",
				},
				"spec": map[string]interface{}{
					"managementState": "Managed",
				},
			},
		}, metav1.CreateOptions{})
		if err != nil && !errors.IsAlreadyExists(err) {
			t.Logf("failed to create APIServer object: %v", err)
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)

	// create APIServer clients
	fakeConfigClient := configv1clientfake.NewClientset(&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})
	fakeConfigInformer := configv1informers.NewSharedInformerFactory(fakeConfigClient, 10*time.Minute)
	fakeApiServerClient := fakeConfigClient.ConfigV1().APIServers()

	// create controllers
	eventRecorder := events.NewLoggingEventRecorder(component, clk)
	deployer := NewInstantDeployer(t, stopCh, kubeClient.CoreV1(), fmt.Sprintf("encryption-config-%s", component))
	migrator := migrators.NewInProcessMigrator(dynamicClient, kubeClient.DiscoveryClient)
	provider := newProvider([]schema.GroupResource{
		// some random low-cardinality GVRs:
		{Group: "operator.openshift.io", Resource: "kubeapiservers"},
		{Group: "operator.openshift.io", Resource: "kubeschedulers"},
	})

	controllers, err := encryption.NewControllers(
		component,
		[]string{},
		provider,
		deployer,
		migrator,
		operatorClient,
		fakeApiServerClient,
		fakeConfigInformer.Config().V1().APIServers(),
		kubeInformers,
		deployer, // secret client wrapping kubeClient with encryption-config revision counting
		eventRecorder,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to initialize controllers: %v", err)
	}

	// launch controllers
	fakeConfigInformer.Start(stopCh)
	kubeInformers.Start(stopCh)
	operatorInformer.Start(stopCh)
	go controllers.Run(ctx, 1)

	t.Logf("Waiting for informers to sync")
	for gvr, synced := range operatorInformer.WaitForCacheSync(stopCh) {
		if !synced {
			t.Fatalf("informer for %v not synced", gvr)
		}
	}
	for gvr, synced := range fakeConfigInformer.WaitForCacheSync(stopCh) {
		if !synced {
			t.Fatalf("informer for %v not synced", gvr)
		}
	}
	for ns, nsSynced := range kubeInformers.WaitForCacheSync(stopCh) {
		for gvr, synced := range nsSynced {
			if !synced {
				t.Fatalf("informer for %v in namespace %v not synced", gvr, ns)
			}
		}
	}
	t.Logf("informers are sync'ed")

	waitForConfigEventuallyCond := func(cond func(s string) bool) {
		t.Helper()
		stopCh := time.After(wait.ForeverTestTimeout)
		for {
			c, err := deployer.WaitUntil(stopCh)
			require.NoError(t, err)
			err = deployer.Deploy()
			require.NoError(t, err)

			got := toString(c)
			t.Logf("Observed %s", got)
			if cond(got) {
				return
			}
		}
	}
	waitForConfigEventually := func(expected string) {
		t.Helper()
		waitForConfigEventuallyCond(func(got string) bool {
			return expected == got
		})
	}
	waitForConfigs := func(ss ...string) {
		t.Helper()
		for _, expected := range ss {
			c, err := deployer.Wait()
			require.NoError(t, err)
			got := toString(c)
			t.Logf("Observed %s", got)
			if expected != "*" && got != expected {
				t.Fatalf("wrong EncryptionConfig:\n  expected: %s\n  got:      %s", expected, got)
			}

			err = deployer.Deploy()
			require.NoError(t, err)
		}
	}
	conditionStatus := func(condType string) operatorv1.ConditionStatus {
		_, status, _, err := operatorClient.GetOperatorState()
		require.NoError(t, err)

		for _, c := range status.Conditions {
			if c.Type != condType {
				continue
			}
			return c.Status
		}
		return operatorv1.ConditionUnknown
	}
	waitForConditionStatus := func(condType string, expected operatorv1.ConditionStatus) {
		t.Helper()
		err := wait.PollUntilContextTimeout(ctx, time.Millisecond*100, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
			return conditionStatus(condType) == expected, nil
		})
		require.NoError(t, err)
	}
	waitForMigration := func(key string) {
		t.Helper()
		err := wait.PollUntilContextTimeout(ctx, time.Millisecond*100, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
			s, err := kubeClient.CoreV1().Secrets("openshift-config-managed").Get(ctx, fmt.Sprintf("encryption-key-%s-%s", component, key), metav1.GetOptions{})
			require.NoError(t, err)

			ks, err := secrets.ToKeyState(s)
			require.NoError(t, err)
			return len(ks.Migrated.Resources) == 2, nil
		})
		require.NoError(t, err)
	}

	t.Logf("Wait for initial Encrypted condition")
	waitForConditionStatus("Encrypted", operatorv1.ConditionFalse)

	t.Logf("Enable encryption, mode aescbc")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":"aescbc"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)

	t.Logf("Waiting for key to show up")
	keySecretsLabel := fmt.Sprintf("%s=%s", secrets.EncryptionKeySecretsLabel, component)
	waitForKeys := func(n int) {
		t.Helper()
		err := wait.PollUntilContextTimeout(ctx, time.Second, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
			l, err := kubeClient.CoreV1().Secrets("openshift-config-managed").List(ctx, metav1.ListOptions{LabelSelector: keySecretsLabel})
			if err != nil {
				return false, err
			}
			if len(l.Items) == n {
				return true, nil
			}
			t.Logf("Seeing %d secrets, waiting for %d", len(l.Items), n)
			return false, nil
		})
		require.NoError(t, err)
	}
	waitForKeys(1)
	waitForConfigs(
		"kubeapiservers.operator.openshift.io=identity,aescbc:1;kubeschedulers.operator.openshift.io=identity,aescbc:1",
		"kubeapiservers.operator.openshift.io=aescbc:1,identity;kubeschedulers.operator.openshift.io=aescbc:1,identity",
	)
	waitForMigration("1")
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Switch to identity")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":"identity"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	waitForKeys(2)
	waitForConfigs(
		"kubeapiservers.operator.openshift.io=aescbc:1,identity,aesgcm:2;kubeschedulers.operator.openshift.io=aescbc:1,identity,aesgcm:2",
		"kubeapiservers.operator.openshift.io=identity,aescbc:1,aesgcm:2;kubeschedulers.operator.openshift.io=identity,aescbc:1,aesgcm:2",
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionFalse)

	t.Logf("Switch to empty mode")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":""}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	time.Sleep(5 * time.Second) // give controller time to create keys (it shouldn't)
	waitForKeys(2)
	waitForConditionStatus("Encrypted", operatorv1.ConditionFalse)

	t.Logf("Switch to aescbc again")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":"aescbc"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	waitForKeys(3)
	waitForConfigs(
		"kubeapiservers.operator.openshift.io=identity,aescbc:3,aescbc:1,aesgcm:2;kubeschedulers.operator.openshift.io=identity,aescbc:3,aescbc:1,aesgcm:2",
		"kubeapiservers.operator.openshift.io=aescbc:3,aescbc:1,identity,aesgcm:2;kubeschedulers.operator.openshift.io=aescbc:3,aescbc:1,identity,aesgcm:2",
		"kubeapiservers.operator.openshift.io=aescbc:3,identity,aesgcm:2;kubeschedulers.operator.openshift.io=aescbc:3,identity,aesgcm:2",
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Setting external reason")
	setExternalReason := func(reason string) {
		t.Helper()
		applyConfig := applyoperatorv1.OperatorSpec().
			WithUnsupportedConfigOverrides(runtime.RawExtension{
				Raw: []byte(fmt.Sprintf(`{"encryption":{"reason":%q}}`, reason)),
			})
		err = operatorClient.ApplyOperatorSpec(ctx, "encryption-test", applyConfig)
		require.NoError(t, err)
	}
	setExternalReason("a")
	waitForKeys(4)
	waitForConfigs(
		"kubeapiservers.operator.openshift.io=aescbc:3,aescbc:4,identity,aesgcm:2;kubeschedulers.operator.openshift.io=aescbc:3,aescbc:4,identity,aesgcm:2",
		"kubeapiservers.operator.openshift.io=aescbc:4,aescbc:3,identity,aesgcm:2;kubeschedulers.operator.openshift.io=aescbc:4,aescbc:3,identity,aesgcm:2",
		"kubeapiservers.operator.openshift.io=aescbc:4,aescbc:3,identity;kubeschedulers.operator.openshift.io=aescbc:4,aescbc:3,identity",
	)

	t.Logf("Setting another external reason")
	setExternalReason("b")
	waitForKeys(5)
	waitForConfigs(
		"kubeapiservers.operator.openshift.io=aescbc:4,aescbc:5,aescbc:3,identity;kubeschedulers.operator.openshift.io=aescbc:4,aescbc:5,aescbc:3,identity",
		"kubeapiservers.operator.openshift.io=aescbc:5,aescbc:4,aescbc:3,identity;kubeschedulers.operator.openshift.io=aescbc:5,aescbc:4,aescbc:3,identity",
		"kubeapiservers.operator.openshift.io=aescbc:5,aescbc:4,identity;kubeschedulers.operator.openshift.io=aescbc:5,aescbc:4,identity",
	)

	t.Logf("Expire the last key")
	_, err = kubeClient.CoreV1().Secrets("openshift-config-managed").Patch(ctx, fmt.Sprintf("encryption-key-%s-5", component), types.MergePatchType, []byte(`{"metadata":{"annotations":{"encryption.apiserver.operator.openshift.io/migrated-timestamp":"2010-10-17T14:14:52+02:00"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	waitForKeys(6)
	waitForConfigs(
		"kubeapiservers.operator.openshift.io=aescbc:5,aescbc:6,aescbc:4,identity;kubeschedulers.operator.openshift.io=aescbc:5,aescbc:6,aescbc:4,identity",
		"kubeapiservers.operator.openshift.io=aescbc:6,aescbc:5,aescbc:4,identity;kubeschedulers.operator.openshift.io=aescbc:6,aescbc:5,aescbc:4,identity",
		"kubeapiservers.operator.openshift.io=aescbc:6,aescbc:5,identity;kubeschedulers.operator.openshift.io=aescbc:6,aescbc:5,identity",
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Delete the last key")
	_, err = kubeClient.CoreV1().Secrets("openshift-config-managed").Patch(ctx, fmt.Sprintf("encryption-key-%s-6", component), types.JSONPatchType, []byte(`[{"op":"remove","path":"/metadata/finalizers"}]`), metav1.PatchOptions{})
	require.NoError(t, err)
	err = kubeClient.CoreV1().Secrets("openshift-config-managed").Delete(ctx, fmt.Sprintf("encryption-key-%s-6", component), metav1.DeleteOptions{})
	require.NoError(t, err)
	err = wait.PollUntilContextTimeout(ctx, time.Second, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := kubeClient.CoreV1().Secrets("openshift-config-managed").Get(ctx, fmt.Sprintf("encryption-key-%s-7", component), metav1.GetOptions{})
		if errors.IsNotFound(err) {
			return false, nil
		}
		return err == nil, nil
	})
	require.NoError(t, err)
	// here we see potentially also the following if the key controller is slower than the state controller:
	//   kubeapiservers.operator.openshift.io=aescbc:6,aescbc:5,identity;kubeschedulers.operator.openshift.io=aescbc:6,aescbc:5,identity
	// but eventually we get the following:
	waitForConfigEventually(
		// 6 as preserved, unbacked config key, 7 as newly created key, and 5 as fully migrated key
		"kubeapiservers.operator.openshift.io=aescbc:6,aescbc:7,aescbc:5,aescbc:4,identity;kubeschedulers.operator.openshift.io=aescbc:6,aescbc:7,aescbc:5,aescbc:4,identity",
	)
	waitForConfigs(
		// 7 is promoted
		"kubeapiservers.operator.openshift.io=aescbc:7,aescbc:6,aescbc:5,aescbc:4,identity;kubeschedulers.operator.openshift.io=aescbc:7,aescbc:6,aescbc:5,aescbc:4,identity",
		// 7 is migrated, plus one more backed key, which is 5 (6 is deleted)
		"kubeapiservers.operator.openshift.io=aescbc:7,aescbc:6,aescbc:5,identity;kubeschedulers.operator.openshift.io=aescbc:7,aescbc:6,aescbc:5,identity",
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Delete the openshift-config-managed config")
	_, err = kubeClient.CoreV1().Secrets("openshift-config-managed").Patch(ctx, fmt.Sprintf("encryption-config-%s", component), types.JSONPatchType, []byte(`[{"op":"remove","path":"/metadata/finalizers"}]`), metav1.PatchOptions{})
	require.NoError(t, err)
	err = kubeClient.CoreV1().Secrets("openshift-config-managed").Delete(ctx, fmt.Sprintf("encryption-config-%s", component), metav1.DeleteOptions{})
	require.NoError(t, err)
	waitForConfigs(
		// one migrated read-key (7) and one more backed key (5), and everything in between (6)
		"kubeapiservers.operator.openshift.io=aescbc:7,aescbc:6,aescbc:5,identity;kubeschedulers.operator.openshift.io=aescbc:7,aescbc:6,aescbc:5,identity",
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Delete the openshift-config-managed config")
	deployer.DeleteOperandConfig()
	waitForConfigs(
		// 7 is migrated, backed key (5) is immediately included when rotating through identity. 6 is deleted, not preserved (would be if operand config was not deleted)
		"kubeapiservers.operator.openshift.io=identity,aescbc:7,aescbc:5;kubeschedulers.operator.openshift.io=identity,aescbc:7,aescbc:5",
		// promote aescbc:7 back to write position
		"kubeapiservers.operator.openshift.io=aescbc:7,aescbc:5,identity;kubeschedulers.operator.openshift.io=aescbc:7,aescbc:5,identity",
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Switch to KMS")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":"KMS"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	waitForKeys(7)
	kms8 := kmsProviderName("kubeapiservers", "8")
	kms8Sched := kmsProviderName("kubeschedulers", "8")
	waitForConfigs(
		fmt.Sprintf("kubeapiservers.operator.openshift.io=aescbc:7,kms:%s,aescbc:5,identity;kubeschedulers.operator.openshift.io=aescbc:7,kms:%s,aescbc:5,identity", kms8, kms8Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:7,aescbc:5,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:7,aescbc:5,identity", kms8, kms8Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:7,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:7,identity", kms8, kms8Sched),
	)
	waitForMigration("8")
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Switch back to aescbc from KMS")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":"aescbc"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	waitForKeys(8)
	waitForConfigs(
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:9,aescbc:7,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:9,aescbc:7,identity", kms8, kms8Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=aescbc:9,kms:%s,aescbc:7,identity;kubeschedulers.operator.openshift.io=aescbc:9,kms:%s,aescbc:7,identity", kms8, kms8Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=aescbc:9,kms:%s,identity;kubeschedulers.operator.openshift.io=aescbc:9,kms:%s,identity", kms8, kms8Sched),
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Switch back to KMS")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":"KMS"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	waitForKeys(9)
	kms10 := kmsProviderName("kubeapiservers", "10")
	kms10Sched := kmsProviderName("kubeschedulers", "10")
	waitForConfigs(
		fmt.Sprintf("kubeapiservers.operator.openshift.io=aescbc:9,kms:%s,kms:%s,identity;kubeschedulers.operator.openshift.io=aescbc:9,kms:%s,kms:%s,identity", kms10, kms8, kms10Sched, kms8Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:9,kms:%s,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:9,kms:%s,identity", kms10, kms8, kms10Sched, kms8Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:9,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:9,identity", kms10, kms10Sched),
	)
	waitForMigration("10")
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Rotate KMS key via aescbc (KMS->AESCBC->KMS)")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":"aescbc"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	waitForKeys(10)
	waitForConfigs(
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:11,aescbc:9,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:11,aescbc:9,identity", kms10, kms10Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=aescbc:11,kms:%s,aescbc:9,identity;kubeschedulers.operator.openshift.io=aescbc:11,kms:%s,aescbc:9,identity", kms10, kms10Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=aescbc:11,kms:%s,identity;kubeschedulers.operator.openshift.io=aescbc:11,kms:%s,identity", kms10, kms10Sched),
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Switch back to KMS after rotation")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":"KMS"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	waitForKeys(11)
	kms12 := kmsProviderName("kubeapiservers", "12")
	kms12Sched := kmsProviderName("kubeschedulers", "12")
	waitForConfigs(
		fmt.Sprintf("kubeapiservers.operator.openshift.io=aescbc:11,kms:%s,kms:%s,identity;kubeschedulers.operator.openshift.io=aescbc:11,kms:%s,kms:%s,identity", kms12, kms10, kms12Sched, kms10Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:11,kms:%s,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:11,kms:%s,identity", kms12, kms10, kms12Sched, kms10Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:11,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:11,identity", kms12, kms12Sched),
	)
	waitForMigration("12")
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Delete the encryption-config while in KMS mode")
	_, err = kubeClient.CoreV1().Secrets("openshift-config-managed").Patch(ctx, fmt.Sprintf("encryption-config-%s", component), types.JSONPatchType, []byte(`[{"op":"remove","path":"/metadata/finalizers"}]`), metav1.PatchOptions{})
	require.NoError(t, err)
	err = kubeClient.CoreV1().Secrets("openshift-config-managed").Delete(ctx, fmt.Sprintf("encryption-config-%s", component), metav1.DeleteOptions{})
	require.NoError(t, err)
	waitForConfigs(
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:11,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:11,identity", kms12, kms12Sched),
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Delete the operand config while in KMS mode")
	deployer.DeleteOperandConfig()
	waitForConfigs(
		// kms12 is migrated and hence only one needed, but we rotate through identity
		fmt.Sprintf("kubeapiservers.operator.openshift.io=identity,kms:%s,aescbc:11;kubeschedulers.operator.openshift.io=identity,kms:%s,aescbc:11", kms12, kms12Sched),
		// kms12 is migrated, plus one backed key (11)
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:11,identity;kubeschedulers.operator.openshift.io=kms:%s,aescbc:11,identity", kms12, kms12Sched),
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionTrue)

	t.Logf("Switch to identity from KMS")
	_, err = fakeApiServerClient.Patch(ctx, "cluster", types.MergePatchType, []byte(`{"spec":{"encryption":{"type":"identity"}}}`), metav1.PatchOptions{})
	require.NoError(t, err)
	waitForKeys(12)
	waitForConfigs(
		fmt.Sprintf("kubeapiservers.operator.openshift.io=kms:%s,aescbc:11,identity,aesgcm:13;kubeschedulers.operator.openshift.io=kms:%s,aescbc:11,identity,aesgcm:13", kms12, kms12Sched),
		fmt.Sprintf("kubeapiservers.operator.openshift.io=identity,kms:%s,aescbc:11,aesgcm:13;kubeschedulers.operator.openshift.io=identity,kms:%s,aescbc:11,aesgcm:13", kms12, kms12Sched),
	)
	waitForConditionStatus("Encrypted", operatorv1.ConditionFalse)
}

const encryptionTestOperatorCRD = `
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: encryptiontests.operator.openshift.io
spec:
  group: operator.openshift.io
  names:
    kind: EncryptionTest
    listKind: EncryptionTestList
    plural: encryptiontests
    singular: encryptiontest
  scope: Cluster
  versions:
  - name: v1
    served: true
    storage: true
    subresources:
      status: {}
    schema:
      openAPIV3Schema:
        type: object
        required:
        - spec
        properties:
          spec:
            type: object
            required:
            - managementState
            properties:
              managementState:
                type: string
                enum:
                - Managed
                - Unmanaged
                - Removed
              observedConfig:
                type: object
                nullable: true
                x-kubernetes-preserve-unknown-fields: true
              unsupportedConfigOverrides:
                type: object
                nullable: true
                x-kubernetes-preserve-unknown-fields: true
          status:
            type: object
            properties:
              conditions:
                type: array
                items:
                  type: object
                  required:
                  - type
                  - status
                  properties:
                    type:
                      type: string
                    status:
                      type: string
                    lastTransitionTime:
                      type: string
                      format: date-time
                    reason:
                      type: string
                    message:
                      type: string
              observedGeneration:
                type: integer
                format: int64
`

func toString(c *apiserverv1.EncryptionConfiguration) string {
	rs := make([]string, 0, len(c.Resources))
	for _, r := range c.Resources {
		ps := make([]string, 0, len(r.Providers))
		for _, p := range r.Providers {
			var s string
			switch {
			case p.AESCBC != nil:
				s = "aescbc:" + p.AESCBC.Keys[0].Name
			case p.AESGCM != nil:
				s = "aesgcm:" + p.AESGCM.Keys[0].Name
			case p.KMS != nil:
				s = "kms:" + p.KMS.Name
			case p.Identity != nil:
				s = "identity"
			}
			ps = append(ps, s)
		}
		rs = append(rs, fmt.Sprintf("%s=%s", strings.Join(r.Resources, ","), strings.Join(ps, ",")))
	}
	return strings.Join(rs, ";")
}

func NewInstantDeployer(t T, stopCh <-chan struct{}, secretsClient corev1client.SecretsGetter, secretName string) *lockStepDeployer {
	return &lockStepDeployer{
		secretsClient: secretsClient,
		stopCh:        stopCh,
		configManagedSecretsClient: secretInterceptor{
			t:               t,
			output:          make(chan *corev1.Secret),
			SecretInterface: secretsClient.Secrets("openshift-config-managed"),
			secretName:      secretName,
		},
	}
}

// lockStepDeployer mirrors the encryption-config each time Deploy() is called.
// After Deploy() a call to Wait() is necessary.
type lockStepDeployer struct {
	stopCh <-chan struct{}

	secretsClient              corev1client.SecretsGetter
	configManagedSecretsClient secretInterceptor

	lock     sync.Mutex
	next     *corev1.Secret
	current  *corev1.Secret
	handlers []cache.ResourceEventHandler
}

func (d *lockStepDeployer) Wait() (*apiserverv1.EncryptionConfiguration, error) {
	return d.WaitUntil(nil)
}

func (d *lockStepDeployer) WaitUntil(stopCh <-chan time.Time) (*apiserverv1.EncryptionConfiguration, error) {
	d.lock.Lock()
	if d.next != nil {
		d.lock.Unlock()
		return nil, fmt.Errorf("next secret already set. Forgotten Deploy call?")
	}
	d.lock.Unlock()

	select {
	case s := <-d.configManagedSecretsClient.output:
		var c apiserverv1.EncryptionConfiguration
		if err := json.Unmarshal(s.Data["encryption-config"], &c); err != nil {
			return nil, fmt.Errorf("failed to unmarshal encryption secret: %v", err)
		}

		d.lock.Lock()
		defer d.lock.Unlock()
		d.next = s

		return &c, nil
	case <-stopCh:
		return nil, fmt.Errorf("timeout")
	case <-d.stopCh:
		return nil, fmt.Errorf("terminating")
	}
}

func (d *lockStepDeployer) Deploy() error {
	d.lock.Lock()

	if d.next == nil {
		d.lock.Unlock()
		return fmt.Errorf("no next secret available")
	}

	old := d.current
	d.current = d.next
	d.next = nil

	handlers := make([]cache.ResourceEventHandler, len(d.handlers))
	copy(handlers, d.handlers)

	d.lock.Unlock()

	for _, h := range handlers {
		if old == nil {
			h.OnAdd(d.current, false /* isInInitialList */)
		} else {
			h.OnUpdate(old, d.current)
		}
	}

	return nil
}

func (d *lockStepDeployer) Secrets(namespace string) corev1client.SecretInterface {
	if namespace == "openshift-config-managed" {
		return &d.configManagedSecretsClient
	}
	return d.secretsClient.Secrets(namespace)
}

type secretInterceptor struct {
	corev1client.SecretInterface

	t          T
	output     chan *corev1.Secret
	secretName string
}

func (c *secretInterceptor) Create(ctx context.Context, s *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error) {
	s, err := c.SecretInterface.Create(ctx, s, opts)
	if err != nil {
		return s, err
	}

	c.t.Logf("Create %s", s.Name)
	if s.Name == c.secretName {
		c.output <- s
	}

	return s, nil
}

func (c *secretInterceptor) Update(ctx context.Context, s *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error) {
	s, err := c.SecretInterface.Update(ctx, s, opts)
	if err != nil {
		return s, err
	}

	c.t.Logf("Update %s", s.Name)
	if s.Name == c.secretName {
		c.output <- s
	}

	return s, nil
}

func (c *secretInterceptor) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *corev1.Secret, err error) {
	s, err := c.SecretInterface.Patch(ctx, name, pt, data, opts, subresources...)
	if err != nil {
		return s, err
	}

	c.t.Logf("Patch %s", s.Name)
	if s.Name == c.secretName {
		c.output <- s
	}

	return s, nil
}

func (d *lockStepDeployer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.handlers = append(d.handlers, handler)
	return d, nil
}

func (d *lockStepDeployer) HasSynced() bool {
	return true
}

func (d *lockStepDeployer) DeployedEncryptionConfigSecret(ctx context.Context) (secret *corev1.Secret, converged bool, err error) {
	d.lock.Lock()
	defer d.lock.Unlock()

	return d.current, true, nil
}

func (d *lockStepDeployer) DeleteOperandConfig() {
	d.lock.Lock()
	old := d.current
	d.current = nil
	d.next = nil
	handlers := make([]cache.ResourceEventHandler, len(d.handlers))
	copy(handlers, d.handlers)
	d.lock.Unlock()

	for _, h := range handlers {
		h.OnDelete(old)
	}
}

type T interface {
	require.TestingT
	Logf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Helper()
}

type fmtLogger struct {
	*testing.T
}

func (l fmtLogger) Errorf(format string, args ...interface{}) {
	l.T.Helper()
	fmt.Printf(format+"\n", args...)
	l.T.Errorf(format, args...)
}

func (l fmtLogger) Logf(format string, args ...interface{}) {
	l.T.Helper()
	fmt.Printf("STEP: "+format+"\n", args...)
	l.T.Logf(format, args...)
}

type provider struct {
	encryptedGRs []schema.GroupResource
}

func newProvider(encryptedGRs []schema.GroupResource) controllers.Provider {
	return &provider{encryptedGRs: encryptedGRs}
}

func (p *provider) EncryptedGRs() []schema.GroupResource {
	return p.encryptedGRs
}

func (p *provider) ShouldRunEncryptionControllers() (bool, error) {
	return true, nil
}

// kmsProviderName computes the KMS provider name with checksum for a given resource and key ID.
// Format: kms-{resource}-{keyID}-{checksumBase64}
func kmsProviderName(resource, keyID string) string {
	kmsConfig := kms.NewKMS(kms.DefaultEndpoint)
	kmsJSON, _ := kmsConfig.ToBytes()
	checksum := crypto.NewKMSKey(kmsJSON)
	checksumBase64 := base64.StdEncoding.EncodeToString(checksum)
	return fmt.Sprintf("kms-%s-%s-%s", resource, keyID, checksumBase64)
}

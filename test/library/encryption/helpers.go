package encryption

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"

	"github.com/openshift/library-go/test/library"
)

var (
	waitPollInterval = 15 * time.Second
	// rolling out a single instance on AWS: 3m 30s (max delay aws) + 60s (in-flight req) + 3m 10s (starting new instance - observation) = 7m 40s
	// rolling out all instances: 7m 40s * 3 = 23m
	// a happy path scenario needs to roll out 3 revisions each taking 23m
	// plus 10 additional minutes for actual migration
	waitPollTimeout       = 69*time.Minute + 10*time.Minute
	defaultEncryptionMode = string(configv1.EncryptionTypeIdentity)

	SupportedStaticEncryptionProviders = []EncryptionProvider{
		{APIServerEncryption: configv1.APIServerEncryption{Type: configv1.EncryptionTypeAESGCM}},
		{APIServerEncryption: configv1.APIServerEncryption{Type: configv1.EncryptionTypeAESCBC}},
	}
)

type ClientSet struct {
	Etcd            EtcdClient
	ApiServerConfig configv1client.APIServerInterface
	Kube            kubernetes.Interface
	DynamicClient   dynamic.Interface
}

type EncryptionKeyMeta struct {
	Name     string
	Migrated []schema.GroupResource
	Mode     string
}

type UpdateUnsupportedConfigFunc func(raw []byte) error

// ForceRotationFunc triggers a key rotation in a provider-specific way.
// Static encryption (AES-CBC/AES-GCM) sets encryption.reason in unsupported config;
// KMS rotates the external KMS key (for example Vault transit).
type ForceRotationFunc func(t testing.TB, ctx context.Context)

// WaitForRotationCompleteFunc waits until re-migration after rotation has finished.
// Static encryption waits for the next encryption key secret to be migrated;
// KMS waits for a new finished entry in KeyRotationStatus, created by the rotation controller.
type WaitForRotationCompleteFunc func(t testing.TB, clientSet ClientSet, prevKeyMeta EncryptionKeyMeta, scenario BasicScenario)

// StaticEncryptionForceRotation returns a ForceRotationFunc that mints a new key via encryption.reason.
func StaticEncryptionForceRotation(updateUnsupportedConfig UpdateUnsupportedConfigFunc) ForceRotationFunc {
	return func(t testing.TB, _ context.Context) {
		t.Helper()
		require.NoError(t, ForceKeyRotation(t, updateUnsupportedConfig, fmt.Sprintf("test-key-rotation-%s", rand.String(4))))
	}
}

// WaitForNextEncryptionKeyRotation waits until a new encryption key secret is fully migrated.
func WaitForNextEncryptionKeyRotation() WaitForRotationCompleteFunc {
	return func(t testing.TB, clientSet ClientSet, prevKeyMeta EncryptionKeyMeta, scenario BasicScenario) {
		t.Helper()
		WaitForNextMigratedKey(t, clientSet.Kube, prevKeyMeta, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	}
}

func SetAndWaitForEncryptionType(ctx context.Context, t testing.TB, provider EncryptionProvider, defaultTargetGRs []schema.GroupResource, namespace, labelSelector string) ClientSet {
	t.Helper()

	t.Logf("Starting encryption e2e test for %q mode", provider.Type)

	clientSet := GetClients(t)
	lastMigratedKeyMeta, err := GetLastKeyMeta(t, clientSet.Kube, namespace, labelSelector)
	require.NoError(t, err)

	apiServer, err := clientSet.ApiServerConfig.Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)
	previousEncryption := apiServer.Spec.Encryption
	needsUpdate := !equality.Semantic.DeepEqual(previousEncryption, provider.APIServerEncryption)
	if needsUpdate {
		if provider.Setup != nil {
			provider.Setup(ctx, t)
		}
		t.Logf("Updating encryption configuration for APIServer from %#v to %#v", previousEncryption, provider.APIServerEncryption)
		apiServer.Spec.Encryption = provider.APIServerEncryption
		_, err = clientSet.ApiServerConfig.Update(ctx, apiServer, metav1.UpdateOptions{})
		require.NoError(t, err)
	} else {
		t.Logf("APIServer is already configured to use %q mode", provider.Type)
	}

	// KMS-to-KMS migration: when both old and new are KMS but the config differs,
	// the key controller creates a new key. We must wait for the next migrated key
	// rather than asserting no new key is created.
	if needsUpdate && provider.Type == configv1.EncryptionTypeKMS && previousEncryption.Type == configv1.EncryptionTypeKMS {
		WaitForNextMigratedKey(t, clientSet.Kube, lastMigratedKeyMeta, defaultTargetGRs, namespace, labelSelector)
		return clientSet
	}

	WaitForEncryptionKeyBasedOn(t, clientSet.Kube, lastMigratedKeyMeta, provider.Type, defaultTargetGRs, namespace, labelSelector)
	return clientSet
}

func GetClients(t testing.TB) ClientSet {
	t.Helper()

	kubeConfig, err := library.NewClientConfigForTest()
	require.NoError(t, err)

	configClient := configv1client.NewForConfigOrDie(kubeConfig)
	apiServerConfigClient := configClient.APIServers()

	kubeClient := kubernetes.NewForConfigOrDie(kubeConfig)
	etcdClient := NewEtcdClient(kubeClient)

	dynamicClient, err := dynamic.NewForConfig(kubeConfig)
	require.NoError(t, err)

	return ClientSet{Etcd: etcdClient, ApiServerConfig: apiServerConfigClient, Kube: kubeClient, DynamicClient: dynamicClient}
}

func WaitForEncryptionKeyBasedOn(t testing.TB, kubeClient kubernetes.Interface, prevKeyMeta EncryptionKeyMeta, encryptionType configv1.EncryptionType, defaultTargetGRs []schema.GroupResource, namespace, labelSelector string) {
	encryptionMode := string(encryptionType)
	if encryptionMode == "" {
		encryptionMode = defaultEncryptionMode
	}
	if len(prevKeyMeta.Name) == 0 {
		prevKeyMeta.Mode = defaultEncryptionMode
	}

	if prevKeyMeta.Mode == encryptionMode {
		WaitForNoNewEncryptionKey(t, kubeClient, prevKeyMeta, namespace, labelSelector)
		return
	}
	WaitForNextMigratedKey(t, kubeClient, prevKeyMeta, defaultTargetGRs, namespace, labelSelector)
}

func WaitForNoNewEncryptionKey(t testing.TB, kubeClient kubernetes.Interface, prevKeyMeta EncryptionKeyMeta, namespace, labelSelector string) {
	t.Helper()
	// given that the happy path scenario needs ~30 min
	// waiting 5 min to see if a new key hasn't been created seems to be enough.
	waitNoKeyPollInterval := 15 * time.Second
	waitNoKeyPollTimeout := 6 * time.Minute
	waitDuration := 5 * time.Minute

	nextKeyName, err := determineNextEncryptionKeyName(prevKeyMeta.Name, labelSelector)
	require.NoError(t, err)
	t.Logf("Waiting up to %s to check if no new key %q will be crated, as the previous (%q) key's encryption mode (%q) is the same as the current/desired one", waitDuration.String(), nextKeyName, prevKeyMeta.Name, prevKeyMeta.Mode)

	observedTimestamp := time.Now()
	if err := wait.Poll(waitNoKeyPollInterval, waitNoKeyPollTimeout, func() (bool, error) {
		currentKeyMeta, err := GetLastKeyMeta(t, kubeClient, namespace, labelSelector)
		if err != nil {
			return false, err
		}

		if currentKeyMeta.Name != prevKeyMeta.Name {
			return false, fmt.Errorf("unexpected key observed %q, expected no new key", currentKeyMeta.Name)
		}

		if time.Since(observedTimestamp) > waitDuration {
			t.Logf("Haven't seen a new key for %s", waitDuration.String())
			return true, nil
		}

		return false, nil
	}); err != nil {
		newErr := fmt.Errorf("failed to check if no new key will be created, err %v", err)
		require.NoError(t, newErr)
	}
}

func WaitForNextMigratedKey(t testing.TB, kubeClient kubernetes.Interface, prevKeyMeta EncryptionKeyMeta, defaultTargetGRs []schema.GroupResource, namespace, labelSelector string) {
	t.Helper()

	var err error
	nextKeyName := ""
	nextKeyName, err = determineNextEncryptionKeyName(prevKeyMeta.Name, labelSelector)
	require.NoError(t, err)
	if len(prevKeyMeta.Name) == 0 {
		prevKeyMeta.Name = ""
		prevKeyMeta.Migrated = defaultTargetGRs
	}

	t.Logf("Waiting up to %s for the next key %q, previous key was %q", waitPollTimeout.String(), nextKeyName, func(prevKeyName string) string {
		if len(prevKeyName) == 0 {
			return "no previous key"
		}
		return prevKeyName
	}(prevKeyMeta.Name))
	observedKeyName := prevKeyMeta.Name
	if err := wait.Poll(waitPollInterval, waitPollTimeout, func() (bool, error) {
		currentKeyMeta, err := GetLastKeyMeta(t, kubeClient, namespace, labelSelector)
		if err != nil {
			return false, err
		}

		if currentKeyMeta.Name != observedKeyName {
			if currentKeyMeta.Name != nextKeyName {
				return false, fmt.Errorf("unexpected key observed %q, expected %q", currentKeyMeta.Name, nextKeyName)
			}
			t.Logf("Observed key %q, waiting up to %s until it will be used to migrate %v", currentKeyMeta.Name, waitPollTimeout.String(), prevKeyMeta.Migrated)
			observedKeyName = currentKeyMeta.Name
		}

		if currentKeyMeta.Name == nextKeyName {
			if len(prevKeyMeta.Migrated) == len(currentKeyMeta.Migrated) {
				for _, expectedGR := range prevKeyMeta.Migrated {
					if !hasResource(expectedGR, prevKeyMeta.Migrated) {
						return false, nil
					}
				}
				t.Logf("Key %q was used to migrate %v", currentKeyMeta.Name, currentKeyMeta.Migrated)
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		newErr := fmt.Errorf("failed waiting for key %s to be used to migrate %v, due to %v", nextKeyName, prevKeyMeta.Migrated, err)
		require.NoError(t, newErr)
	}
}

func GetLastKeyMeta(t testing.TB, kubeClient kubernetes.Interface, namespace, labelSelector string) (EncryptionKeyMeta, error) {
	secretsClient := kubeClient.CoreV1().Secrets(namespace)
	var selectedSecrets *corev1.SecretList

	// in theory the max time we tolerate disruption on an SNO cluster is 60 seconds
	// so we set the timeout to 5 min just in case
	pollTimeout := time.Minute * 5

	// set the number of step to high value
	// we should stop on timeout otherwise the backoff returns after 5 steps
	// and we never wait the timeout value
	backOff := retry.DefaultBackoff
	backOff.Steps = 9999

	// in theory the max time we tolerate disruption on an SNO cluster is 60 seconds
	// so we set the timeout to 5 min just in case
	err := onErrorWithTimeout(pollTimeout, backOff, func(err error) bool {
		if !transientAPIError(err) {
			t.Logf("error = %v is not retriable, failed to get the metadata from the last encryption key", err)
			return false
		}
		return true // retry
	}, func() (err error) {
		selectedSecrets, err = secretsClient.List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil {
			t.Logf("failed to list secrets, err = %v", err.Error())
		}
		return
	})
	if err != nil {
		return EncryptionKeyMeta{}, err
	}

	if len(selectedSecrets.Items) == 0 {
		return EncryptionKeyMeta{}, nil
	}
	encryptionSecrets := make([]*corev1.Secret, 0, len(selectedSecrets.Items))
	for _, s := range selectedSecrets.Items {
		encryptionSecrets = append(encryptionSecrets, s.DeepCopy())
	}
	sort.Slice(encryptionSecrets, func(i, j int) bool {
		iKeyID, _ := encryptionKeyNameToKeyID(encryptionSecrets[i].Name)
		jKeyID, _ := encryptionKeyNameToKeyID(encryptionSecrets[j].Name)
		return iKeyID > jKeyID
	})
	lastKey := encryptionSecrets[0]

	type migratedGroupResources struct {
		Resources []schema.GroupResource `json:"resources"`
	}

	migrated := &migratedGroupResources{}
	if v, ok := lastKey.Annotations["encryption.apiserver.operator.openshift.io/migrated-resources"]; ok && len(v) > 0 {
		if err := json.Unmarshal([]byte(v), migrated); err != nil {
			return EncryptionKeyMeta{}, err
		}
	}
	mode := lastKey.Annotations["encryption.apiserver.operator.openshift.io/mode"]

	return EncryptionKeyMeta{Name: lastKey.Name, Migrated: migrated.Resources, Mode: mode}, nil
}

func ForceKeyRotation(t testing.TB, updateUnsupportedConfig UpdateUnsupportedConfigFunc, reason string) error {
	t.Logf("Forcing a new key rotation, reason %q", reason)
	data := map[string]map[string]string{
		"encryption": {
			"reason": reason,
		},
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return onErrorWithTimeout(wait.ForeverTestTimeout, retry.DefaultBackoff, orError(errors.IsConflict, transientAPIError), func() error {
		return updateUnsupportedConfig(raw)
	})
}

// hasResource returns whether the given group resource is contained in the migrated group resource list.
func hasResource(expectedResource schema.GroupResource, actualResources []schema.GroupResource) bool {
	for _, gr := range actualResources {
		if gr == expectedResource {
			return true
		}
	}
	return false
}

func encryptionKeyNameToKeyID(name string) (uint64, bool) {
	lastIdx := strings.LastIndex(name, "-")
	idString := name
	if lastIdx >= 0 {
		idString = name[lastIdx+1:] // this can never overflow since str[-1+1:] is
	}
	id, err := strconv.ParseUint(idString, 10, 0)
	return id, err == nil
}

func determineNextEncryptionKeyName(prevKeyName, labelSelector string) (string, error) {
	if len(prevKeyName) > 0 {
		prevKeyID, prevKeyValid := encryptionKeyNameToKeyID(prevKeyName)
		if !prevKeyValid {
			return "", fmt.Errorf("invalid key %q passed", prevKeyName)
		}
		nexKeyID := prevKeyID + 1
		return strings.Replace(prevKeyName, fmt.Sprintf("%d", prevKeyID), fmt.Sprintf("%d", nexKeyID), 1), nil
	}

	ret := strings.Split(labelSelector, "=")
	if len(ret) != 2 {
		return "", fmt.Errorf("unable to read the component name from the label selector, wrong format of the selector, expected \"...openshift.io/component=name\", got %s", labelSelector)
	}

	// no encryption key - the first one will look like the following
	return fmt.Sprintf("encryption-key-%s-1", ret[1]), nil
}

func setUpTearDown(namespace string) func(testing.TB, bool) {
	return func(t testing.TB, failed bool) {
		if failed { // we don't use t.Failed() because we handle termination differently when running on a local machine
			t.Logf("Tearing Down %s", t.Name())
			eventsToPrint := 20
			clientSet := GetClients(t)

			eventList, err := clientSet.Kube.CoreV1().Events(namespace).List(context.TODO(), metav1.ListOptions{})
			require.NoError(t, err)

			sort.Slice(eventList.Items, func(i, j int) bool {
				first := eventList.Items[i]
				second := eventList.Items[j]
				return first.LastTimestamp.After(second.LastTimestamp.Time)
			})

			t.Logf("Dumping %d events from %q namespace", eventsToPrint, namespace)
			now := time.Now()
			if len(eventList.Items) > eventsToPrint {
				eventList.Items = eventList.Items[:eventsToPrint]
			}
			for _, ev := range eventList.Items {
				t.Logf("Last seen: %-15v Type: %-10v Reason: %-40v Source: %-55v Message: %v", now.Sub(ev.LastTimestamp.Time), ev.Type, ev.Reason, ev.Source.Component, ev.Message)
			}
		}
	}
}

// WaitForPodImagePullBackOff polls pods in the given namespace until at least one pod
// has a container stuck in ImagePullBackOff or ErrImagePull.
// When a KMS plugin image is invalid, the operator cannot progress because the
// sidecar container fails to start. The operator does not report Degraded in this
// case — it only gets stuck in Progressing. This function detects that stuck state
// by observing the pod-level image pull failure, which is the earliest signal that
// the invalid config has taken effect.
func WaitForPodImagePullBackOff(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, namespace, labelSelector string, timeout time.Duration) {
	t.Helper()
	t.Logf("Waiting up to %s for a pod in %s (selector=%s) to enter ImagePullBackOff", timeout, namespace, labelSelector)
	err := wait.PollUntilContextTimeout(ctx, waitPollInterval, timeout, true, func(ctx context.Context) (bool, error) {
		pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil {
			t.Logf("Error listing pods: %v", err)
			return false, nil
		}
		for _, pod := range pods.Items {
			for _, cs := range append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...) {
				if cs.State.Waiting != nil && (cs.State.Waiting.Reason == "ImagePullBackOff" || cs.State.Waiting.Reason == "ErrImagePull") {
					t.Logf("Pod %s container %s is in %s", pod.Name, cs.Name, cs.State.Waiting.Reason)
					return true, nil
				}
			}
		}
		return false, nil
	})
	require.NoError(t, err, "timed out waiting for pod to enter ImagePullBackOff in namespace %s", namespace)
}

// WaitForPodContainerCondition polls pods until at least one pod satisfies the given condition.
// keyName is the current encryption key secret name, passed to match so callers can
// correlate pod container names with the active key (e.g. vault-kms-plugin-42).
func WaitForPodContainerCondition(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface, namespace, labelSelector, keyName string, match func(pod corev1.Pod, keyName string) bool) {
	t.Helper()
	t.Logf("Waiting up to %s for a pod in %s (selector=%s, key=%s) to satisfy condition",
		waitPollTimeout, namespace, labelSelector, keyName)
	err := wait.PollUntilContextTimeout(ctx, waitPollInterval, waitPollTimeout, true, func(ctx context.Context) (bool, error) {
		pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil {
			t.Logf("Error listing pods: %v", err)
			return false, nil
		}
		if len(pods.Items) == 0 {
			t.Logf("No pods found yet in %s", namespace)
			return false, nil
		}
		for _, pod := range pods.Items {
			if match(pod, keyName) {
				return true, nil
			}
		}
		t.Logf("No pod yet satisfies condition")
		return false, nil
	})
	require.NoError(t, err, "timed out waiting for a pod in %s to satisfy condition", namespace)
}

// WaitForCurrentKeyMigrated waits until the current (latest) encryption key has completed
// migration for all target group resources. It fails if the key changes unexpectedly
// (i.e. a different key than prevKeyMeta appears).
func WaitForCurrentKeyMigrated(t testing.TB, kubeClient kubernetes.Interface, prevKeyMeta EncryptionKeyMeta, targetGRs []schema.GroupResource, namespace, labelSelector string) {
	t.Helper()

	t.Logf("Waiting up to %s for key %q to complete migration of %v", waitPollTimeout.String(), prevKeyMeta.Name, targetGRs)
	if err := wait.Poll(waitPollInterval, waitPollTimeout, func() (bool, error) {
		currentKeyMeta, err := GetLastKeyMeta(t, kubeClient, namespace, labelSelector)
		if err != nil {
			return false, err
		}
		if currentKeyMeta.Name != prevKeyMeta.Name {
			return false, fmt.Errorf("unexpected key observed %q, expected no new key", currentKeyMeta.Name)
		}
		if len(currentKeyMeta.Migrated) < len(targetGRs) {
			return false, nil
		}
		for _, expectedGR := range targetGRs {
			if !hasResource(expectedGR, currentKeyMeta.Migrated) {
				return false, nil
			}
		}
		t.Logf("Key %q has completed migration of %v", currentKeyMeta.Name, currentKeyMeta.Migrated)
		return true, nil
	}); err != nil {
		newErr := fmt.Errorf("timed out waiting for key %q to complete migration of %v: %v", prevKeyMeta.Name, targetGRs, err)
		require.NoError(t, newErr)
	}
}

// inParallel returns a single testStep that runs the given steps
// concurrently and waits for all to finish before returning.
// Panics are caught and reported via t.Errorf. Failures from
// t.FailNow/require (runtime.Goexit) are handled naturally since
// the testing framework already records the error on t.
func inParallel(steps ...testStep) testStep {
	if len(steps) == 1 {
		return steps[0]
	}
	names := make([]string, len(steps))
	for i, s := range steps {
		names[i] = s.name
	}
	return testStep{
		name: strings.Join(names, " | "),
		testFunc: func(t testing.TB) {
			var wg sync.WaitGroup
			for _, s := range steps {
				wg.Go(func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("step %q panicked: %v", s.name, r)
						}
					}()
					s.testFunc(t)
				})
			}
			wg.Wait()
		},
	}
}

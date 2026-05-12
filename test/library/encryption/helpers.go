package encryption

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
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
}

type EncryptionKeyMeta struct {
	Name     string
	Migrated []schema.GroupResource
	Mode     string
}

type UpdateUnsupportedConfigFunc func(raw []byte) error

// GetOperatorConditionsFuncType fetches operator conditions (e.g. for EncryptionMigrationControllerProgressing).
type GetOperatorConditionsFuncType func(t testing.TB) ([]operatorv1.OperatorCondition, error)

func SetAndWaitForEncryptionType(t testing.TB, provider EncryptionProvider, defaultTargetGRs []schema.GroupResource, namespace, labelSelector string) ClientSet {
	clientSet := GetClients(t)
	lastMigratedKeyMeta, err := GetLastKeyMeta(t, clientSet.Kube, namespace, labelSelector)
	require.NoError(t, err)

	ApplyAPIServerEncryptionType(t, clientSet, provider)
	WaitForEncryptionKeyBasedOn(t, clientSet.Kube, lastMigratedKeyMeta, provider.Type, defaultTargetGRs, namespace, labelSelector)
	return clientSet
}

func ApplyAPIServerEncryptionType(t testing.TB, clientSet ClientSet, provider EncryptionProvider) {
	t.Helper()
	t.Logf("Starting encryption e2e test for %q mode", provider.Type)

	apiServer, err := clientSet.ApiServerConfig.Get(context.TODO(), "cluster", metav1.GetOptions{})
	require.NoError(t, err)
	needsUpdate := !equality.Semantic.DeepEqual(apiServer.Spec.Encryption, provider.APIServerEncryption)
	if needsUpdate {
		if provider.Setup != nil {
			provider.Setup(t)
		}
		t.Logf("Updating encryption configuration for APIServer from %#v to %#v", apiServer.Spec.Encryption, provider.APIServerEncryption)
		apiServer.Spec.Encryption = provider.APIServerEncryption
		_, err = clientSet.ApiServerConfig.Update(context.TODO(), apiServer, metav1.UpdateOptions{})
		require.NoError(t, err)
	} else {
		t.Logf("APIServer is already configured to use %q mode", provider.Type)
	}
}

func GetClients(t testing.TB) ClientSet {
	t.Helper()

	kubeConfig, err := library.NewClientConfigForTest()
	require.NoError(t, err)

	configClient := configv1client.NewForConfigOrDie(kubeConfig)
	apiServerConfigClient := configClient.APIServers()

	kubeClient := kubernetes.NewForConfigOrDie(kubeConfig)
	etcdClient := NewEtcdClient(kubeClient)

	return ClientSet{Etcd: etcdClient, ApiServerConfig: apiServerConfigClient, Kube: kubeClient}
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
		waitForNoNewEncryptionKey(t, kubeClient, prevKeyMeta, namespace, labelSelector)
		return
	}
	WaitForNextMigratedKey(t, kubeClient, prevKeyMeta, defaultTargetGRs, namespace, labelSelector)
}

func waitForNoNewEncryptionKey(t testing.TB, kubeClient kubernetes.Interface, prevKeyMeta EncryptionKeyMeta, namespace, labelSelector string) {
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

// ClearForcedKeyRotationReason clears encryption.reason under UnsupportedConfigOverrides (same merge path as
// ForceKeyRotation). Call when a test finishes so the next test in sequence does not inherit a non-empty
// reason and the key controller does not keep seeing an external rotation request.
func ClearForcedKeyRotationReason(t testing.TB, updateUnsupportedConfig UpdateUnsupportedConfigFunc) error {
	t.Helper()
	t.Logf("Clearing forced encryption rotation reason (unsupported config overrides)")
	data := map[string]map[string]string{
		"encryption": {
			"reason": "",
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

const encryptionMigrationControllerProgressingType = "EncryptionMigrationControllerProgressing"

// allTargetGRsMigrated reports whether every resource in targetGRs appears in meta's migrated list.
func allTargetGRsMigrated(meta EncryptionKeyMeta, targetGRs []schema.GroupResource) bool {
	if len(targetGRs) == 0 {
		return true
	}
	for _, gr := range targetGRs {
		if !hasResource(gr, meta.Migrated) {
			return false
		}
	}
	return true
}

// WaitUntilEncryptionStable waits until the latest write key secret reports the expected mode and all target resources are migrated.
func WaitUntilEncryptionStable(t testing.TB, kube kubernetes.Interface, expectedMode configv1.EncryptionType, targetGRs []schema.GroupResource, namespace, labelSelector string) {
	t.Helper()
	wantMode := string(expectedMode)
	err := wait.Poll(waitPollInterval, waitPollTimeout, func() (bool, error) {
		meta, err := GetLastKeyMeta(t, kube, namespace, labelSelector)
		if err != nil {
			return false, err
		}
		if meta.Mode != wantMode {
			return false, nil
		}
		if !allTargetGRsMigrated(meta, targetGRs) {
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)
}

// WaitForNRotations waits until encryption is stable (expectedMode on the latest write key and every target
// group resource migrated), then asserts the latest write key secret's numeric suffix equals the baseline
// secret's suffix plus n. If baselineMeta.Name is empty (no prior write key), the baseline suffix is treated
// as 0. Use n to count new write-key revisions you expect after baselineMeta was captured (for example one
// per successful ForceKeyRotation, plus any additional revision from turning encryption on).
func WaitForNRotations(t testing.TB, kube kubernetes.Interface, expectedMode configv1.EncryptionType, targetGRs []schema.GroupResource, namespace, labelSelector string, baselineMeta EncryptionKeyMeta, n uint64) {
	t.Helper()
	WaitUntilEncryptionStable(t, kube, expectedMode, targetGRs, namespace, labelSelector)

	finalMeta, err := GetLastKeyMeta(t, kube, namespace, labelSelector)
	require.NoError(t, err)
	finalID, ok := EncryptionWriteKeySecretID(finalMeta.Name)
	require.True(t, ok, "latest encryption key name must carry a numeric suffix: %q", finalMeta.Name)

	var baselineID uint64
	if len(baselineMeta.Name) == 0 {
		baselineID = 0
	} else {
		var baselineOK bool
		baselineID, baselineOK = EncryptionWriteKeySecretID(baselineMeta.Name)
		require.True(t, baselineOK, "baseline encryption key name must carry a numeric suffix: %q", baselineMeta.Name)
	}

	expectedFinalID := baselineID + n
	require.Equal(t, expectedFinalID, finalID, "expected write-key id %d (baseline id %d + %d), got final key %q id %d", expectedFinalID, baselineID, n, finalMeta.Name, finalID)
}

// EncryptionWriteKeySecretID returns the numeric suffix of an encryption write-key secret name (the value
// used when sorting keys by revision, e.g. encryption-key-openshift-apiserver-4 yields 4).
func EncryptionWriteKeySecretID(secretName string) (uint64, bool) {
	return encryptionKeyNameToKeyID(secretName)
}

// WaitForEncryptionMigrationInProgressWindow waits until storage migration is actively running so another
// encryption change can be stacked. It returns false when the migration for expectedWriteKey completed
// before an in-progress snapshot could be observed (caller may t.Skip).
func WaitForEncryptionMigrationInProgressWindow(t testing.TB, kube kubernetes.Interface, getOp GetOperatorConditionsFuncType, expectedWriteKey string, targetGRs []schema.GroupResource, namespace, labelSelector string) bool {
	t.Helper()
	const kubePoll = 1 * time.Second
	const windowWait = 25 * time.Minute

	if getOp != nil {
		err := wait.Poll(2*time.Second, windowWait, func() (bool, error) {
			conds, err := getOp(t)
			if err != nil {
				return false, err
			}
			for _, c := range conds {
				if c.Type == encryptionMigrationControllerProgressingType && c.Status == operatorv1.ConditionTrue && c.Reason == "Migrating" {
					return true, nil
				}
			}
			return false, nil
		})
		if err == nil {
			return true
		}
		t.Logf("encryption migration progressing condition not observed within %v, falling back to secret metadata polling: %v", windowWait, err)
	}

	deadline := time.Now().Add(windowWait)
	for time.Now().Before(deadline) {
		meta, err := GetLastKeyMeta(t, kube, namespace, labelSelector)
		require.NoError(t, err)
		if meta.Name == expectedWriteKey {
			if allTargetGRsMigrated(meta, targetGRs) {
				return false
			}
			return true
		}
		time.Sleep(kubePoll)
	}
	require.FailNow(t, fmt.Sprintf("timed out after %v waiting for migration in progress on key %q", windowWait, expectedWriteKey))
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

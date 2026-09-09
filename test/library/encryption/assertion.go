package encryption

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clientv3 "go.etcd.io/etcd/client/v3"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	configv1 "github.com/openshift/api/config/v1"
	oauthapiv1 "github.com/openshift/api/oauth/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

var protoEncodingPrefix = []byte{0x6b, 0x38, 0x73, 0x00}

var (
	apiserverScheme = runtime.NewScheme()
	apiserverCodecs = serializer.NewCodecFactory(apiserverScheme)
)

const (
	jsonEncodingPrefix           = "{"
	protoEncryptedDataPrefix     = "k8s:enc:"
	aesCBCTransformerPrefixV1    = "k8s:enc:aescbc:v1:"
	aesGCMTransformerPrefixV1    = "k8s:enc:aesgcm:v1:"
	secretboxTransformerPrefixV1 = "k8s:enc:secretbox:v1:"
	kmsTransformerPrefixV2       = "k8s:enc:kms:v2:"
)

func init() {
	utilruntime.Must(apiserverconfigv1.AddToScheme(apiserverScheme))
}

// AssertEncryptionConfig checks if the encryption config holds only targetGRs, this ensures that only those resources were encrypted,
// we don't check the keys because e2e tests are run randomly and we would have to consider all encryption secrets to get the right order of the keys.
// We test the content of the encryption config in more detail in unit and integration tests
func AssertEncryptionConfig(t testing.TB, clientSet ClientSet, encryptionConfigSecretName string, namespace string, targetGRs []schema.GroupResource) {
	t.Helper()
	t.Logf("Checking if %q in %q has desired GRs %v", encryptionConfigSecretName, namespace, targetGRs)
	encryptionCofnigSecret, err := clientSet.Kube.CoreV1().Secrets(namespace).Get(context.TODO(), encryptionConfigSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	encodedEncryptionConfig, foundEncryptionConfig := encryptionCofnigSecret.Data["encryption-config"]
	if !foundEncryptionConfig {
		t.Errorf("Haven't found encryption config at %q key in the encryption secret %q", "encryption-config", encryptionConfigSecretName)
	}

	decoder := apiserverCodecs.UniversalDecoder(apiserverconfigv1.SchemeGroupVersion)
	encryptionConfigObj, err := runtime.Decode(decoder, encodedEncryptionConfig)
	require.NoError(t, err)
	encryptionConfig, ok := encryptionConfigObj.(*apiserverconfigv1.EncryptionConfiguration)
	if !ok {
		t.Errorf("Unable to decode encryption config, unexpected wrong type %T", encryptionConfigObj)
	}

	for _, rawActualResource := range encryptionConfig.Resources {
		if len(rawActualResource.Resources) != 1 {
			t.Errorf("Invalid encryption config for resource %s, expected exactly one resource, got %d", rawActualResource.Resources, len(rawActualResource.Resources))
		}
		actualResource := schema.ParseGroupResource(rawActualResource.Resources[0])
		actualResourceFound := false
		for _, expectedResource := range targetGRs {
			if reflect.DeepEqual(expectedResource, actualResource) {
				actualResourceFound = true
				break
			}
		}
		if !actualResourceFound {
			t.Errorf("Encryption config has an invalid resource %v", actualResource)
		}
	}
}

func AssertLastMigratedKey(t testing.TB, kubeClient kubernetes.Interface, targetGRs []schema.GroupResource, namespace, labelSelector string) {
	t.Helper()
	expectedGRs := targetGRs
	t.Logf("Checking if the last migrated key was used to encrypt %v", expectedGRs)
	lastMigratedKeyMeta, err := GetLastKeyMeta(t, kubeClient, namespace, labelSelector)
	require.NoError(t, err)
	if len(lastMigratedKeyMeta.Name) == 0 {
		t.Log("Nothing to check no new key was created")
		return
	}

	if len(expectedGRs) != len(lastMigratedKeyMeta.Migrated) {
		t.Errorf("Wrong number of migrated resources for %q key, expected %d, got %d", lastMigratedKeyMeta.Name, len(expectedGRs), len(lastMigratedKeyMeta.Migrated))
	}

	for _, expectedGR := range expectedGRs {
		if !hasResource(expectedGR, lastMigratedKeyMeta.Migrated) {
			t.Errorf("%q wasn't used to encrypt %v, only %v", lastMigratedKeyMeta.Name, expectedGR, lastMigratedKeyMeta.Migrated)
		}
	}
}

func VerifyResources(t testing.TB, etcdClient EtcdClient, etcdKeyPreifx string, expectedMode string, allowEmpty bool) (int, error) {
	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	resp, err := etcdClient.Get(timeout, etcdKeyPreifx, clientv3.WithPrefix())
	switch {
	case err != nil:
		return 0, fmt.Errorf("failed to list prefix %s: %v", etcdKeyPreifx, err)
	case (resp.Count == 0 || len(resp.Kvs) == 0) && !allowEmpty:
		return 0, fmt.Errorf("empty list response for prefix %s: %+v", etcdKeyPreifx, resp)
	case resp.More:
		return 0, fmt.Errorf("incomplete list response for prefix %s: %+v", etcdKeyPreifx, resp)
	}

	for _, keyValue := range resp.Kvs {
		if err := verifyPrefixForRawData(expectedMode, keyValue.Value); err != nil {
			return 0, fmt.Errorf("key %s failed check: %v\n%s", keyValue.Key, err, hex.Dump(keyValue.Value))
		}
	}

	return len(resp.Kvs), nil
}

func verifyPrefixForRawData(expectedMode string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}

	conditionToStr := func(condition bool) string {
		if condition {
			return "encrypted"
		}
		return "unencrypted"
	}

	expectedEncrypted := true
	if expectedMode == "identity" {
		expectedMode = "identity-proto"
		expectedEncrypted = false
	}

	actualMode, isEncrypted := encryptionModeFromEtcdValue(data)
	if expectedEncrypted != isEncrypted {
		return fmt.Errorf("unexpected encrypted state, expected data to be %q but was %q with mode %q", conditionToStr(expectedEncrypted), conditionToStr(isEncrypted), actualMode)
	}
	if actualMode != expectedMode {
		return fmt.Errorf("unexpected encryption mode %q, expected %q, was data encrypted/decrypted with a wrong key", actualMode, expectedMode)
	}

	return nil
}

func encryptionModeFromEtcdValue(data []byte) (string, bool) {
	isEncrypted := bytes.HasPrefix(data, []byte(protoEncryptedDataPrefix)) // all encrypted data has this prefix
	return func() string {
		switch {
		case hasPrefixAndTrailingData(data, []byte(aesCBCTransformerPrefixV1)): // AES-CBC has this prefix
			return "aescbc"
		case hasPrefixAndTrailingData(data, []byte(aesGCMTransformerPrefixV1)): // AES-GCM has this prefix
			return "aesgcm"
		case hasPrefixAndTrailingData(data, []byte(secretboxTransformerPrefixV1)): // Secretbox has this prefix
			return "secretbox"
		case hasPrefixAndTrailingData(data, []byte(kmsTransformerPrefixV2)): // KMS v2 has this prefix
			return "KMS"
		case hasPrefixAndTrailingData(data, []byte(jsonEncodingPrefix)): // unencrypted json data has this prefix
			return "identity-json"
		case hasPrefixAndTrailingData(data, protoEncodingPrefix): // unencrypted protobuf data has this prefix
			return "identity-proto"
		default:
			return "unknown" // this should never happen
		}
	}(), isEncrypted
}

func hasPrefixAndTrailingData(data, prefix []byte) bool {
	return bytes.HasPrefix(data, prefix) && len(data) > len(prefix)
}

// kmsPluginNameFromEtcdValue extracts the KMS provider name from etcd data encrypted with KMS v2.
// In OpenShift the name is "{operatorKeyID}_{resource}", e.g. "2_secrets".
func kmsPluginNameFromEtcdValue(data []byte) (string, bool) {
	if !bytes.HasPrefix(data, []byte(kmsTransformerPrefixV2)) {
		return "", false
	}
	rest := data[len(kmsTransformerPrefixV2):]
	i := bytes.IndexByte(rest, ':')
	if i <= 0 {
		return "", false
	}
	return string(rest[:i]), true
}

func assertKMSEncryptedWithWriteKey(t testing.TB, kubeClient kubernetes.Interface, namespace, labelSelector string, raw []byte, gr schema.GroupResource) {
	t.Helper()
	lastMigratedKeyMeta, err := GetLastKeyMeta(t, kubeClient, namespace, labelSelector)
	require.NoError(t, err)
	require.NotEmpty(t, lastMigratedKeyMeta.Name, "no encryption key found to verify KMS keyID")

	keyID, ok := encryptionKeyNameToKeyID(lastMigratedKeyMeta.Name)
	require.True(t, ok, "invalid encryption key secret name %q", lastMigratedKeyMeta.Name)
	expectedKeyID := strconv.FormatUint(keyID, 10)

	// OpenShift builds KMS plugin names as "{keyID}_{resource}" where resource is the
	// bare resource name (gr.Resource), not gr.String() — see stateToProviders in encryptiondata/config.go.
	expectedPluginName := fmt.Sprintf("%s_%s", expectedKeyID, gr.Resource)
	t.Logf("Verifying etcd encryption prefix for resource %q matches operator keyID %q", gr.Resource, expectedKeyID)

	actualPluginName, ok := kmsPluginNameFromEtcdValue(raw)
	if !ok {
		t.Fatalf("etcd data for resource %q: expected KMS v2 encryption with operator keyID %q", gr.Resource, expectedKeyID)
	}
	if actualPluginName != expectedPluginName {
		t.Fatalf("etcd data for resource %q: want plugin name %q, got %q (expected operator keyID %q)",
			gr.Resource, expectedPluginName, actualPluginName, expectedKeyID)
	}
	t.Logf("etcd data for resource %q matches operator keyID %q", gr.Resource, expectedKeyID)
}

var WellKnownKASTargetGRs = []schema.GroupResource{
	{Group: "", Resource: "secrets"},
	{Group: "", Resource: "configmaps"},
}

func AssertWellKnownSecretOfLifeEncrypted(t testing.TB, clientSet ClientSet, resource runtime.Object) {
	t.Helper()
	secret, ok := resource.(*corev1.Secret)
	if !ok {
		t.Fatalf("expected *corev1.Secret, got %T", resource)
	}
	rawValue := GetRawWellKnownSecretOfLife(t, clientSet, secret.Namespace)
	if strings.Contains(rawValue, string(secret.Data["quote"])) {
		t.Errorf("secret not encrypted, etcd value contains quote in plain text")
	}
}

func AssertWellKnownSecretOfLifeEncryptedWithKMS(t testing.TB, clientSet ClientSet, namespace, labelSelector string, resource runtime.Object) {
	t.Helper()
	secret, ok := resource.(*corev1.Secret)
	if !ok {
		t.Fatalf("expected *corev1.Secret, got %T", resource)
	}
	assertKMSEncryptedWithWriteKey(t, clientSet.Kube, namespace, labelSelector,
		[]byte(GetRawWellKnownSecretOfLife(t, clientSet, secret.Namespace)), WellKnownKASTargetGRs[0])
}

func AssertWellKnownSecretOfLifeNotEncrypted(t testing.TB, clientSet ClientSet, resource runtime.Object) {
	t.Helper()
	secret, ok := resource.(*corev1.Secret)
	if !ok {
		t.Fatalf("expected *corev1.Secret, got %T", resource)
	}
	rawValue := GetRawWellKnownSecretOfLife(t, clientSet, secret.Namespace)
	if !strings.Contains(rawValue, string(secret.Data["quote"])) {
		t.Errorf("secret not decrypted, etcd value does not contain quote in plain text")
	}
}

func AssertWellKnownSecretsAndConfigMaps(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
	t.Helper()
	assertSecrets(t, clientSet.Etcd, string(expectedMode))
	assertConfigMaps(t, clientSet.Etcd, string(expectedMode))
	AssertLastMigratedKey(t, clientSet.Kube, WellKnownKASTargetGRs, namespace, labelSelector)
}

func assertSecrets(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all Secrets where encrypted/decrypted for %q mode", expectedMode)
	totalSecrets, err := VerifyResources(t, etcdClient, "/kubernetes.io/secrets/", expectedMode, false)
	t.Logf("Verified %d Secrets", totalSecrets)
	require.NoError(t, err)
}

func assertConfigMaps(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all ConfigMaps where encrypted/decrypted for %q mode", expectedMode)
	totalConfigMaps, err := VerifyResources(t, etcdClient, "/kubernetes.io/configmaps/", expectedMode, false)
	t.Logf("Verified %d ConfigMaps", totalConfigMaps)
	require.NoError(t, err)
}

var WellKnownAuthTargetGRs = []schema.GroupResource{
	{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
	{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
}

func AssertWellKnownTokenOfLifeEncrypted(t testing.TB, clientSet ClientSet, _ runtime.Object) {
	t.Helper()
	rawTokenValue := GetRawWellKnownTokenOfLife(t, clientSet)
	marker := "I have no special talents. I am only passionately curious"
	if strings.Contains(rawTokenValue, marker) {
		t.Errorf("access token not encrypted, etcd value contains refresh token marker in plain text")
	}
}

func AssertWellKnownTokenOfLifeEncryptedWithKMS(t testing.TB, clientSet ClientSet, namespace, labelSelector string, resource runtime.Object) {
	t.Helper()
	if _, ok := resource.(*oauthapiv1.OAuthAccessToken); !ok {
		t.Fatalf("expected *oauthapiv1.OAuthAccessToken, got %T", resource)
	}
	assertKMSEncryptedWithWriteKey(t, clientSet.Kube, namespace, labelSelector,
		[]byte(GetRawWellKnownTokenOfLife(t, clientSet)), WellKnownAuthTargetGRs[0])
}

func AssertWellKnownTokenOfLifeNotEncrypted(t testing.TB, clientSet ClientSet, _ runtime.Object) {
	t.Helper()
	rawTokenValue := GetRawWellKnownTokenOfLife(t, clientSet)
	marker := "I have no special talents. I am only passionately curious"
	if !strings.Contains(rawTokenValue, marker) {
		t.Errorf("access token not decrypted, etcd value does not contain refresh token marker in plain text")
	}
}

func AssertWellKnownTokens(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
	t.Helper()
	assertWellKnownAccessTokens(t, clientSet.Etcd, string(expectedMode))
	assertWellKnownAuthTokens(t, clientSet.Etcd, string(expectedMode))
	AssertLastMigratedKey(t, clientSet.Kube, WellKnownAuthTargetGRs, namespace, labelSelector)
}

func assertWellKnownAccessTokens(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all OauthAccessTokens where encrypted/decrypted for %q mode", expectedMode)
	totalAccessTokens, err := VerifyResources(t, etcdClient, "/openshift.io/oauth/accesstokens/", expectedMode, true)
	t.Logf("Verified %d OauthAccessTokens", totalAccessTokens)
	require.NoError(t, err)
}

func assertWellKnownAuthTokens(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all OAuthAuthorizeTokens where encrypted/decrypted for %q mode", expectedMode)
	totalAuthTokens, err := VerifyResources(t, etcdClient, "/openshift.io/oauth/authorizetokens/", expectedMode, true)
	t.Logf("Verified %d OAuthAuthorizeTokens", totalAuthTokens)
	require.NoError(t, err)
}

var WellKnownOASTargetGRs = []schema.GroupResource{
	{Group: "route.openshift.io", Resource: "routes"},
}

func AssertWellKnownRouteOfLifeEncrypted(t testing.TB, clientSet ClientSet, resource runtime.Object) {
	t.Helper()
	routeOfLife, ok := resource.(*routev1.Route)
	if !ok {
		t.Fatalf("expected *routev1.Route, got %T", resource)
	}
	rawRouteValue := GetRawWellKnownRouteOfLife(t, clientSet, routeOfLife.Namespace)
	if strings.Contains(rawRouteValue, routeOfLife.Spec.To.Name) {
		t.Errorf("route not encrypted, etcd value contains target name %q in plain text", routeOfLife.Spec.To.Name)
	}
}

func AssertWellKnownRouteOfLifeEncryptedWithKMS(t testing.TB, clientSet ClientSet, namespace, labelSelector string, resource runtime.Object) {
	t.Helper()
	routeOfLife, ok := resource.(*routev1.Route)
	if !ok {
		t.Fatalf("expected *routev1.Route, got %T", resource)
	}
	assertKMSEncryptedWithWriteKey(t, clientSet.Kube, namespace, labelSelector,
		[]byte(GetRawWellKnownRouteOfLife(t, clientSet, routeOfLife.Namespace)), WellKnownOASTargetGRs[0])
}

func AssertWellKnownRouteOfLifeNotEncrypted(t testing.TB, clientSet ClientSet, resource runtime.Object) {
	t.Helper()
	routeOfLife, ok := resource.(*routev1.Route)
	if !ok {
		t.Fatalf("expected *routev1.Route, got %T", resource)
	}
	rawRouteValue := GetRawWellKnownRouteOfLife(t, clientSet, routeOfLife.Namespace)
	if !strings.Contains(rawRouteValue, routeOfLife.Spec.To.Name) {
		t.Errorf("route not decrypted, etcd value does not contain target name %q in plain text", routeOfLife.Spec.To.Name)
	}
}

func AssertWellKnownRoutes(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
	t.Helper()
	assertWellKnownRoutes(t, clientSet.Etcd, string(expectedMode))
	AssertLastMigratedKey(t, clientSet.Kube, WellKnownOASTargetGRs, namespace, labelSelector)
}

func assertWellKnownRoutes(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all Routes where encrypted/decrypted for %q mode", expectedMode)
	totalRoutes, err := VerifyResources(t, etcdClient, "/openshift.io/routes/", expectedMode, false)
	t.Logf("Verified %d Routes", totalRoutes)
	require.NoError(t, err)
}

// preflightDegradedConditionType is set by kmsPreflightController, which exports no constant for it.
const preflightDegradedConditionType = "EncryptionKMSPreflightControllerDegraded"

// kmsOperatorStatus is the subset of an operator CR status the KMS preflight assertions read.
type kmsOperatorStatus struct {
	Conditions       []operatorv1.OperatorCondition `json:"conditions"`
	EncryptionStatus operatorv1.KMSEncryptionStatus `json:"encryptionStatus"`
}

func decodeKMSOperatorStatus(obj map[string]interface{}) (kmsOperatorStatus, error) {
	var cr struct {
		Status kmsOperatorStatus `json:"status"`
	}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj, &cr)
	return cr.Status, err
}

// operatorGVRForNamespace maps an operator namespace to its operator CR.
func operatorGVRForNamespace(t testing.TB, operatorNamespace string) schema.GroupVersionResource {
	t.Helper()
	byNamespace := map[string]schema.GroupVersionResource{
		"openshift-kube-apiserver-operator": {Group: "operator.openshift.io", Version: "v1", Resource: "kubeapiservers"},
		"openshift-authentication-operator": {Group: "operator.openshift.io", Version: "v1", Resource: "authentications"},
		"openshift-apiserver-operator":      {Group: "operator.openshift.io", Version: "v1", Resource: "openshiftapiservers"},
	}
	gvr, ok := byNamespace[operatorNamespace]
	require.Truef(t, ok, "no known operator CR for namespace %q; cannot read/assert KMS preflight", operatorNamespace)
	return gvr
}

// AssertKMSPreflightSucceededForOperator asserts KMS preflight passed for the operator owning
// operatorNamespace. previous is the pre-apply snapshot (see ReadKMSPreflightForOperator).
func AssertKMSPreflightSucceededForOperator(ctx context.Context, t testing.TB, clientSet ClientSet, operatorNamespace string, previous operatorv1.KMSPreflightCheck) {
	t.Helper()
	gvr := operatorGVRForNamespace(t, operatorNamespace)
	assertKMSPreflightSucceeded(ctx, t, clientSet.DynamicClient, gvr, "cluster", previous)
}

// assertKMSPreflightSucceeded asserts preflight passed for the CR's current config: degraded is
// False, preflight reports Succeeded for the observed config hash, remoteKeyID is set (proving a
// live KMS check ran), and remoteKeyID advanced when the config changed since previous.
func assertKMSPreflightSucceeded(ctx context.Context, t testing.TB, dynamicClient dynamic.Interface, gvr schema.GroupVersionResource, name string, previous operatorv1.KMSPreflightCheck) {
	t.Helper()

	var preflight operatorv1.KMSPreflightCheck
	var degradedFalse bool
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
		obj, err := dynamicClient.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		status, err := decodeKMSOperatorStatus(obj.Object)
		if err != nil {
			return false, err
		}
		preflight = status.EncryptionStatus.Preflight
		result := preflight.Result
		degradedFalse = v1helpers.IsOperatorConditionFalse(status.Conditions, preflightDegradedConditionType)
		passed := result.Status == operatorv1.KMSPreflightResultSucceeded && result.ConfigHash != "" && result.ConfigHash == preflight.ObservedConfigHash
		fresh := preflight.ObservedConfigHash == previous.ObservedConfigHash || result.RemoteKeyID != previous.Result.RemoteKeyID
		ran := result.RemoteKeyID != ""
		return degradedFalse && passed && ran && fresh, nil
	})
	require.NoErrorf(t, err,
		"KMS preflight not confirmed for %s/%s: degradedFalse=%t result.status=%q result.configHash=%q observedConfigHash=%q remoteKeyID=%q (previous observedConfigHash=%q remoteKeyID=%q)",
		gvr.Resource, name, degradedFalse, preflight.Result.Status, preflight.Result.ConfigHash, preflight.ObservedConfigHash, preflight.Result.RemoteKeyID,
		previous.ObservedConfigHash, previous.Result.RemoteKeyID)
}

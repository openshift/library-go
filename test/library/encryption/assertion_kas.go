// Copied from KAS-O test/library/encryption/assertion.go:
// https://github.com/openshift/cluster-kube-apiserver-operator/blob/main/test/library/encryption/assertion.go
package encryption

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1 "github.com/openshift/api/config/v1"
)

var DefaultTargetGRs = []schema.GroupResource{
	{Group: "", Resource: "secrets"},
	{Group: "", Resource: "configmaps"},
}

func AssertSecretOfLifeEncrypted(t testing.TB, clientSet ClientSet, resource runtime.Object) {
	t.Helper()
	secret, ok := resource.(*corev1.Secret)
	if !ok {
		t.Fatalf("expected *corev1.Secret, got %T", resource)
	}
	rawValue := GetRawSecretOfLife(t, clientSet, secret.Namespace)
	if strings.Contains(rawValue, string(secret.Data["quote"])) {
		t.Errorf("secret not encrypted, etcd value contains quote in plain text")
	}
}

func AssertSecretOfLifeNotEncrypted(t testing.TB, clientSet ClientSet, resource runtime.Object) {
	t.Helper()
	secret, ok := resource.(*corev1.Secret)
	if !ok {
		t.Fatalf("expected *corev1.Secret, got %T", resource)
	}
	rawValue := GetRawSecretOfLife(t, clientSet, secret.Namespace)
	if !strings.Contains(rawValue, string(secret.Data["quote"])) {
		t.Errorf("secret not decrypted, etcd value does not contain quote in plain text")
	}
}

func AssertSecretsAndConfigMaps(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
	t.Helper()
	assertSecrets(t, clientSet.Etcd, string(expectedMode))
	assertConfigMaps(t, clientSet.Etcd, string(expectedMode))
	AssertLastMigratedKey(t, clientSet.Kube, DefaultTargetGRs, namespace, labelSelector)
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

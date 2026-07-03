// Copied from KAS-O test/library/encryption/helpers.go:
// https://github.com/openshift/cluster-kube-apiserver-operator/blob/main/test/library/encryption/helpers.go
package encryption

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const secretOfLifeName = "secret-of-life"

func CreateAndStoreSecretOfLife(t testing.TB, clientSet ClientSet, namespace string) runtime.Object {
	t.Helper()
	ctx := context.TODO()

	oldSecret, err := clientSet.Kube.CoreV1().Secrets(namespace).Get(ctx, secretOfLifeName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		t.Fatalf("Failed to check if the secret already exists: %v", err)
	}
	if oldSecret != nil && len(oldSecret.Name) > 0 {
		t.Log("The secret already exists, removing it first")
		require.NoError(t, clientSet.Kube.CoreV1().Secrets(namespace).Delete(ctx, oldSecret.Name, metav1.DeleteOptions{}))
	}

	t.Logf("Creating %q in %s namespace", secretOfLifeName, namespace)
	rawSecret := SecretOfLife(t, namespace)
	secret, err := clientSet.Kube.CoreV1().Secrets(namespace).Create(ctx, rawSecret.(*corev1.Secret), metav1.CreateOptions{})
	require.NoError(t, err)
	return secret
}

func SecretOfLife(_ testing.TB, namespace string) runtime.Object {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretOfLifeName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"quote": []byte("I have no special talents. I am only passionately curious"),
		},
	}
}

func GetRawSecretOfLife(t testing.TB, clientSet ClientSet, namespace string) string {
	t.Helper()
	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	secretOfLifeKey := fmt.Sprintf("/kubernetes.io/secrets/%s/%s", namespace, secretOfLifeName)
	resp, err := clientSet.Etcd.Get(timeout, secretOfLifeKey)
	require.NoError(t, err)
	require.Len(t, resp.Kvs, 1, "expected exactly one key from etcd for secret-of-life")

	return string(resp.Kvs[0].Value)
}

package encryption

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1 "github.com/openshift/api/config/v1"
)

var AuthTargetGRs = []schema.GroupResource{
	{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
	{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
}

func AssertTokenOfLifeEncrypted(t testing.TB, clientSet ClientSet, _ runtime.Object) {
	t.Helper()
	rawTokenValue := GetRawTokenOfLife(t, clientSet)
	marker := "I have no special talents. I am only passionately curious"
	if strings.Contains(rawTokenValue, marker) {
		t.Errorf("access token not encrypted, etcd value contains refresh token marker in plain text")
	}
}

func AssertTokenOfLifeNotEncrypted(t testing.TB, clientSet ClientSet, _ runtime.Object) {
	t.Helper()
	rawTokenValue := GetRawTokenOfLife(t, clientSet)
	marker := "I have no special talents. I am only passionately curious"
	if !strings.Contains(rawTokenValue, marker) {
		t.Errorf("access token not decrypted, etcd value does not contain refresh token marker in plain text")
	}
}

func AssertTokens(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
	t.Helper()
	assertAccessTokens(t, clientSet.Etcd, string(expectedMode))
	assertAuthTokens(t, clientSet.Etcd, string(expectedMode))
	AssertLastMigratedKey(t, clientSet.Kube, AuthTargetGRs, namespace, labelSelector)
}

func assertAccessTokens(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all OauthAccessTokens where encrypted/decrypted for %q mode", expectedMode)
	totalAccessTokens, err := VerifyResources(t, etcdClient, "/openshift.io/oauth/accesstokens/", expectedMode, true)
	t.Logf("Verified %d OauthAccessTokens", totalAccessTokens)
	require.NoError(t, err)
}

func assertAuthTokens(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all OAuthAuthorizeTokens where encrypted/decrypted for %q mode", expectedMode)
	totalAuthTokens, err := VerifyResources(t, etcdClient, "/openshift.io/oauth/authorizetokens/", expectedMode, true)
	t.Logf("Verified %d OAuthAuthorizeTokens", totalAuthTokens)
	require.NoError(t, err)
}

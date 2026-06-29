package encryption

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	oauthapiv1 "github.com/openshift/api/oauth/v1"
)

var oauthAccessTokenGVR = schema.GroupVersionResource{Group: "oauth.openshift.io", Version: "v1", Resource: "oauthaccesstokens"}

const tokenOfLifeName = "sha256~token-aaaaaaaa-of-aaaaaaaa-life-aaaaaaaa"

func CreateAndStoreTokenOfLife(ctx context.Context, t testing.TB, cs ClientSet) runtime.Object {
	t.Helper()
	tokens := cs.DynamicClient.Resource(oauthAccessTokenGVR)

	oldToken, err := tokens.Get(ctx, tokenOfLifeName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		t.Fatalf("Failed to check if the token already exists: %v", err)
	}
	if oldToken != nil && len(oldToken.GetName()) > 0 {
		t.Log("The access token already exists, removing it first")
		require.NoError(t, tokens.Delete(ctx, oldToken.GetName(), metav1.DeleteOptions{}))
	}

	t.Logf("Creating %q at cluster scope level", tokenOfLifeName)
	token := TokenOfLife(t, "")
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(token)
	require.NoError(t, err)

	created, err := tokens.Create(ctx, &unstructured.Unstructured{Object: obj}, metav1.CreateOptions{})
	require.NoError(t, err)

	var result oauthapiv1.OAuthAccessToken
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(created.Object, &result)
	require.NoError(t, err)
	return &result
}

func TokenOfLife(_ testing.TB, _ string) runtime.Object {
	return &oauthapiv1.OAuthAccessToken{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "oauth.openshift.io/v1",
			Kind:       "OAuthAccessToken",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: tokenOfLifeName,
		},
		RefreshToken: "I have no special talents. I am only passionately curious",
		UserName:     "kube:admin",
		Scopes:       []string{"user:full"},
		RedirectURI:  "redirect.me.to.token.of.life",
		ClientName:   "console",
		UserUID:      "non-existing-user-id",
	}
}

func GetRawTokenOfLife(t testing.TB, clientSet ClientSet) string {
	t.Helper()
	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tokenOfLifeKey := fmt.Sprintf("/openshift.io/oauth/accesstokens/%s", tokenOfLifeName)
	resp, err := clientSet.Etcd.Get(timeout, tokenOfLifeKey)
	require.NoError(t, err)
	require.Len(t, resp.Kvs, 1, "expected exactly one key from etcd for token-of-life")

	return string(resp.Kvs[0].Value)
}

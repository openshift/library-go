package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewDryRunSecretsGetter_NilReal(t *testing.T) {
	overlay, err := newDryRunSecretsGetter(nil)
	require.Error(t, err)
	require.Nil(t, overlay)
	require.Contains(t, err.Error(), "non-nil SecretsGetter")
}

func TestDryRunSecretsOverlay_CreateThenGet(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	overlay, err := newDryRunSecretsGetter(fakeClient.CoreV1())
	require.NoError(t, err)

	created, err := overlay.Secrets("ns").Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "ns"},
		Data:       map[string][]byte{"k": []byte("v")},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, "my-secret", created.Name)

	got, err := overlay.Secrets("ns").Get(context.Background(), "my-secret", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []byte("v"), got.Data["k"])

	for _, action := range fakeClient.Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "update" {
			t.Fatalf("live client must not be mutated, got action %#v", action)
		}
	}
}

func TestDryRunSecretsOverlay_GetFallsThrough(t *testing.T) {
	live := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "live-secret", Namespace: "ns"},
		Data:       map[string][]byte{"from": []byte("live")},
	}
	fakeClient := fake.NewSimpleClientset(live)
	overlay, err := newDryRunSecretsGetter(fakeClient.CoreV1())
	require.NoError(t, err)

	got, err := overlay.Secrets("ns").Get(context.Background(), "live-secret", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []byte("live"), got.Data["from"])
}

func TestDryRunSecretsOverlay_ListMergesNewName(t *testing.T) {
	live := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing",
			Namespace: "ns",
			Labels:    map[string]string{"comp": "test"},
		},
	}
	fakeClient := fake.NewSimpleClientset(live)
	overlay, err := newDryRunSecretsGetter(fakeClient.CoreV1())
	require.NoError(t, err)

	_, err = overlay.Secrets("ns").Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-key",
			Namespace: "ns",
			Labels:    map[string]string{"comp": "test"},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	list, err := overlay.Secrets("ns").List(context.Background(), metav1.ListOptions{
		LabelSelector: "comp=test",
	})
	require.NoError(t, err)
	require.Len(t, list.Items, 2)

	names := map[string]bool{}
	for _, s := range list.Items {
		names[s.Name] = true
	}
	require.True(t, names["existing"])
	require.True(t, names["new-key"])
}

func TestDryRunSecretsOverlay_ListReplacesSameName(t *testing.T) {
	live := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared",
			Namespace: "ns",
			Labels:    map[string]string{"comp": "test"},
		},
		Data: map[string][]byte{"v": []byte("live")},
	}
	fakeClient := fake.NewSimpleClientset(live)
	overlay, err := newDryRunSecretsGetter(fakeClient.CoreV1())
	require.NoError(t, err)

	_, err = overlay.Secrets("ns").Update(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared",
			Namespace: "ns",
			Labels:    map[string]string{"comp": "test"},
		},
		Data: map[string][]byte{"v": []byte("overlay")},
	}, metav1.UpdateOptions{})
	require.NoError(t, err)

	list, err := overlay.Secrets("ns").List(context.Background(), metav1.ListOptions{
		LabelSelector: "comp=test",
	})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, "shared", list.Items[0].Name)
	require.Equal(t, []byte("overlay"), list.Items[0].Data["v"])
}

func TestDryRunSecretsOverlay_CreateUsesClientNamespace(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	overlay, err := newDryRunSecretsGetter(fakeClient.CoreV1())
	require.NoError(t, err)

	created, err := overlay.Secrets("ns").Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "other-ns", // mismatched; client namespace must win
		},
		Data: map[string][]byte{"k": []byte("v")},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, "ns", created.Namespace)

	got, err := overlay.Secrets("ns").Get(context.Background(), "my-secret", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, "ns", got.Namespace)
	require.Equal(t, []byte("v"), got.Data["k"])

	_, err = overlay.Secrets("other-ns").Get(context.Background(), "my-secret", metav1.GetOptions{})
	require.Error(t, err, "must not be stored under the object Namespace")

	recorded, ok := overlay.Recorded("ns", "my-secret")
	require.True(t, ok)
	require.Equal(t, "ns", recorded.Namespace)
	_, ok = overlay.Recorded("other-ns", "my-secret")
	require.False(t, ok)
}

func TestDryRunSecretsOverlay_ListDropsWhenLabelsNoLongerMatch(t *testing.T) {
	live := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared",
			Namespace: "ns",
			Labels:    map[string]string{"comp": "test"},
		},
		Data: map[string][]byte{"v": []byte("live")},
	}
	fakeClient := fake.NewSimpleClientset(live)
	overlay, err := newDryRunSecretsGetter(fakeClient.CoreV1())
	require.NoError(t, err)

	_, err = overlay.Secrets("ns").Update(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared",
			Namespace: "ns",
			Labels:    map[string]string{"comp": "other"},
		},
		Data: map[string][]byte{"v": []byte("overlay")},
	}, metav1.UpdateOptions{})
	require.NoError(t, err)

	list, err := overlay.Secrets("ns").List(context.Background(), metav1.ListOptions{
		LabelSelector: "comp=test",
	})
	require.NoError(t, err)
	require.Empty(t, list.Items, "overlay write that demotes labels must remove the live list entry")
}

func TestDryRunSecretsOverlay_MutatorsFailClosed(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	overlay, err := newDryRunSecretsGetter(fakeClient.CoreV1())
	require.NoError(t, err)
	client := overlay.Secrets("ns")
	ctx := context.Background()

	err = client.Delete(ctx, "x", metav1.DeleteOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not support Delete")

	err = client.DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not support DeleteCollection")

	_, err = client.Patch(ctx, "x", types.MergePatchType, []byte("{}"), metav1.PatchOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not support Patch")

	_, err = client.Watch(ctx, metav1.ListOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not support Watch")

	_, err = client.Apply(ctx, nil, metav1.ApplyOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not support Apply")

	for _, action := range fakeClient.Actions() {
		t.Fatalf("live client must not be called for unsupported mutators, got action %#v", action)
	}
}

func TestDryRunSecretsOverlay_Recorded(t *testing.T) {
	live := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "live-only", Namespace: "ns"},
	}
	fakeClient := fake.NewSimpleClientset(live)
	overlay, err := newDryRunSecretsGetter(fakeClient.CoreV1())
	require.NoError(t, err)

	_, ok := overlay.Recorded("ns", "live-only")
	require.False(t, ok, "live-only reads must not appear in recorded writes")

	_, err = overlay.Secrets("ns").Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "written-a", Namespace: "ns"},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = overlay.Secrets("ns").Update(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "written-b", Namespace: "ns"},
		Data:       map[string][]byte{"k": []byte("v")},
	}, metav1.UpdateOptions{})
	require.NoError(t, err)

	gotA, ok := overlay.Recorded("ns", "written-a")
	require.True(t, ok)
	require.Equal(t, "ns", gotA.Namespace)

	gotB, ok := overlay.Recorded("ns", "written-b")
	require.True(t, ok)
	require.Equal(t, []byte("v"), gotB.Data["k"])

	_, ok = overlay.Recorded("ns", "live-only")
	require.False(t, ok, "live-only reads must not appear in recorded writes")

	// Mutating the returned object must not affect the overlay store.
	gotA.Data = map[string][]byte{"mutated": []byte("x")}
	reread, ok := overlay.Recorded("ns", "written-a")
	require.True(t, ok)
	require.NotEqual(t, []byte("x"), reread.Data["mutated"])
}

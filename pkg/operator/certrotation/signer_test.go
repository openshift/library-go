package certrotation

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/operator/events"
)

type getter struct {
	w *wrapped
}

func (g *getter) Secrets(string) corev1client.SecretInterface {
	return g.w
}

type wrapped struct {
	corev1client.SecretInterface
	name string
	t    *testing.T
	// the hooks are not invoked for every operation
	hook func(controllerName, op string)
}

func (w wrapped) Create(ctx context.Context, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error) {
	w.t.Logf("[%s] op=Create, secret=%s/%s", w.name, secret.Namespace, secret.Name)
	return w.SecretInterface.Create(ctx, secret, opts)
}
func (w wrapped) Update(ctx context.Context, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error) {
	w.t.Logf("[%s] op=Update, secret=%s/%s", w.name, secret.Namespace, secret.Name)
	return w.SecretInterface.Update(ctx, secret, opts)
}
func (w wrapped) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	w.t.Logf("[%s] op=Delete, secret=%s", w.name, name)
	defer func() {
		if w.hook != nil {
			w.hook(w.name, operation(w.t, opts))
		}
	}()
	return w.SecretInterface.Delete(ctx, name, opts)
}
func (w wrapped) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	if w.hook != nil {
		w.hook(w.name, operation(w.t, opts))
	}
	obj, err := w.SecretInterface.Get(ctx, name, opts)
	w.t.Logf("[%s] op=Get, secret=%s, err: %v", w.name, name, err)
	return obj, err
}

func operation(t *testing.T, options interface{}) string {
	switch options.(type) {
	case metav1.CreateOptions:
		return "create"
	case metav1.DeleteOptions:
		return "delete"
	case metav1.UpdateOptions:
		return "update"
	case metav1.GetOptions:
		return "get"
	case metav1.PatchOptions:
		return "patch"
	}
	t.Fatalf("wrong test setup: we shouldn't be here for this test")
	return ""
}

func TestEnsureSigningCertKeyPair(t *testing.T) {
	tests := []struct {
		name string

		initialSecret *corev1.Secret

		verifyActions func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool)
		expectedError string
	}{
		{
			name: "initial create",
			verifyActions: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !controllerUpdatedSecret {
					t.Errorf("expected controller to update secret")
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("create", "secrets") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeSigner {
					t.Errorf("expected certificate type 'signer', got: %v", certType)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				if len(actual.Annotations) == 0 {
					t.Errorf("expected certificates to be annotated")
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
		{
			name: "update no annotations",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer", ResourceVersion: "10"},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("update", "secrets") {
					t.Error(actions[1])
				}
				if !controllerUpdatedSecret {
					t.Errorf("expected controller to update secret")
				}

				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeSigner {
					t.Errorf("expected certificate type 'signer', got: %v", certType)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
		{
			name: "update no work",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
						annotations.OpenShiftComponent:             "test",
					},
					OwnerReferences: []metav1.OwnerReference{{
						Name: "operator",
					}},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
				if controllerUpdatedSecret {
					t.Errorf("expected controller to not update secret")
				}
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
		{
			name: "recreate invalid type secrets",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
					}},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"foo": {}, "bar": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				t.Helper()

				actions := client.Actions()
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}

				idx := 2
				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Error(actions[1])
				}
				if !actions[2].Matches("create", "secrets") {
					t.Error(actions[2])
				}
				if controllerUpdatedSecret {
					t.Errorf("expected controller to not update secret")
				}

				actual := actions[idx].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if actual.Type != corev1.SecretTypeTLS {
					t.Errorf("expected secret type to be kubernetes.io/tls, got: %v", actual.Type)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s/update-only", test.name), func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

			client := kubefake.NewSimpleClientset()
			if test.initialSecret != nil {
				indexer.Add(test.initialSecret)
				client = kubefake.NewSimpleClientset(test.initialSecret)
			}

			c := &RotatedSigningCASecret{
				Namespace:     "ns",
				Name:          "signer",
				Validity:      24 * time.Hour,
				Refresh:       12 * time.Hour,
				Client:        client.CoreV1(),
				Lister:        corev1listers.NewSecretLister(indexer),
				EventRecorder: events.NewInMemoryRecorder("test"),
				AdditionalAnnotations: AdditionalAnnotations{
					JiraComponent: "test",
				},
				Owner: &metav1.OwnerReference{
					Name: "operator",
				},
			}

			_, updated, err := c.EnsureSigningCertKeyPair(context.TODO())
			switch {
			case err != nil && len(test.expectedError) == 0:
				t.Error(err)
			case err != nil && !strings.Contains(err.Error(), test.expectedError):
				t.Error(err)
			case err == nil && len(test.expectedError) != 0:
				t.Errorf("missing %q", test.expectedError)
			}

			test.verifyActions(t, client, updated)
		})
	}
}

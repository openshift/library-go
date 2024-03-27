package certrotation

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
)

// loadbalancer-serving-signer secret in openshift-kube-apiserver-operator namespace
// is reconciled by multiple controllers at the same time without any coordination.
// it looks like we have `2` separate processes and `4` different controllers competing over the same resource.
//
// the following unit test demonstrates that the secret crypto material
// can be regenerated, which has serious consequences for the platform
// as it can break external clients and the cluster itself.
//
// controllers reconciling the secret:
//  - https://github.com/openshift/cluster-kube-apiserver-operator/blob/release-4.15/pkg/operator/certrotationcontroller/certrotationcontroller.go#L338
//  - https://github.com/openshift/cluster-kube-apiserver-operator/blob/release-4.15/pkg/operator/certrotationcontroller/certrotationcontroller.go#L392

// processes reconciling the secret:
//   - https://github.com/openshift/cluster-kube-apiserver-operator/blob/63691a0ee938b1b7002777db8464d50791efb94a/pkg/operator/starter.go#L318
//   - https://github.com/openshift/cluster-kube-apiserver-operator/blob/052beea48fdeb9be7cdafe7a5ae2e7c4c74c3a0f/pkg/cmd/certregenerationcontroller/cmd.go#L105
//
// In general, NewCertRotationController react to changes on secrets in
// openshift-kube-apiserver-operator ns (https://github.com/openshift/cluster-kube-apiserver-operator/blob/ae0c9631284bca8cfcbc305674781e097f7238ae/vendor/github.com/openshift/library-go/pkg/operator/certrotation/client_cert_rotation_controller.go#L94)
func TestEnsureSigningCertKeyPairRace(t *testing.T) {
	secondControllerStartChan := make(chan struct{})
	secondControllerEndChan := make(chan struct{})
	firstControllerEndChan := make(chan struct{})

	// represents a secret that was created before 4.7 and
	// hasn't been updated until now (upgrade to 4.15)
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "signer", ResourceVersion: "10",
			Annotations: map[string]string{
				"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
				"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
			},
		},
		Type: "SecretTypeTLS",
		Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
	}
	// add a key pair so that the check
	// (GetCAFromBytes) in the
	// target's method doesn't fail
	if err := setSigningCertKeyPairSecret(existingSecret, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := indexer.Add(existingSecret); err != nil {
		t.Fatal(err)
	}

	fakeKubeClient := kubefake.NewSimpleClientset(existingSecret)
	fakeKubeClient.PrependReactor("delete", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		// the assumption here is that delete operation
		// will be delivered via watch to the second controller
		// which could result in a 404 thus
		// to simulate this scenario
		// the secret si removed from the cache
		if err = indexer.Delete(existingSecret); err != nil {
			return true, nil, err
		}
		close(secondControllerStartChan) // this triggers the second controller
		return false /*means that the next reactor in the chain will be invoked (secret will be deleted)*/, nil, nil
	})
	fakeKubeClient.PrependReactor("get", "secrets", func() clienttesting.ReactionFunc {
		counter := 0
		counterLock := sync.Mutex{}
		return func(action clienttesting.Action) (bool, runtime.Object, error) {
			counterLock.Lock()
			defer counterLock.Unlock()
			defer func() {
				counter++
			}()
			if counter == 0 {
				// this is the call from the first controller
				return false /*means that the next reactor in the chain will be invoked (return the existingSecret)*/, nil, nil
			}
			// this is a call from the second controller
			// wait until the first controller finishes
			// so that we can update the secret with the new keys
			<-firstControllerEndChan
			return false /*means that the next reactor in the chain will be invoked (return re-created secret)*/, nil, nil
		}
	}())

	c := &RotatedSigningCASecret{
		Namespace:     "ns",
		Name:          "signer",
		Validity:      24 * time.Hour,
		Refresh:       12 * time.Hour,
		Client:        fakeKubeClient.CoreV1(),
		Lister:        corev1listers.NewSecretLister(indexer),
		EventRecorder: events.NewInMemoryRecorder("test"),
		AdditionalAnnotations: AdditionalAnnotations{
			JiraComponent: "test",
		},
		Owner: &metav1.OwnerReference{
			Name: "operator",
		},
	}

	var signingKeyPairFromControllerTwo *crypto.CA
	go func() {
		// start the second controller
		var err error
		<-secondControllerStartChan
		signingKeyPairFromControllerTwo, err = c.ensureSigningCertKeyPair(context.TODO())
		if err != nil {
			t.Error(err)
		}
		close(secondControllerEndChan)
	}()

	// start the first controller
	signingKeyPairFromControllerOne, err := c.ensureSigningCertKeyPair(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	certBytesFromControllerOne, keyBytesFromControllerOne, err := signingKeyPairFromControllerOne.Config.GetPEMBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(existingSecret.Data["tls.crt"], certBytesFromControllerOne) {
		t.Fatal("returned certificate data from controller one doesn't match existing secreted data")
	}
	if !bytes.Equal(existingSecret.Data["tls.key"], keyBytesFromControllerOne) {
		t.Fatal("returned certificate key from controller one doesn't match existing secreted data")
	}
	close(firstControllerEndChan)
	<-secondControllerEndChan

	certBytesFromControllerTwo, keyBytesFromControllerTwo, err := signingKeyPairFromControllerTwo.Config.GetPEMBytes()
	if err != nil {
		t.Fatal(err)
	}
	// note that GetTLSCertificateConfigFromBytes (executed by the target method) check if
	// the crypto material is not empty
	//
	// the following 2 checks show that the second controller
	// created a new signing key pair!
	if !bytes.Equal(certBytesFromControllerOne, certBytesFromControllerTwo) {
		t.Errorf("cert data from both controllers are NOT equal")
	}
	if !bytes.Equal(keyBytesFromControllerOne, keyBytesFromControllerTwo) {
		t.Errorf("cert key from both controllers are NOT equal")
	}

	actions := fakeKubeClient.Actions()
	updateActionValidated := false
	createActionValidated := false
	for _, action := range actions {
		switch action.GetVerb() {
		case "create":
			if createAction, ok := action.(clienttesting.CreateAction); ok {
				createdSecret, _ := createAction.GetObject().(*corev1.Secret)
				existingSecretCpy := existingSecret.DeepCopy()
				existingSecretCpy.ResourceVersion = ""
				existingSecretCpy.Type = createdSecret.Type
				existingSecretCpy.Annotations["openshift.io/owning-component"] = "test"
				if !!apiequality.Semantic.DeepEqual(createdSecret, existingSecretCpy) {
					t.Fatal("unexpected secret was created")
				}
				createActionValidated = true
			}
		case "update":
			if updateAction, ok := action.(clienttesting.UpdateAction); ok {
				updatedSecret, _ := updateAction.GetObject().(*corev1.Secret)
				if reflect.DeepEqual(updatedSecret.Data, existingSecret.Data) {
					t.Fatal("updated object has the same data as existing one")
				}
				updateActionValidated = true
			}
		}
	}
	if !updateActionValidated {
		t.Fatal("update action wasn't validated")
	}
	if !createActionValidated {
		t.Fatal("create action wasn't validated")
	}
}

func TestEnsureSigningCertKeyPair(t *testing.T) {
	tests := []struct {
		name string

		initialSecret *corev1.Secret

		verifyActions func(t *testing.T, client *kubefake.Clientset)
		expectedError string
	}{
		{
			name: "initial create",
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
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
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
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
					}},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
		{
			name: "update SecretTLSType secrets",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
					}},
				Type: "SecretTypeTLS",
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Error(actions[1])
				}
				if !actions[2].Matches("create", "secrets") {
					t.Error(actions[2])
				}
				actual := actions[2].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if actual.Type != corev1.SecretTypeTLS {
					t.Errorf("expected secret type to be kubernetes.io/tls, got: %v", actual.Type)
				}
				cert, found := actual.Data["tls.crt"]
				if !found {
					t.Errorf("expected to have tls.crt key")
				}
				if len(cert) != 0 {
					t.Errorf("expected tls.crt to be empty, got %v", cert)
				}
				key, found := actual.Data["tls.key"]
				if !found {
					t.Errorf("expected to have tls.key key")
				}
				if len(key) != 0 {
					t.Errorf("expected tls.key to be empty, got %v", key)
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
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Error(actions[1])
				}
				if !actions[2].Matches("create", "secrets") {
					t.Error(actions[2])
				}
				actual := actions[2].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
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
		t.Run(test.name, func(t *testing.T) {
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

			_, err := c.ensureSigningCertKeyPair(context.TODO())
			switch {
			case err != nil && len(test.expectedError) == 0:
				t.Error(err)
			case err != nil && !strings.Contains(err.Error(), test.expectedError):
				t.Error(err)
			case err == nil && len(test.expectedError) != 0:
				t.Errorf("missing %q", test.expectedError)
			}

			test.verifyActions(t, client)
		})
	}
}

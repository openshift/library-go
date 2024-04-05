package certrotation

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestRotatedSigningCASecretShouldNotUseDelete(t *testing.T) {
	ns, name := "ns", "test-signer"
	// represents a secret that was created before 4.7 and
	// hasn't been updated until now (upgrade to 4.15)
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       ns,
			Name:            name,
			ResourceVersion: "10",
		},
		Type: "SecretTypeTLS",
		Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
	}
	// not-after and not-before annotations are filled when new signer is generated
	if err := setSigningCertKeyPairSecret(existing, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	// give it a second so we have a unique signer name,
	// and also unique not-after, and not-before values
	<-time.After(2 * time.Second)

	// get the original crt and key bytes to compare later
	tlsCertWant, ok := existing.Data["tls.crt"]
	if !ok || len(tlsCertWant) == 0 {
		t.Fatalf("missing data in 'tls.crt' key of Data: %#v", existing.Data)
	}
	tlsKeyWant, ok := existing.Data["tls.key"]
	if !ok || len(tlsKeyWant) == 0 {
		t.Fatalf("missing data in 'tls.key' key of Data: %#v", existing.Data)
	}

	// copy the existing object before test begins, so we can diff it against
	// the final object on the cluster after the controllers finish
	secretWant := existing.DeepCopy()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	syncCacheFn := func(t *testing.T, obj runtime.Object) {
		switch {
		case obj == nil:
			if err := indexer.Delete(existing); err != nil {
				t.Fatalf("unexpected error while syncing the cache, op=delete: %v", err)
			}
		default:
			indexer.Delete(obj)
			if err := indexer.Add(obj); err != nil {
				t.Fatalf("unexpected error while syncing the cache: %v", err)
			}
		}
	}
	syncCacheFn(t, existing)
	clientset := kubefake.NewSimpleClientset(existing)

	// the list cache is synced as soon as we have a delete, create, or update
	clientset.PrependReactor("delete", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		syncCacheFn(t, nil)
		return false, nil, nil
	})
	clientset.PrependReactor("create", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		switch action := action.(type) {
		case clienttesting.CreateActionImpl:
			syncCacheFn(t, action.GetObject())
			return false, action.GetObject(), nil
		}
		t.Fatalf("wrong test setup, expected an action object of %T", clienttesting.CreateActionImpl{})
		return false, nil, nil
	})
	clientset.PrependReactor("update", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		switch action := action.(type) {
		case clienttesting.UpdateActionImpl:
			syncCacheFn(t, action.GetObject())
			return false, action.GetObject(), nil
		}
		t.Fatalf("wrong test setup, expected an action object of %T", clienttesting.UpdateActionImpl{})
		return false, nil, nil
	})

	options := events.RecommendedClusterSingletonCorrelatorOptions()
	client := clientset.CoreV1().Secrets(ns)
	newControllerFn := func(ctrlName string, wrapped *secretwrapped) *RotatedSigningCASecret {
		recorder := events.NewKubeRecorderWithOptions(clientset.CoreV1().Events(ns), options, "operator", &corev1.ObjectReference{Name: ctrlName, Namespace: ns})
		return &RotatedSigningCASecret{
			Namespace:             ns,
			Name:                  name,
			Validity:              24 * time.Hour,
			Refresh:               12 * time.Hour,
			Client:                &secretgetter{w: wrapped},
			Lister:                corev1listers.NewSecretLister(indexer),
			AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
			Owner:                 &metav1.OwnerReference{Name: "operator"},
			EventRecorder:         recorder,
			UseSecretUpdateOnly:   true,
		}
	}

	// we have two controllers, running cncurrently, A and B
	// a) A starts
	// b) A detects secret type mismatch, it proceeds to do delete + create
	// c) A completes delete operation, we make A stop here, and let B start
	// d) B sees a NotFound error (from the list cache), constructs an in-memory
	//    secret object, creates a new signer, and then invokes ApplySecret
	// e) let's make B pause just before it is about to invoke a GET
	// f) let A resume and finish
	// g) let B resume
	// h) B proceeds with the GET operation, the secret object on the cluster
	//    has a signer that does not match
	// i) B updates the secret with the signer from 'd'
	ctrlAPauses, ctrlBStart, ctrlBPauses := make(chan struct{}), make(chan struct{}), make(chan struct{})
	hookA := func(name, op string) {
		switch {
		case name == "controller-A" && op == "delete":
			// step 'c' has completed, B can strat, and A should block
			close(ctrlBStart)
			<-ctrlAPauses
		}
	}
	hookB := func(name, op string) {
		switch {
		case name == "controller-B" && op == "get":
			// step 'e': B is about to GET the secret, A should resume, and B should pause
			close(ctrlAPauses)
			<-ctrlBPauses
		}
	}
	wrappedA := &secretwrapped{SecretInterface: client, name: "controller-A", t: t, hook: hookA}
	ctrlA := newControllerFn("controller-A", wrappedA)
	wrappedB := &secretwrapped{SecretInterface: client, name: "controller-B", t: t, hook: hookB}
	ctrlB := newControllerFn("controller-B", wrappedB)

	ctrlADone, ctrlBDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(ctrlADone)
		defer close(ctrlBPauses)
		// step 'a': A starts first
		_, _, err := ctrlA.EnsureSigningCertKeyPair(context.TODO())
		if err != nil {
			t.Logf("error from controller-A - %v", err)
		}
	}()
	go func() {
		defer close(ctrlBDone)
		// wait until step 'c' completes
		<-ctrlBStart
		_, _, err := ctrlB.EnsureSigningCertKeyPair(context.TODO())
		if err != nil {
			t.Logf("error from controller-B - %v", err)
		}
	}()

	<-ctrlADone
	select {
	case <-ctrlBStart:
	default:
		// controller A did not exercise delete + create, make
		// sure the test does not block
		close(ctrlBStart)
	}
	<-ctrlBDone

	// controllers are done, we don't expect the signer to change
	secretGot, err := client.Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCertGot, ok := secretGot.Data["tls.crt"]; !ok || !bytes.Equal(tlsCertWant, tlsCertGot) {
		t.Errorf("the signer cert has mutated unexpectedly")
	}
	if tlsKeyGot, ok := secretGot.Data["tls.key"]; !ok || !bytes.Equal(tlsKeyWant, tlsKeyGot) {
		t.Errorf("the signer key has mutated unexpectedly")
	}
	if got, exists := secretGot.Annotations["openshift.io/owning-component"]; !exists || got != "test" {
		t.Errorf("owner annotation is missing: %#v", secretGot.Annotations)
	}
	if secretGot.Type != corev1.SecretTypeTLS {
		t.Errorf("expected the secret type to be: %q, but got: %q", corev1.SecretTypeTLS, secretGot.Type)
	}

	t.Logf("diff: %s", cmp.Diff(secretWant, secretGot))
}

type secretgetter struct {
	w *secretwrapped
}

func (g *secretgetter) Secrets(string) corev1client.SecretInterface {
	return g.w
}

type secretwrapped struct {
	corev1client.SecretInterface
	d    *dispatcher
	name string
	t    *testing.T
	// the hooks are not invoked for every operation
	hook func(controllerName, op string)
}

func (w secretwrapped) Create(ctx context.Context, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error) {
	w.t.Logf("[%s] op=Create, secret=%s/%s", w.name, secret.Namespace, secret.Name)
	return w.SecretInterface.Create(ctx, secret, opts)
}
func (w secretwrapped) Update(ctx context.Context, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error) {
	w.t.Logf("[%s] op=Update, secret=%s/%s", w.name, secret.Namespace, secret.Name)
	return w.SecretInterface.Update(ctx, secret, opts)
}
func (w secretwrapped) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	w.t.Logf("[%s] op=Delete, secret=%s", w.name, name)
	defer func() {
		if w.hook != nil {
			w.hook(w.name, operation(w.t, opts))
		}
	}()
	return w.SecretInterface.Delete(ctx, name, opts)
}
func (w secretwrapped) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
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
		return "get"
	}
	t.Fatalf("wrong test setup: we shouldn't be here for this test")
	return ""
}

func TestEnsureSigningCertKeyPair(t *testing.T) {
	tests := []struct {
		name string

		initialSecret *corev1.Secret

		verifyActions func(t *testing.T, updateOnly bool, client *kubefake.Clientset, controllerUpdatedSecret bool)
		expectedError string
	}{
		{
			name: "initial create",
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset, controllerUpdatedSecret bool) {
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
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset, controllerUpdatedSecret bool) {
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
					}},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset, controllerUpdatedSecret bool) {
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
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				t.Helper()
				lengthWant := 3
				if updateOnly {
					lengthWant = 2
				}

				actions := client.Actions()
				if len(actions) != lengthWant {
					t.Fatal(spew.Sdump(actions))
				}

				var idx int
				switch updateOnly {
				case true:
					idx = 1
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("update", "secrets") {
						t.Error(actions[1])
					}
				default:
					idx = 2
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("delete", "secrets") {
						t.Error(actions[1])
					}
					if !actions[2].Matches("create", "secrets") {
						t.Error(actions[2])
					}
				}
				actual := actions[idx].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
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
			verifyActions: func(t *testing.T, updateOnly bool, client *kubefake.Clientset, controllerUpdatedSecret bool) {
				t.Helper()
				lengthWant := 3
				if updateOnly {
					lengthWant = 2
				}

				actions := client.Actions()
				if len(actions) != lengthWant {
					t.Fatal(spew.Sdump(actions))
				}

				var idx int
				switch updateOnly {
				case true:
					idx = 1
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("update", "secrets") {
						t.Error(actions[1])
					}
				default:
					idx = 2
					if !actions[0].Matches("get", "secrets") {
						t.Error(actions[0])
					}
					if !actions[1].Matches("delete", "secrets") {
						t.Error(actions[1])
					}
					if !actions[2].Matches("create", "secrets") {
						t.Error(actions[2])
					}
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

	for _, b := range []bool{true, false} {
		for _, test := range tests {
			t.Run(fmt.Sprintf("%s/update-only/%t", test.name, b), func(t *testing.T) {
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
					UseSecretUpdateOnly: b,
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

				test.verifyActions(t, b, client, updated)
			})
		}
	}
}

type dispatcher struct {
	t        *testing.T
	choices  []byte
	requests chan request
}

type request struct {
	who  string
	what string
	when chan<- struct{}
}

func (d *dispatcher) Sequence(who, what string) {
	signal := make(chan struct{})
	d.requests <- request{
		who:  who,
		what: what,
		when: signal,
	}
	<-signal
}

func (d *dispatcher) Join(who string) {
	signal := make(chan struct{})
	d.requests <- request{
		who:  who,
		what: "JOIN",
		when: signal,
	}
}

func (d *dispatcher) Leave(who string) {
	signal := make(chan struct{})
	d.requests <- request{
		who:  who,
		what: "LEAVE",
		when: signal,
	}
}

func (d *dispatcher) Stop() {
	close(d.requests)
}

func (d *dispatcher) Run() {
	members := make(map[string]struct{})
	var waiting []request
	choices := d.choices

	dispatch := func() {
		slices.SortFunc(waiting, func(a, b request) int {
			if a.who == b.who {
				panic(fmt.Sprintf("two concurrent requests from same actor %q", a.who))
			}
			if a.who < b.who {
				return -1
			}
			return 1
		})
		d.t.Logf("queue %v", waiting)
		if len(choices) == 0 {
			choices = d.choices
		}
		choice := int(choices[0])
		if choice > len(waiting)-1 {
			choice = choice % len(waiting)
		}
		d.t.Logf("choice %v", choice)

		var w request
		var newWaiting []request
		for i, v := range waiting {
			if i == choice {
				w = v
			} else {
				newWaiting = append(newWaiting, v)
			}
		}
		d.t.Logf("w %v", w)

		choices = choices[1:]
		waiting = newWaiting
		d.t.Logf("new queue %v", waiting)
		d.t.Logf("dispatching %q by %q", w.what, w.who)
		close(w.when)
	}

	for r := range d.requests {
		switch r.what {
		case "JOIN":
			if _, ok := members[r.who]; ok {
				d.t.Fatalf("double join by actor %q", r.who)
			}
			members[r.who] = struct{}{}
			d.t.Logf("%q joined", r.who)
		case "LEAVE":
			if _, ok := members[r.who]; !ok {
				d.t.Fatalf("double leave by actor %q", r.who)
			}
			delete(members, r.who)
			d.t.Logf("%q left", r.who)
		default:
			waiting = append(waiting, r)
		}

		for len(waiting) > 0 && len(waiting) >= len(members) && len(d.choices) > 0 {
			dispatch()
		}
	}

	for range waiting {
		dispatch()
	}
}

type fakeSecretLister struct {
	who        string
	dispatcher *dispatcher
	tracker    clienttesting.ObjectTracker
}

func (l *fakeSecretLister) List(selector labels.Selector) (ret []*corev1.Secret, err error) {
	return l.Secrets("").List(selector)
}

func (l *fakeSecretLister) Secrets(namespace string) corev1listers.SecretNamespaceLister {
	return &fakeSecretNamespaceLister{
		who:        l.who,
		dispatcher: l.dispatcher,
		tracker:    l.tracker,
		ns:         namespace,
	}
}

type fakeSecretNamespaceLister struct {
	who        string
	dispatcher *dispatcher
	tracker    clienttesting.ObjectTracker
	ns         string
}

func (l *fakeSecretNamespaceLister) List(selector labels.Selector) (ret []*corev1.Secret, err error) {
	obj, err := l.tracker.List(
		schema.GroupVersionResource{Version: "v1", Resource: "secrets"},
		schema.GroupVersionKind{Version: "v1", Kind: "Secret"},
		l.ns,
	)
	var secrets []*corev1.Secret
	if l, ok := obj.(*corev1.SecretList); ok {
		for i := range l.Items {
			secrets = append(secrets, &l.Items[i])
		}
	}
	return secrets, err
}

func (l *fakeSecretNamespaceLister) Get(name string) (*corev1.Secret, error) {
	l.dispatcher.Sequence(l.who, "before-lister-get")
	obj, err := l.tracker.Get(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}, l.ns, name)
	l.dispatcher.Sequence(l.who, "after-lister-get")
	if secret, ok := obj.(*corev1.Secret); ok {
		return secret, err
	}
	return nil, err
}

func FuzzEnsureSigningCertKeyPair(f *testing.F) {
	const (
		SecretNamespace, SecretName = "ns", "test-signer"
	)
	// represents a secret that was created before 4.7 and
	// hasn't been updated until now (upgrade to 4.15)
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       SecretNamespace,
			Name:            SecretName,
			ResourceVersion: "10",
		},
		Type: "SecretTypeTLS",
		Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
	}
	if err := setSigningCertKeyPairSecret(existing, 24*time.Hour); err != nil {
		f.Fatal(err)
	}

	for workers := 1; workers <= 3; workers++ {
		for _, b := range []bool{true, false} {
			for _, choices := range [][]byte{{1, 2, 3}, {2, 1, 3}, {3, 2, 1}} {
				f.Add(choices, b, workers)
			}
		}
	}

	f.Fuzz(func(t *testing.T, choices []byte, useSecretUpdateOnly bool, workers int) {
		if len(choices) == 0 {
			t.Skip()
		}
		if workers < 1 || workers > 10 {
			t.Skip()
		}
		t.Logf("choices: %v, useSecretUpdateOnly: %v, workers: %d", choices, useSecretUpdateOnly, workers)
		d := &dispatcher{
			t:        t,
			choices:  choices,
			requests: make(chan request, workers),
		}
		go d.Run()
		defer d.Stop()

		existing = existing.DeepCopy()

		// get the original crt and key bytes to compare later
		tlsCertWant, ok := existing.Data["tls.crt"]
		if !ok || len(tlsCertWant) == 0 {
			t.Fatalf("missing data in 'tls.crt' key of Data: %#v", existing.Data)
		}
		tlsKeyWant, ok := existing.Data["tls.key"]
		if !ok || len(tlsKeyWant) == 0 {
			t.Fatalf("missing data in 'tls.key' key of Data: %#v", existing.Data)
		}

		secretWant := existing.DeepCopy()

		clientset := kubefake.NewSimpleClientset(existing)

		options := events.RecommendedClusterSingletonCorrelatorOptions()
		client := clientset.CoreV1().Secrets(SecretNamespace)

		var wg sync.WaitGroup
		for i := 1; i <= workers; i++ {
			controllerName := fmt.Sprintf("controller-%d", i)
			wg.Add(1)
			d.Join(controllerName)

			go func(controllerName string) {
				defer func() {
					d.Leave(controllerName)
					wg.Done()
				}()

				recorder := events.NewKubeRecorderWithOptions(clientset.CoreV1().Events(SecretNamespace), options, "operator", &corev1.ObjectReference{Name: controllerName, Namespace: SecretNamespace})
				wrapped := &secretwrapped{SecretInterface: client, name: controllerName, t: t, d: d}
				getter := &secretgetter{w: wrapped}
				ctrl := &RotatedSigningCASecret{
					Namespace: SecretNamespace,
					Name:      SecretName,
					Validity:  24 * time.Hour,
					Refresh:   12 * time.Hour,
					Client:    getter,
					Lister: &fakeSecretLister{
						who:        controllerName,
						dispatcher: d,
						tracker:    clientset.Tracker(),
					},
					AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
					Owner:                 &metav1.OwnerReference{Name: "operator"},
					EventRecorder:         recorder,
					UseSecretUpdateOnly:   useSecretUpdateOnly,
				}

				d.Sequence(controllerName, "begin")
				_, _, err := ctrl.EnsureSigningCertKeyPair(context.TODO())
				if err != nil {
					t.Logf("error from %s: %v", controllerName, err)
				}
			}(controllerName)
		}

		wg.Wait()
		t.Log("controllers done")
		// controllers are done, we don't expect the signer to change
		secretGot, err := client.Get(context.TODO(), SecretName, metav1.GetOptions{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if tlsCertGot, ok := secretGot.Data["tls.crt"]; !ok || !bytes.Equal(tlsCertWant, tlsCertGot) {
			t.Errorf("the signer cert has mutated unexpectedly")
		}
		if tlsKeyGot, ok := secretGot.Data["tls.key"]; !ok || !bytes.Equal(tlsKeyWant, tlsKeyGot) {
			t.Errorf("the signer cert has mutated unexpectedly")
		}
		if got, exists := secretGot.Annotations["openshift.io/owning-component"]; !exists || got != "test" {
			t.Errorf("owner annotation is missing: %#v", secretGot.Annotations)
		}
		t.Logf("diff: %s", cmp.Diff(secretWant, secretGot))
	})
}

package certrotation

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
)

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
	w.d.Sequence(w.name, fmt.Sprintf("create-%s", secret.Name))
	w.t.Logf("[%s] op=Create, secret=%s/%s", w.name, secret.Namespace, secret.Name)
	return w.SecretInterface.Create(ctx, secret, opts)
}
func (w secretwrapped) Update(ctx context.Context, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error) {
	w.d.Sequence(w.name, fmt.Sprintf("update-%s", secret.Name))
	w.t.Logf("[%s] op=Update, secret=%s/%s", w.name, secret.Namespace, secret.Name)
	return w.SecretInterface.Update(ctx, secret, opts)
}
func (w secretwrapped) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	w.d.Sequence(w.name, fmt.Sprintf("delete-%s", name))
	defer func() {
		if w.hook != nil {
			w.hook(w.name, operation(w.t, opts))
		}
	}()
	w.t.Logf("[%s] op=Delete, secret=%s", w.name, name)
	return w.SecretInterface.Delete(ctx, name, opts)
}
func (w secretwrapped) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	w.d.Sequence(w.name, fmt.Sprintf("get-%s", name))
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
	if d.requests == nil {
		return
	}
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
		if len(choices) == 0 {
			choices = d.choices
		}
		choice := int(choices[0])
		if choice > len(waiting)-1 {
			choice = choice % len(waiting)
		}

		var w request
		var newWaiting []request
		for i, v := range waiting {
			if i == choice {
				w = v
			} else {
				newWaiting = append(newWaiting, v)
			}
		}
		choices = choices[1:]
		waiting = newWaiting
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

func prepareSigningSecret(f *testing.F, secretNamespace, secretName string) *corev1.Secret {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       secretNamespace,
			Name:            secretName,
			ResourceVersion: "10",
		},
		Type: "SecretTypeTLS",
		Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
	}
	if err := setSigningCertKeyPairSecret(existing, 24*time.Hour); err != nil {
		f.Fatal(err)
	}
	// get the original crt and key bytes to compare later
	tlsCertWant, ok := existing.Data["tls.crt"]
	if !ok || len(tlsCertWant) == 0 {
		f.Fatalf("missing data in 'tls.crt' key of Data: %#v", existing.Data)
	}
	tlsKeyWant, ok := existing.Data["tls.key"]
	if !ok || len(tlsKeyWant) == 0 {
		f.Fatalf("missing data in 'tls.key' key of Data: %#v", existing.Data)
	}
	return existing
}

func prepareSecretController(t *testing.T, secretNamespace, secretName string, controllerName string, getter *secretgetter, d *dispatcher, tracker *clienttesting.ObjectTracker, recorder *events.Recorder) {
	ctrl := &RotatedSigningCASecret{
		Namespace: secretNamespace,
		Name:      secretName,
		Validity:  24 * time.Hour,
		Refresh:   12 * time.Hour,
		Client:    getter,
		Lister: &fakeSecretLister{
			who:        controllerName,
			dispatcher: d,
			tracker:    *tracker,
		},
		AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
		Owner:                 &metav1.OwnerReference{Name: "operator"},
		EventRecorder:         *recorder,
		UseSecretUpdateOnly:   false,
	}

	d.Sequence(controllerName, "begin")
	_, _, err := ctrl.EnsureSigningCertKeyPair(context.TODO())
	if err != nil {
		t.Logf("error from %s: %v", controllerName, err)
	}
}

func prepareSecretControllerUseSecretUpdateOnly(t *testing.T, secretNamespace, secretName string, controllerName string, getter *secretgetter, d *dispatcher, tracker *clienttesting.ObjectTracker, recorder *events.Recorder) {
	ctrl := &RotatedSigningCASecret{
		Namespace: secretNamespace,
		Name:      secretName,
		Validity:  24 * time.Hour,
		Refresh:   12 * time.Hour,
		Client:    getter,
		Lister: &fakeSecretLister{
			who:        controllerName,
			dispatcher: d,
			tracker:    *tracker,
		},
		AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
		Owner:                 &metav1.OwnerReference{Name: "operator"},
		EventRecorder:         *recorder,
		UseSecretUpdateOnly:   true,
	}

	d.Sequence(controllerName, "begin")
	_, _, err := ctrl.EnsureSigningCertKeyPair(context.TODO())
	if err != nil {
		t.Logf("error from %s: %v", controllerName, err)
	}
}

type SecretControllerFuzzer struct {
	name                        string
	secretNamespace, secretName string
	prepareSecretFn             func(f *testing.F, secretNamespace, secretName string) *corev1.Secret
	prepareSecretControllerFn   func(t *testing.T, secretNamespace, secretName string, controllerName string, getter *secretgetter, d *dispatcher, tracker *clienttesting.ObjectTracker, recorder *events.Recorder)
	verifySecretFn              func(t *testing.T, secretWant, secretGot *corev1.Secret)
}

func NewSecretControllerFuzzer(name string) SecretControllerFuzzer {
	return SecretControllerFuzzer{
		name:            name,
		secretNamespace: "ns",
		secretName:      "test-secret",
	}
}

func (c SecretControllerFuzzer) Run(f *testing.F) {
	existing := c.prepareSecretFn(f, c.secretNamespace, c.secretName)
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, choices []byte) {
		if len(choices) == 0 || len(choices) > 10 {
			t.Skip()
		}
		workers := len(choices)
		t.Logf("choices: %v, workers: %d", choices, workers)
		d := &dispatcher{
			t:        t,
			choices:  choices,
			requests: make(chan request, workers),
		}
		go d.Run()
		defer d.Stop()

		secretWant := existing.DeepCopy()

		clientset := kubefake.NewSimpleClientset(existing)
		options := events.RecommendedClusterSingletonCorrelatorOptions()
		client := clientset.CoreV1().Secrets(c.secretNamespace)

		var wg sync.WaitGroup
		for i := 1; i <= workers; i++ {
			controllerName := fmt.Sprintf("controller-fuzz-%d", i)
			wg.Add(1)
			d.Join(controllerName)

			go func(controllerName string) {
				defer func() {
					d.Leave(controllerName)
					wg.Done()
				}()

				recorder := events.NewKubeRecorderWithOptions(clientset.CoreV1().Events(c.secretNamespace), options, "operator", &corev1.ObjectReference{Name: controllerName, Namespace: c.secretNamespace})
				wrapped := &secretwrapped{SecretInterface: client, name: controllerName, t: t, d: d}
				getter := &secretgetter{w: wrapped}
				tracker := clientset.Tracker()
				c.prepareSecretControllerFn(t, c.secretNamespace, c.secretName, controllerName, getter, d, &tracker, &recorder)
			}(controllerName)
		}

		wg.Wait()
		t.Log("controllers done")
		// controllers are done, we don't expect the signer to change
		secretGot, err := client.Get(context.TODO(), c.secretName, metav1.GetOptions{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		c.verifySecretFn(t, secretWant, secretGot)
	})
}

func verifySecret(t *testing.T, secretWant, secretGot *corev1.Secret) {
	tlsCertWant, ok := secretWant.Data["tls.crt"]
	if !ok || len(tlsCertWant) == 0 {
		t.Fatalf("missing data in 'tls.crt' key of Data: %#v", secretWant.Data)
	}
	tlsKeyWant, ok := secretWant.Data["tls.key"]
	if !ok || len(tlsKeyWant) == 0 {
		t.Fatalf("missing data in 'tls.key' key of Data: %#v", secretWant.Data)
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
	if secretGot.Type == "SecretTypeTLS" {
		t.Errorf("secret type was not updated: %#v", secretGot.Type)
	}
	t.Logf("diff: %s", cmp.Diff(secretWant, secretGot))
}

// func FuzzRotatedSigningCASecretDefault(f *testing.F) {
// 	c := NewSecretControllerFuzzer("RotatedSigningCASecret")
// 	c.prepareSecretFn = func(f *testing.F, secretNamespace, secretName string) *corev1.Secret {
// 		existing := &corev1.Secret{
// 			ObjectMeta: metav1.ObjectMeta{
// 				Namespace:       secretNamespace,
// 				Name:            secretName,
// 				ResourceVersion: "10",
// 			},
// 			Type: "SecretTypeTLS",
// 			Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
// 		}
// 		if err := setSigningCertKeyPairSecret(existing, 24*time.Hour); err != nil {
// 			f.Fatal(err)
// 		}
// 		// ensure the secret has been processed initially
// 		tlsCertWant, ok := existing.Data["tls.crt"]
// 		if !ok || len(tlsCertWant) == 0 {
// 			f.Fatalf("missing data in 'tls.crt' key of Data: %#v", existing.Data)
// 		}
// 		tlsKeyWant, ok := existing.Data["tls.key"]
// 		if !ok || len(tlsKeyWant) == 0 {
// 			f.Fatalf("missing data in 'tls.key' key of Data: %#v", existing.Data)
// 		}
// 		return existing
// 	}
// 	c.prepareSecretControllerFn = prepareSecretController
// 	c.verifySecretFn = verifySecret
// 	c.Run(f)
// }

func FuzzRotatedSigningCASecretUseSecretUpdateOnly(f *testing.F) {
	c := NewSecretControllerFuzzer("RotatedSigningCASecretUseSecretUpdateOnly")
	c.prepareSecretFn = func(f *testing.F, secretNamespace, secretName string) *corev1.Secret {
		existing := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       secretNamespace,
				Name:            secretName,
				ResourceVersion: "10",
			},
			Type: "SecretTypeTLS",
			Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
		}
		if err := setSigningCertKeyPairSecret(existing, 24*time.Hour); err != nil {
			f.Fatal(err)
		}
		// ensure the secret has been processed initially
		tlsCertWant, ok := existing.Data["tls.crt"]
		if !ok || len(tlsCertWant) == 0 {
			f.Fatalf("missing data in 'tls.crt' key of Data: %#v", existing.Data)
		}
		tlsKeyWant, ok := existing.Data["tls.key"]
		if !ok || len(tlsKeyWant) == 0 {
			f.Fatalf("missing data in 'tls.key' key of Data: %#v", existing.Data)
		}
		return existing
	}
	c.prepareSecretControllerFn = func(t *testing.T, secretNamespace, secretName string, controllerName string, getter *secretgetter, d *dispatcher, tracker *clienttesting.ObjectTracker, recorder *events.Recorder) {
		ctrl := &RotatedSigningCASecret{
			Namespace: secretNamespace,
			Name:      secretName,
			Validity:  24 * time.Hour,
			Refresh:   12 * time.Hour,
			Client:    getter,
			Lister: &fakeSecretLister{
				who:        controllerName,
				dispatcher: d,
				tracker:    *tracker,
			},
			AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
			Owner:                 &metav1.OwnerReference{Name: "operator"},
			EventRecorder:         *recorder,
			UseSecretUpdateOnly:   true,
		}

		d.Sequence(controllerName, "begin")
		_, _, err := ctrl.EnsureSigningCertKeyPair(context.TODO())
		if err != nil {
			t.Logf("error from %s: %v", controllerName, err)
		}
	}
	c.verifySecretFn = verifySecret
	c.Run(f)
}

func FuzzRotatedTargetSecretUseSecretUpdateOnly(f *testing.F) {
	c := NewSecretControllerFuzzer("FuzzRotatedTargetSecretUseSecretUpdateOnly")
	c.prepareSecretFn = func(f *testing.F, secretNamespace, secretName string) *corev1.Secret {
		existing := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       secretNamespace,
				Name:            secretName,
				ResourceVersion: "10",
			},
			Type: "SecretTypeTLS",
			Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
		}
		if err := setSigningCertKeyPairSecret(existing, 24*time.Hour); err != nil {
			f.Fatal(err)
		}
		// ensure the secret has been processed initially
		tlsCertWant, ok := existing.Data["tls.crt"]
		if !ok || len(tlsCertWant) == 0 {
			f.Fatalf("missing data in 'tls.crt' key of Data: %#v", existing.Data)
		}
		tlsKeyWant, ok := existing.Data["tls.key"]
		if !ok || len(tlsKeyWant) == 0 {
			f.Fatalf("missing data in 'tls.key' key of Data: %#v", existing.Data)
		}
		return existing
	}
	c.prepareSecretControllerFn = func(t *testing.T, secretNamespace, secretName string, controllerName string, getter *secretgetter, d *dispatcher, tracker *clienttesting.ObjectTracker, recorder *events.Recorder) {
		ctrl := &RotatedSigningCASecret{
			Namespace: secretNamespace,
			Name:      secretName,
			Validity:  24 * time.Hour,
			Refresh:   12 * time.Hour,
			Client:    getter,
			Lister: &fakeSecretLister{
				who:        controllerName,
				dispatcher: d,
				tracker:    *tracker,
			},
			AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
			Owner:                 &metav1.OwnerReference{Name: "operator"},
			EventRecorder:         *recorder,
			UseSecretUpdateOnly:   true,
		}

		d.Sequence(controllerName, "begin")
		_, _, err := ctrl.EnsureSigningCertKeyPair(context.TODO())
		if err != nil {
			t.Logf("error from %s: %v", controllerName, err)
		}
	}
	c.verifySecretFn = verifySecret
	c.Run(f)
}

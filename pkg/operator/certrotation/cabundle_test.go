package certrotation

import (
	"context"
	gcrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/util/cert"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

func TestEnsureConfigMapCABundle(t *testing.T) {
	tests := []struct {
		name string

		initialConfigMapFn func() *corev1.ConfigMap
		caFn               func() (*crypto.CA, error)

		verifyActions func(t *testing.T, client *kubefake.Clientset)
		expectedError string
	}{
		{
			name: "initial create",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialConfigMapFn: func() *corev1.ConfigMap { return nil },
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "configmaps") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("create", "configmaps") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeCABundle {
					t.Errorf("expected certificate type 'ca-bundle', got: %v", certType)
				}
				if len(actual.Data["ca-bundle.crt"]) == 0 {
					t.Error(actual.Data)
				}
			},
		},
		{
			name: "update keep both",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialConfigMapFn: func() *corev1.ConfigMap {
				caBundleConfigMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "trust-bundle"},
					Data:       map[string]string{},
				}
				certs, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				caBytes, err := crypto.EncodeCertificates(certs.Config.Certs...)
				if err != nil {
					t.Fatal(err)
				}
				caBundleConfigMap.Data["ca-bundle.crt"] = string(caBytes)
				return caBundleConfigMap
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[1].Matches("update", "configmaps") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if len(actual.Data["ca-bundle.crt"]) == 0 {
					t.Error(actual.Data)
				}
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeCABundle {
					t.Errorf("expected certificate type 'ca-bundle', got: %v", certType)
				}
				result, err := cert.ParseCertsPEM([]byte(actual.Data["ca-bundle.crt"]))
				if err != nil {
					t.Fatal(err)
				}
				if len(result) != 2 {
					t.Error(len(result))
				}
			},
		},
		{
			name: "update remove old",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialConfigMapFn: func() *corev1.ConfigMap {
				caBundleConfigMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "trust-bundle"},
					Data:       map[string]string{},
				}
				certs, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				caBytes, err := crypto.EncodeCertificates(certs.Config.Certs[0], certs.Config.Certs[0])
				if err != nil {
					t.Fatal(err)
				}
				caBundleConfigMap.Data["ca-bundle.crt"] = string(caBytes)
				return caBundleConfigMap
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[1].Matches("update", "configmaps") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if len(actual.Data["ca-bundle.crt"]) == 0 {
					t.Error(actual.Data)
				}
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeCABundle {
					t.Errorf("expected certificate type 'ca-bundle', got: %v", certType)
				}
				result, err := cert.ParseCertsPEM([]byte(actual.Data["ca-bundle.crt"]))
				if err != nil {
					t.Fatal(err)
				}
				if len(result) != 2 {
					t.Error(len(result))
				}
			},
		},
		{
			name: "update remove duplicate",
			caFn: func() (*crypto.CA, error) {
				return newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
			},
			initialConfigMapFn: func() *corev1.ConfigMap {
				caBundleConfigMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "trust-bundle"},
					Data:       map[string]string{},
				}
				certBytes, err := ioutil.ReadFile("./testfiles/tls-expired.crt")
				if err != nil {
					t.Fatal(err)
				}
				certs, err := cert.ParseCertsPEM(certBytes)
				if err != nil {
					t.Fatal(err)
				}
				caBytes, err := crypto.EncodeCertificates(certs...)
				if err != nil {
					t.Fatal(err)
				}
				caBundleConfigMap.Data["ca-bundle.crt"] = string(caBytes)
				return caBundleConfigMap
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[1].Matches("update", "configmaps") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if len(actual.Data["ca-bundle.crt"]) == 0 {
					t.Error(actual.Data)
				}
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeCABundle {
					t.Errorf("expected certificate type 'ca-bundle', got: %v", certType)
				}
				result, err := cert.ParseCertsPEM([]byte(actual.Data["ca-bundle.crt"]))
				if err != nil {
					t.Fatal(err)
				}
				if len(result) != 1 {
					t.Error(len(result))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

			client := kubefake.NewSimpleClientset()
			if startingObj := test.initialConfigMapFn(); startingObj != nil {
				indexer.Add(startingObj)
				client = kubefake.NewSimpleClientset(startingObj)
			}

			c := &CABundleConfigMap{
				Namespace: "ns",
				Name:      "trust-bundle",

				Client:        client.CoreV1(),
				Lister:        corev1listers.NewConfigMapLister(indexer),
				EventRecorder: events.NewInMemoryRecorder("test"),
			}

			newCA, err := test.caFn()
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.EnsureConfigMapCABundle(context.TODO(), newCA)
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

// NewCACertificate generates and signs new CA certificate and key.
func newTestCACertificate(subject pkix.Name, serialNumber int64, validity metav1.Duration, currentTime func() time.Time) (*crypto.CA, error) {
	caPublicKey, caPrivateKey, err := crypto.NewKeyPair()
	if err != nil {
		return nil, err
	}

	caCert := &x509.Certificate{
		Subject: subject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore:    currentTime().Add(-1 * time.Second),
		NotAfter:     currentTime().Add(validity.Duration),
		SerialNumber: big.NewInt(serialNumber),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := signCertificate(caCert, caPublicKey, caCert, caPrivateKey)
	if err != nil {
		return nil, err
	}

	return &crypto.CA{
		Config: &crypto.TLSCertificateConfig{
			Certs: []*x509.Certificate{cert},
			Key:   caPrivateKey,
		},
		SerialGenerator: &crypto.RandomSerialGenerator{},
	}, nil
}

func signCertificate(template *x509.Certificate, requestKey gcrypto.PublicKey, issuer *x509.Certificate, issuerKey gcrypto.PrivateKey) (*x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, requestKey, issuerKey)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, errors.New("Expected a single certificate")
	}
	return certs[0], nil
}

type cmgetter struct {
	w *cmwrapped
}

func (g *cmgetter) ConfigMaps(string) corev1client.ConfigMapInterface {
	return g.w
}

type cmwrapped struct {
	corev1client.ConfigMapInterface
	d    *dispatcher
	name string
	t    *testing.T
	// the hooks are not invoked for every operation
	hook func(controllerName, op string)
}

func (w cmwrapped) Create(ctx context.Context, cm *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error) {
	w.t.Logf("[%s] op=Create, cm=%s/%s", w.name, cm.Namespace, cm.Name)
	return w.ConfigMapInterface.Create(ctx, cm, opts)
}
func (w cmwrapped) Update(ctx context.Context, cm *corev1.ConfigMap, opts metav1.UpdateOptions) (*corev1.ConfigMap, error) {
	w.t.Logf("[%s] op=Update, cm=%s/%s", w.name, cm.Namespace, cm.Name)
	return w.ConfigMapInterface.Update(ctx, cm, opts)
}
func (w cmwrapped) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	w.t.Logf("[%s] op=Delete, cm=%s", w.name, name)
	defer func() {
		if w.hook != nil {
			w.hook(w.name, operation(w.t, opts))
		}
	}()
	return w.ConfigMapInterface.Delete(ctx, name, opts)
}
func (w cmwrapped) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error) {
	if w.hook != nil {
		w.hook(w.name, operation(w.t, opts))
	}
	obj, err := w.ConfigMapInterface.Get(ctx, name, opts)
	w.t.Logf("[%s] op=Get, cm=%s, err: %v", w.name, name, err)
	return obj, err
}

type fakeCMLister struct {
	who        string
	dispatcher *dispatcher
	tracker    clienttesting.ObjectTracker
}

func (l *fakeCMLister) List(selector labels.Selector) (ret []*corev1.ConfigMap, err error) {
	return l.ConfigMaps("").List(selector)
}

func (l *fakeCMLister) ConfigMaps(namespace string) corev1listers.ConfigMapNamespaceLister {
	return &fakeCMNamespaceLister{
		who:        l.who,
		dispatcher: l.dispatcher,
		tracker:    l.tracker,
		ns:         namespace,
	}
}

type fakeCMNamespaceLister struct {
	who        string
	dispatcher *dispatcher
	tracker    clienttesting.ObjectTracker
	ns         string
}

func (l *fakeCMNamespaceLister) List(selector labels.Selector) (ret []*corev1.ConfigMap, err error) {
	obj, err := l.tracker.List(
		schema.GroupVersionResource{Version: "v1", Resource: "configmaps"},
		schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"},
		l.ns,
	)
	var cms []*corev1.ConfigMap
	if l, ok := obj.(*corev1.ConfigMapList); ok {
		for i := range l.Items {
			cms = append(cms, &l.Items[i])
		}
	}
	return cms, err
}

func (l *fakeCMNamespaceLister) Get(name string) (*corev1.ConfigMap, error) {
	l.dispatcher.Sequence(l.who, "before-lister-get")
	obj, err := l.tracker.Get(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, l.ns, name)
	l.dispatcher.Sequence(l.who, "after-lister-get")
	if cm, ok := obj.(*corev1.ConfigMap); ok {
		return cm, err
	}
	return nil, err
}

func FuzzEnsureConfigMapCABundle(f *testing.F) {
	const (
		WorkerCount                       = 3
		ConfigMapNamespace, ConfigMapName = "ns", "test-target"
	)
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       ConfigMapNamespace,
			Name:            ConfigMapName,
			ResourceVersion: "10",
		},
		Data: map[string]string{"ca-bundle.crt": ""},
	}
	newCA, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
	if err != nil {
		f.Fatal(err)
	}
	_, err = manageCABundleConfigMap(existing, newCA.Config.Certs[0])
	if err != nil {
		f.Fatal(err)
	}

	for _, choices := range [][]byte{{1}, {1, 2}, {1, 2, 3}} {
		f.Add(choices)
	}

	f.Fuzz(func(t *testing.T, choices []byte) {
		d := &dispatcher{
			t:        t,
			choices:  choices,
			requests: make(chan request, WorkerCount),
		}
		go d.Run()
		defer d.Stop()

		existing = existing.DeepCopy()

		// get the original crt bytes to compare later
		caCertWant, ok := existing.Data["ca-bundle.crt"]
		if !ok || len(caCertWant) == 0 {
			t.Fatalf("missing data in 'ca-bundle.crt' key of Data: %#v", existing.Data)
		}

		caWant := existing.DeepCopy()

		clientset := kubefake.NewSimpleClientset(existing)

		options := events.RecommendedClusterSingletonCorrelatorOptions()
		client := clientset.CoreV1().ConfigMaps(ConfigMapNamespace)

		var wg sync.WaitGroup
		for i := 1; i <= WorkerCount; i++ {
			controllerName := fmt.Sprintf("controller-%d", i)
			wg.Add(1)
			d.Join(controllerName)

			go func(controllerName string) {
				defer func() {
					d.Leave(controllerName)
					wg.Done()
				}()

				recorder := events.NewKubeRecorderWithOptions(clientset.CoreV1().Events(ConfigMapNamespace), options, "operator", &corev1.ObjectReference{Name: controllerName, Namespace: ConfigMapNamespace})
				wrapped := &cmwrapped{ConfigMapInterface: client, name: controllerName, t: t, d: d}
				getter := &cmgetter{w: wrapped}
				ctrl := &CABundleConfigMap{
					Namespace: ConfigMapNamespace,
					Name:      ConfigMapName,
					Client:    getter,
					Lister: &fakeCMLister{
						who:        controllerName,
						dispatcher: d,
						tracker:    clientset.Tracker(),
					},
					AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
					Owner:                 &metav1.OwnerReference{Name: "operator"},
					EventRecorder:         recorder,
				}

				d.Sequence(controllerName, "begin")
				_, err := ctrl.EnsureConfigMapCABundle(context.TODO(), newCA)
				if err != nil {
					t.Logf("error from %s: %v", controllerName, err)
				}
			}(controllerName)
		}

		wg.Wait()
		t.Log("controllers done")
		// controllers are done, we don't expect the signer to change
		caCertGot, err := client.Get(context.TODO(), ConfigMapName, metav1.GetOptions{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if caCertGot, ok := caCertGot.Data["ca-bundle.crt"]; !ok || caCertWant != caCertGot {
			t.Errorf("the ca has mutated unexpectedly")
		}
		if got, exists := caCertGot.Annotations["openshift.io/owning-component"]; !exists || got != "test" {
			t.Errorf("owner annotation is missing: %#v", caCertGot.Annotations)
		}
		t.Logf("diff: %s", cmp.Diff(caWant, caCertGot))
	})
}

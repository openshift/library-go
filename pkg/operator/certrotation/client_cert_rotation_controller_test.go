package certrotation

import (
	"context"
	"crypto/x509"
	"runtime"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/events/eventstesting"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

type fakeStatusReporter struct{}

func (f *fakeStatusReporter) Report(ctx context.Context, controllerName string, syncErr error) (updated bool, updateErr error) {
	return false, nil
}

type fakeTargetCertCreator struct {
	name             string
	hostnamesChanged chan struct{}
	channelClosed    bool
	callCount        int
}

func (f *fakeTargetCertCreator) NewCertificate(signer *crypto.CA, validity time.Duration) (*crypto.TLSCertificateConfig, error) {
	return nil, nil
}

func (f *fakeTargetCertCreator) NeedNewTargetCertKeyPair(currentCertSecret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration, refreshOnlyWhenExpired bool, _ bool) string {
	f.callCount += 1
	return ""
}

func (f *fakeTargetCertCreator) SetAnnotations(cert *crypto.TLSCertificateConfig, annotations map[string]string) map[string]string {
	return map[string]string{}
}

func (f *fakeTargetCertCreator) RecheckChannel() <-chan struct{} {
	if !f.channelClosed {
		return f.hostnamesChanged
	} else {
		f.channelClosed = true
		close(f.hostnamesChanged)
		return nil
	}
}

func (f *fakeTargetCertCreator) triggerSync() {
	f.hostnamesChanged <- struct{}{}
}

func TestCertRotationController(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewSimpleClientset()
	controllerCtx, cancel := context.WithCancel(context.Background())

	ns, signerName, caName, targetName := "ns", "test-signer", "test-ca", "test-target"
	eventRecorder := events.NewInMemoryRecorder("test")
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
		JiraComponent: "test",
	}
	owner := &metav1.OwnerReference{
		Name: "operator",
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, 1*time.Minute, informers.WithNamespace(ns))

	signerSecret := RotatedSigningCASecret{
		Namespace:             ns,
		Name:                  signerName,
		Validity:              24 * time.Hour,
		Refresh:               12 * time.Hour,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewSecretLister(indexer),
		Informer:              informerFactory.Core().V1().Secrets(),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
		UseSecretUpdateOnly:   true,
	caBundleConfigMap := CABundleConfigMap{
		Namespace:             ns,
		Name:                  caName,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewConfigMapLister(indexer),
		EventRecorder:         eventRecorder,
		Informer:              informerFactory.Core().V1().ConfigMaps(),
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
	}
	targetSecret := RotatedSelfSignedCertKeySecret{
		Name:      targetName,
		Namespace: ns,
		Validity:  24 * time.Hour,
		Refresh:   12 * time.Hour,
		CertCreator: &ServingRotation{
			Hostnames: func() []string { return []string{"foo", "bar"} },
		},
		Client:                client.CoreV1(),
		Informer:              informerFactory.Core().V1().Secrets(),
		Lister:                corev1listers.NewSecretLister(indexer),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
		UseSecretUpdateOnly:   true,

	c := NewCertRotationController("operator", signerSecret, caBundleConfigMap, targetSecret, eventRecorder, &fakeStatusReporter{})

	time.AfterFunc(1*time.Second, func() {
		cancel()
	})
	c.Run(controllerCtx, 1)

	syncCtx := factory.NewSyncContext("test", eventstesting.NewTestingEventRecorder(t))
	err := c.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("sync error: %v", err)
	}

	if len(actions) != 3 {
	if len(actions) != 6 {
		t.Fatal(spew.Sdump(actions))
	}
	if !actions[0].Matches("create", "secrets") {
	if !actions[0].Matches("get", "secrets") {
		t.Error(actions[0])
	if !actions[1].Matches("create", "configmaps") {
	if !actions[1].Matches("create", "secrets") {
		t.Error(actions[1])
	if !actions[2].Matches("create", "secrets") {
	if !actions[2].Matches("get", "configmaps") {
		t.Error(actions[2])
	actualSignerSecret := actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	actualSignerSecret := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualSignerSecret.Name != signerName {
		t.Errorf("expected signer secret name to be %s, got %s", signerName, actualSignerSecret.Name)
	}
	actualCABundleConfigMap := actions[3].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if actualCABundleConfigMap.Name != caName {
		t.Errorf("expected CA bundle configmap name to be %s, got %s", signerName, actualCABundleConfigMap.Name)
	}
	actualTargetSecret := actions[5].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualTargetSecret.Name != targetName {
		t.Errorf("expected target secret name to be %s, got %s", signerName, actualTargetSecret.Name)
	}
}
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
func TestCertRotationControllerMultipleTargets(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewSimpleClientset()
	controllerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns, signerName, caName, targetFirstName, targetSecondName := "ns", "test-signer", "test-ca", "test-target-one", "test-target-two"
	eventRecorder := events.NewInMemoryRecorder("test")
	additionalAnnotations := AdditionalAnnotations{
		JiraComponent: "test",
	}
	owner := &metav1.OwnerReference{
		Name: "operator",
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, 1*time.Minute, informers.WithNamespace(ns))

	signerSecret := RotatedSigningCASecret{
		Namespace:             ns,
		Name:                  signerName,
		Refresh:               12 * time.Hour,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewSecretLister(indexer),
		Informer:              informerFactory.Core().V1().Secrets(),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
		UseSecretUpdateOnly:   true,
	}
	caBundleConfigMap := CABundleConfigMap{
		Namespace:             ns,
		Name:                  caName,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewConfigMapLister(indexer),
		EventRecorder:         eventRecorder,
		Informer:              informerFactory.Core().V1().ConfigMaps(),
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
	}
	targetFirstSecret := RotatedSelfSignedCertKeySecret{
		Name:      targetFirstName,
		Namespace: ns,
		Validity:  24 * time.Hour,
		Refresh:   12 * time.Hour,
		CertCreator: &ServingRotation{
		},
		Client:                client.CoreV1(),
		Informer:              informerFactory.Core().V1().Secrets(),
		Lister:                corev1listers.NewSecretLister(indexer),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
		UseSecretUpdateOnly:   true,
	}
	targetSecondSecret := RotatedSelfSignedCertKeySecret{
		Name:      targetSecondName,
		Namespace: ns,
		Validity:  24 * time.Hour,
		Refresh:   12 * time.Hour,
		CertCreator: &ServingRotation{
		},
		Client:                client.CoreV1(),
		Informer:              informerFactory.Core().V1().Secrets(),
		Lister:                corev1listers.NewSecretLister(indexer),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
		UseSecretUpdateOnly:   true,
	}

	c := NewCertRotationControllerMultipleTargets("operator", signerSecret, caBundleConfigMap, []RotatedSelfSignedCertKeySecret{targetFirstSecret, targetSecondSecret}, eventRecorder, &fakeStatusReporter{})

	time.AfterFunc(1*time.Second, func() {
		cancel()
	})
	c.Run(controllerCtx, 1)

	// Ensure we don't leak goroutines
	initialNumGoroutine := runtime.NumGoroutine()

	syncCtx := factory.NewSyncContext("test", eventstesting.NewTestingEventRecorder(t))
	err := c.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("sync error: %v", err)
	}

	actions := client.Actions()
	if len(actions) != 8 {
		t.Fatal(spew.Sdump(actions))
	}

	if !actions[0].Matches("get", "secrets") {
		t.Error(actions[0])
	}
	if len(actions) != 4 {
		t.Error(actions[1])
	}
	if !actions[2].Matches("get", "configmaps") {
	if !actions[0].Matches("create", "secrets") {
	}
	if !actions[3].Matches("create", "configmaps") {
	if !actions[1].Matches("create", "configmaps") {
	}
	if !actions[4].Matches("get", "secrets") {
	if !actions[2].Matches("create", "secrets") {
	}
	if !actions[5].Matches("create", "secrets") {
	if !actions[3].Matches("create", "secrets") {
	}
	if !actions[6].Matches("get", "secrets") {
<<<<<<< HEAD
		t.Error(actions[6])
	}
	if !actions[7].Matches("create", "secrets") {
		t.Error(actions[7])
	}
	actualSignerSecret := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualSignerSecret.Name != signerName {
		t.Errorf("expected signer secret name to be %s, got %s", signerName, actualSignerSecret.Name)
	}
	actualCABundleConfigMap := actions[3].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if actualCABundleConfigMap.Name != caName {
		t.Errorf("expected CA bundle configmap name to be %s, got %s", signerName, actualCABundleConfigMap.Name)
	}
	actualFirstTargetSecret := actions[5].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualFirstTargetSecret.Name != targetFirstName {
		t.Errorf("expected first target secret name to be %s, got %s", signerName, actualFirstTargetSecret.Name)
	}
	actualSecondTargetSecret := actions[7].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualSecondTargetSecret.Name != targetSecondName {
		t.Errorf("expected second target secret name to be %s, got %s", signerName, actualFirstTargetSecret.Name)
	}
	currentNumGoroutine := runtime.NumGoroutine()
	if currentNumGoroutine != initialNumGoroutine {
		t.Errorf("Goroutine leak detected, expected %d but was %d", initialNumGoroutine, currentNumGoroutine)
	}
}
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
func TestCertRotationControllerMultipleTargetsPostRunHooks(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewSimpleClientset()
	controllerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns, signerName, caName, targetFirstName, targetSecondName := "ns", "test-signer", "test-ca", "test-target-one", "test-target-two"
	eventRecorder := events.NewInMemoryRecorder("test")
	additionalAnnotations := AdditionalAnnotations{
		JiraComponent: "test",
	}
	owner := &metav1.OwnerReference{
		Name: "operator",
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, 1*time.Minute, informers.WithNamespace(ns))

	firstTargetCertCreator := &fakeTargetCertCreator{name: "first", hostnamesChanged: make(chan struct{}, 1)}
	secondTargetCertCreator := &fakeTargetCertCreator{name: "second", hostnamesChanged: make(chan struct{}, 1)}

	signerSecret := RotatedSigningCASecret{
		Namespace:             ns,
		Name:                  signerName,
		Refresh:               12 * time.Hour,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewSecretLister(indexer),
		Informer:              informerFactory.Core().V1().Secrets(),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
		UseSecretUpdateOnly:   true,
	}
	caBundleConfigMap := CABundleConfigMap{
		Namespace:             ns,
		Name:                  caName,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewConfigMapLister(indexer),
		EventRecorder:         eventRecorder,
		Informer:              informerFactory.Core().V1().ConfigMaps(),
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
	}
	targetFirstSecret := RotatedSelfSignedCertKeySecret{
		Name:                  targetFirstName,
		Namespace:             ns,
		Validity:              24 * time.Hour,
		CertCreator:           firstTargetCertCreator,
		Client:                client.CoreV1(),
		Informer:              informerFactory.Core().V1().Secrets(),
		Lister:                corev1listers.NewSecretLister(indexer),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
		UseSecretUpdateOnly:   true,
	}
	targetSecondSecret := RotatedSelfSignedCertKeySecret{
		Name:                  targetSecondName,
		Namespace:             ns,
		Validity:              24 * time.Hour,
		CertCreator:           secondTargetCertCreator,
		Client:                client.CoreV1(),
		Informer:              informerFactory.Core().V1().Secrets(),
		Lister:                corev1listers.NewSecretLister(indexer),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
		UseSecretUpdateOnly:   true,
	}

	// Ensure we don't leak goroutines
	initialNumGoroutine := runtime.NumGoroutine()

	c := NewCertRotationControllerMultipleTargets("operator", signerSecret, caBundleConfigMap, []RotatedSelfSignedCertKeySecret{targetFirstSecret, targetSecondSecret}, eventRecorder, &fakeStatusReporter{})

	informerFactory.Start(controllerCtx.Done())
	hasSecretSynced := cache.WaitForCacheSync(controllerCtx.Done(), informerFactory.Core().V1().Secrets().Informer().HasSynced)
	if hasSecretSynced != true {
		t.Errorf("caches for secrets didn't sync")
	}
	hasConfigMapsSynced := cache.WaitForCacheSync(controllerCtx.Done(), informerFactory.Core().V1().ConfigMaps().Informer().HasSynced)
	if hasConfigMapsSynced != true {
		t.Errorf("caches for configmap didn't sync")
	}

	time.AfterFunc(1*time.Second, func() {
		cancel()
	})
	firstTargetCertCreator.triggerSync()
	secondTargetCertCreator.triggerSync()
	c.Run(controllerCtx, 1)

	// Ensure both target certs have been called exactly three times
	// initial sync and two hook calls for target certs
||||||| parent of f7056aa9b (fixup! cert-rotation: allow specifying multiple target certs in CertRotationController)
		t.Error(actions[6])
	}
	if !actions[7].Matches("create", "secrets") {
		t.Error(actions[7])
	}
	actualSignerSecret := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualSignerSecret.Name != signerName {
		t.Errorf("expected signer secret name to be %s, got %s", signerName, actualSignerSecret.Name)
	}
	actualCABundleConfigMap := actions[3].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if actualCABundleConfigMap.Name != caName {
		t.Errorf("expected CA bundle configmap name to be %s, got %s", signerName, actualCABundleConfigMap.Name)
	// initial sync and two hook calls for target certs
=======
	actualSignerSecret := actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
>>>>>>> f7056aa9b (fixup! cert-rotation: allow specifying multiple target certs in CertRotationController)
	// TODO[vrutkovs]: informers make unpredictable number of calls
	if firstTargetCertCreator.callCount < 3 {
		t.Errorf("first target cert was expected to be synced three times but was called %d times", firstTargetCertCreator.callCount)
	actualCABundleConfigMap := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if secondTargetCertCreator.callCount < 3 {
		t.Errorf("second target cert was expected to be synced three times but was called %d times", secondTargetCertCreator.callCount)
	}
	actualFirstTargetSecret := actions[2].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	currentNumGoroutine := runtime.NumGoroutine()
	if currentNumGoroutine != initialNumGoroutine {
		t.Errorf("Goroutine leak detected, expected %d but was %d", initialNumGoroutine, currentNumGoroutine)
	actualSecondTargetSecret := actions[3].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
}

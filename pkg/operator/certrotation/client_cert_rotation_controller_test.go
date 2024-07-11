package certrotation

import (
	"context"
	"crypto/x509"
	"fmt"
	"runtime"
	"strings"
	"sync"
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
	"k8s.io/utils/clock"
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
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
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
		Validity:              24 * time.Hour,
		Refresh:               12 * time.Hour,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewSecretLister(indexer),
		Informer:              informerFactory.Core().V1().Secrets(),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
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
	}

	c := NewCertRotationController("operator", signerSecret, caBundleConfigMap, targetSecret, eventRecorder, &fakeStatusReporter{})

	time.AfterFunc(1*time.Second, func() {
		cancel()
	})

	syncCtx := factory.NewSyncContext("test", eventstesting.NewTestingEventRecorder(t))
	err := c.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("sync error: %v", err)
	}

	actions := client.Actions()
	if len(actions) != 3 {
		t.Fatal(spew.Sdump(actions))
	}

	if !actions[0].Matches("create", "secrets") {
		t.Error(actions[0])
	}
	if !actions[1].Matches("create", "configmaps") {
		t.Error(actions[1])
	}
	if !actions[2].Matches("create", "secrets") {
		t.Error(actions[2])
	}
	actualSignerSecret := actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualSignerSecret.Name != signerName {
		t.Errorf("expected signer secret name to be %s, got %s", signerName, actualSignerSecret.Name)
	}
	actualSignerContent := actualSignerSecret.Data["tls.crt"]
	actualCABundleConfigMap := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if actualCABundleConfigMap.Name != caName {
		t.Errorf("expected CA bundle configmap name to be %s, got %s", caName, actualCABundleConfigMap.Name)
	}
	actualCABundleContent := actualCABundleConfigMap.Data["ca-bundle.crt"]
	actualTargetSecret := actions[2].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualTargetSecret.Name != targetName {
		t.Errorf("expected target secret name to be %s, got %s", targetName, actualTargetSecret.Name)
	}
	// Verify that CA bundle is equivalent to the signer
	if string(actualSignerContent) != actualCABundleContent {
		t.Errorf("expected CA bundle to be equivalent to the signer\n signer:\n%s\n, ca bundle:\n %s", string(actualSignerContent), actualCABundleContent)
	}
}

func TestCertRotationControllerIdempotent(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewSimpleClientset()
	controllerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns, signerName, caName, targetName := "ns", "test-signer", "test-ca", "test-target"
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
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
		Validity:              24 * time.Hour,
		Refresh:               12 * time.Hour,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewSecretLister(indexer),
		Informer:              informerFactory.Core().V1().Secrets(),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
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
	}

	// Run sync once to get signer / cabundle / target filled up
	c := NewCertRotationController("operator", signerSecret, caBundleConfigMap, targetSecret, eventRecorder, &fakeStatusReporter{})
	syncCtx := factory.NewSyncContext("test", eventstesting.NewTestingEventRecorder(t))
	err := c.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("sync error: %v", err)
	}

	actions := client.Actions()
	if len(actions) != 3 {
		t.Fatal(spew.Sdump(actions))
	}
	// Extract signer / cabundle / target certs from actions
	previousSignerSecret := actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if previousSignerSecret.Name != signerName {
		t.Fatalf("expected signer secret name to be %s, got %s", signerName, previousSignerSecret.Name)
	}
	previousCABundleConfigMap := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if previousCABundleConfigMap.Name != caName {
		t.Fatalf("expected CA bundle configmap name to be %s, got %s", caName, previousCABundleConfigMap.Name)
	}
	previousTargetSecret := actions[2].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if previousTargetSecret.Name != targetName {
		t.Fatalf("expected target secret name to be %s, got %s", targetName, previousTargetSecret.Name)
	}
	client.ClearActions()

	// Cache generated resources
	indexer.Add(previousSignerSecret)
	indexer.Add(previousCABundleConfigMap)
	indexer.Add(previousTargetSecret)

	// Run a sync and make sure no changes were performed
	err = c.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("sync error: %v", err)
	}

	actions = client.Actions()
	if len(actions) != 0 {
		t.Fatal(spew.Sdump(actions))
	}
}

func TestCertRotationControllerSignerUpdate(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewSimpleClientset()
	controllerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns, signerName, caName, targetName := "ns", "test-signer", "test-ca", "test-target"
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
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
		Validity:              24 * time.Hour,
		Refresh:               12 * time.Hour,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewSecretLister(indexer),
		Informer:              informerFactory.Core().V1().Secrets(),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
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
	}

	// Run sync once to get signer / cabundle / target filled up
	c := NewCertRotationController("operator", signerSecret, caBundleConfigMap, targetSecret, eventRecorder, &fakeStatusReporter{})
	syncCtx := factory.NewSyncContext("test", eventstesting.NewTestingEventRecorder(t))
	err := c.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("sync error: %v", err)
	}

	actions := client.Actions()
	if len(actions) != 3 {
		t.Fatal(spew.Sdump(actions))
	}
	// Extract signer / cabundle / target certs from actions
	previousSignerSecret := actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if previousSignerSecret.Name != signerName {
		t.Fatalf("expected signer secret name to be %s, got %s", signerName, previousSignerSecret.Name)
	}
	previousSignerContent := previousSignerSecret.Data["tls.crt"]
	previousCABundleConfigMap := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if previousCABundleConfigMap.Name != caName {
		t.Fatalf("expected CA bundle configmap name to be %s, got %s", caName, previousCABundleConfigMap.Name)
	}
	previousCABundleContent := previousCABundleConfigMap.Data["ca-bundle.crt"]
	previousTargetSecret := actions[2].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if previousTargetSecret.Name != targetName {
		t.Fatalf("expected target secret name to be %s, got %s", targetName, previousTargetSecret.Name)
	}
	client.ClearActions()

	// Cache all created objects
	indexer.Add(previousSignerSecret)
	indexer.Add(previousCABundleConfigMap)
	indexer.Add(previousTargetSecret)

	// Remove annotations to trigger signer regeneration
	newSignerSecret := previousSignerSecret.DeepCopy()
	newSignerSecret.Annotations = map[string]string{}
	updatedSignerSecret, err := client.CoreV1().Secrets(ns).Update(controllerCtx, newSignerSecret, metav1.UpdateOptions{})
	if err != nil {
		t.Errorf("signer update error: %v", err)
	}
	indexer.Update(updatedSignerSecret)
	client.ClearActions()

	// Run a sync and make sure signer and CA bundle were regenerated
	err = c.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("sync error: %v", err)
	}

	actions = client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	if !actions[0].Matches("update", "secrets") {
		t.Error(actions[0])
	}
	actualSignerSecret := actions[0].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
	if actualSignerSecret.Name != signerName {
		t.Fatalf("expected signer secret name to be %s, got %s", signerName, previousSignerSecret.Name)
	}
	actualSignerContents := actualSignerSecret.Data["tls.crt"]
	if string(actualSignerContents) == string(previousSignerContent) {
		t.Fatalf("new signer content is equivalent to the previous")
	}

	if !actions[1].Matches("update", "configmaps") {
		t.Error(actions[1])
	}
	actualCABundleConfigMap := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
	if actualCABundleConfigMap.Name != caName {
		t.Fatalf("expected CA bundle configmap name to be %s, got %s", caName, previousCABundleConfigMap.Name)
	}
	actualCABundleContent := actualCABundleConfigMap.Data["ca-bundle.crt"]
	if string(actualCABundleContent) == string(previousCABundleContent) {
		t.Fatalf("CA bundle was not regenerated")
	}
	if !strings.Contains(actualCABundleContent, string(previousSignerContent)) {
		t.Fatalf("New CA bundle doesn't contain previous CA bundle\n expected\n%s\n to contain\n%s", actualCABundleContent, string(previousSignerContent))
	}
	if !strings.Contains(actualCABundleContent, string(actualSignerContents)) {
		t.Fatalf("New CA bundle doesn't contain new CA bundle\n expected\n%s\n to contain\n%s", actualCABundleContent, string(actualSignerContents))
	}
}

func TestCertRotationControllerFilterExpiredSigners(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewSimpleClientset()
	controllerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns, signerName, caName, targetName := "ns", "test-signer", "test-ca", "test-target"
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
	additionalAnnotations := AdditionalAnnotations{
		JiraComponent: "test",
	}
	owner := &metav1.OwnerReference{
		Name: "operator",
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, 1*time.Minute, informers.WithNamespace(ns))
	const validity = time.Second

	signerSecret := RotatedSigningCASecret{
		Namespace:             ns,
		Name:                  signerName,
		Validity:              validity,
		Refresh:               validity / 2,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewSecretLister(indexer),
		Informer:              informerFactory.Core().V1().Secrets(),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
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
	targetSecret := RotatedSelfSignedCertKeySecret{
		Name:      targetName,
		Namespace: ns,
		Validity:  validity,
		Refresh:   validity / 2,
		CertCreator: &ServingRotation{
			Hostnames: func() []string { return []string{"foo", "bar"} },
		},
		Client:                client.CoreV1(),
		Informer:              informerFactory.Core().V1().Secrets(),
		Lister:                corev1listers.NewSecretLister(indexer),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
	}

	// Run sync once to get signer / cabundle / target filled up
	c := NewCertRotationController("operator", signerSecret, caBundleConfigMap, targetSecret, eventRecorder, &fakeStatusReporter{})
	syncCtx := factory.NewSyncContext("test", eventstesting.NewTestingEventRecorder(t))
	err := c.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("sync error: %v", err)
	}

	actions := client.Actions()
	if len(actions) != 3 {
		t.Fatal(spew.Sdump(actions))
	}
	// Extract signer / cabundle / target certs from actions
	previousSignerSecret := actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if previousSignerSecret.Name != signerName {
		t.Fatalf("expected signer secret name to be %s, got %s", signerName, previousSignerSecret.Name)
	}
	previousSignerContent := previousSignerSecret.Data["tls.crt"]
	previousCABundleConfigMap := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if previousCABundleConfigMap.Name != caName {
		t.Fatalf("expected CA bundle configmap name to be %s, got %s", caName, previousCABundleConfigMap.Name)
	}
	previousCABundleContent := previousCABundleConfigMap.Data["ca-bundle.crt"]
	previousTargetSecret := actions[2].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if previousTargetSecret.Name != targetName {
		t.Fatalf("expected target secret name to be %s, got %s", targetName, previousTargetSecret.Name)
	}
	client.ClearActions()

	// Cache all created objects
	indexer.Add(previousSignerSecret)
	indexer.Add(previousCABundleConfigMap)
	indexer.Add(previousTargetSecret)

	// Run a sync and make sure signer has expired
	targetSecret.Validity = time.Minute * 5
	time.AfterFunc(validity, func() {
		cancel()
	})
	c.Run(controllerCtx, 1)
	err = c.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("sync error: %v", err)
	}

	actions = client.Actions()
	if len(actions) != 3 {
		t.Fatal(spew.Sdump(actions))
	}
	if !actions[0].Matches("update", "secrets") {
		t.Error(actions[0])
	}
	actualSignerSecret := actions[0].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
	if actualSignerSecret.Name != signerName {
		t.Fatalf("expected signer secret name to be %s, got %s", signerName, actualSignerSecret.Name)
	}
	actualSignerContents := actualSignerSecret.Data["tls.crt"]
	if string(actualSignerContents) == string(previousSignerContent) {
		t.Fatalf("new signer content is equivalent to the previous")
	}

	if !actions[1].Matches("update", "configmaps") {
		t.Error(actions[1])
	}
	actualCABundleConfigMap := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
	if actualCABundleConfigMap.Name != caName {
		t.Fatalf("expected CA bundle configmap name to be %s, got %s", caName, actualCABundleConfigMap.Name)
	}
	actualCABundleContent := actualCABundleConfigMap.Data["ca-bundle.crt"]
	if string(actualCABundleContent) == string(previousCABundleContent) {
		t.Fatalf("CA bundle was not regenerated")
	}
	if strings.Contains(actualCABundleContent, string(previousSignerContent)) {
		t.Fatalf("New CA bundle still contains previous CA bundle\n expected\n%s\n to contain\n%s", actualCABundleContent, string(previousSignerContent))
	}
	if !strings.Contains(actualCABundleContent, string(actualSignerContents)) {
		t.Fatalf("New CA bundle doesn't contain new CA bundle\n expected\n%s\n to contain\n%s", actualCABundleContent, string(actualSignerContents))
	}
	if !actions[2].Matches("update", "secrets") {
		t.Error(actions[2])
	}
	actualTargetSecret := actions[2].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
	if actualTargetSecret.Name != targetName {
		t.Fatalf("expected target secret name to be %s, got %s", signerName, actualTargetSecret.Name)
	}
}

func TestCertRotationControllerParallelUpdate(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewSimpleClientset()
	controllerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns, signerName, caName, targetName := "ns", "test-signer", "test-ca", "test-target"
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
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
		Validity:              24 * time.Hour,
		Refresh:               12 * time.Hour,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewSecretLister(indexer),
		Informer:              informerFactory.Core().V1().Secrets(),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
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
	targetSecret := RotatedSelfSignedCertKeySecret{
		Name:      targetName,
		Namespace: ns,
		Validity:  24 * time.Hour,
		Refresh:   12 * time.Hour,
		CertCreator: &ServingRotation{
			Hostnames: func() []string { return []string{"first"} },
		},
		Client:                client.CoreV1(),
		Informer:              informerFactory.Core().V1().Secrets(),
		Lister:                corev1listers.NewSecretLister(indexer),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
	}

	syncCtx := factory.NewSyncContext("test", eventstesting.NewTestingEventRecorder(t))
	c1 := NewCertRotationController("c1", signerSecret, caBundleConfigMap, targetSecret, eventRecorder, &fakeStatusReporter{})

	// Sync first controller to get first copy of signer/cabundle
	err := c1.Sync(controllerCtx, syncCtx)
	if err != nil {
		t.Errorf("c1 sync error: %v", err)
	}

	actions := client.Actions()
	if len(actions) != 3 {
		t.Fatal(spew.Sdump(actions))
	}
	// Extract signer / cabundle / target certs from actions
	previousSignerSecret := actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if previousSignerSecret.Name != signerName {
		t.Fatalf("expected signer secret name to be %s, got %s", signerName, previousSignerSecret.Name)
	}
	firstSignerContent := previousSignerSecret.Data["tls.crt"]
	previousCABundleConfigMap := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if previousCABundleConfigMap.Name != caName {
		t.Fatalf("expected CA bundle configmap name to be %s, got %s", caName, previousCABundleConfigMap.Name)
	}
	previousTargetSecret := actions[2].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if previousTargetSecret.Name != targetName {
		t.Fatalf("expected target secret name to be %s, got %s", targetName, previousTargetSecret.Name)
	}
	previousCABundleContent := previousCABundleConfigMap.Data["ca-bundle.crt"]
	client.ClearActions()

	// Cache all created resources
	indexer.Add(previousSignerSecret)
	indexer.Add(previousCABundleConfigMap)
	indexer.Add(previousTargetSecret)

	// Remove annotations to trigger signer regeneration
	newSignerSecret := previousSignerSecret.DeepCopy()
	newSignerSecret.Annotations = map[string]string{}
	updatedSignerSecret, err := client.CoreV1().Secrets(ns).Update(controllerCtx, newSignerSecret, metav1.UpdateOptions{})
	if err != nil {
		t.Errorf("signer update error: %v", err)
	}
	indexer.Update(updatedSignerSecret)
	client.ClearActions()

	// Run multiple controllers in parallel
	var workerWg sync.WaitGroup
	var controllers = map[string]factory.Controller{
		"c1": c1,
	}
	const nParallelControllers = 4

	for i := 1; i <= nParallelControllers; i++ {
		// Create second controller reusing signer / cabundle but creating second target cert
		targetNewSecret := RotatedSelfSignedCertKeySecret{
			Name:      fmt.Sprintf("%s-%d", targetName, i),
			Namespace: ns,
			Validity:  24 * time.Hour,
			Refresh:   12 * time.Hour,
			CertCreator: &ServingRotation{
				Hostnames: func() []string { return []string{"second"} },
			},
			Client:                client.CoreV1(),
			Informer:              informerFactory.Core().V1().Secrets(),
			Lister:                corev1listers.NewSecretLister(indexer),
			EventRecorder:         eventRecorder,
			AdditionalAnnotations: additionalAnnotations,
			Owner:                 owner,
		}
		name := fmt.Sprintf("c%d", i)
		ctrl := NewCertRotationController(name, signerSecret, caBundleConfigMap, targetNewSecret, eventRecorder, &fakeStatusReporter{})
		controllers[name] = ctrl
	}

	// Sync informers
	informerFactory.Start(controllerCtx.Done())
	hasSecretSynced := cache.WaitForCacheSync(controllerCtx.Done(), informerFactory.Core().V1().Secrets().Informer().HasSynced)
	if hasSecretSynced != true {
		t.Errorf("caches for secrets didn't sync")
	}
	hasConfigMapsSynced := cache.WaitForCacheSync(controllerCtx.Done(), informerFactory.Core().V1().ConfigMaps().Informer().HasSynced)
	if hasConfigMapsSynced != true {
		t.Errorf("caches for configmap didn't sync")
	}

	// Start parallel controllers
	time.AfterFunc(time.Second, func() {
		cancel()
	})
	for name, ctrl := range controllers {
		t.Logf("Starting %s controller ...", name)
		workerWg.Add(1)
		go func() {
			ctrl.Run(controllerCtx, 1)
			t.Logf("Shutting down %s controller ...", name)
			workerWg.Done()
		}()
	}
	workerWg.Wait()

	var action clienttesting.Action
	actions = client.Actions()
	// Find last configmap update
	for i := len(actions) - 1; i > 0; i-- {
		if actions[i].Matches("update", "configmaps") {
			action = actions[i]
			break
		}
	}
	if action == nil {
		t.Fatal(spew.Sdump(actions))
	}
	actualCABundleConfigMap := action.(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
	if actualCABundleConfigMap.Name != caName {
		t.Fatalf("expected CA bundle configmap name to be %s, got %s", caName, previousCABundleConfigMap.Name)
	}
	actualCABundleContent := actualCABundleConfigMap.Data["ca-bundle.crt"]
	if string(actualCABundleContent) == string(previousCABundleContent) {
		t.Fatalf("CA bundle was not regenerated")
	}
	if !strings.Contains(actualCABundleContent, string(firstSignerContent)) {
		t.Fatalf("New CA bundle doesn't contain previous CA bundle\n expected %s\n to contain %s", actualCABundleContent, string(firstSignerContent))
	}
}

func TestCertRotationControllerMultipleTargets(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	client := kubefake.NewSimpleClientset()
	controllerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns, signerName, caName, targetFirstName, targetSecondName := "ns", "test-signer", "test-ca", "test-target-one", "test-target-two"
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
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
		Validity:              24 * time.Hour,
		Refresh:               12 * time.Hour,
		Client:                client.CoreV1(),
		Lister:                corev1listers.NewSecretLister(indexer),
		Informer:              informerFactory.Core().V1().Secrets(),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
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
			Hostnames: func() []string { return []string{"foo", "bar"} },
		},
		Client:                client.CoreV1(),
		Informer:              informerFactory.Core().V1().Secrets(),
		Lister:                corev1listers.NewSecretLister(indexer),
		EventRecorder:         eventRecorder,
		AdditionalAnnotations: additionalAnnotations,
		Owner:                 owner,
	}
	targetSecondSecret := RotatedSelfSignedCertKeySecret{
		Name:      targetSecondName,
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
	if len(actions) != 4 {
		t.Fatal(spew.Sdump(actions))
	}

	if !actions[0].Matches("create", "secrets") {
		t.Error(actions[0])
	}
	if !actions[1].Matches("create", "configmaps") {
		t.Error(actions[1])
	}
	if !actions[2].Matches("create", "secrets") {
		t.Error(actions[2])
	}
	if !actions[3].Matches("create", "secrets") {
		t.Error(actions[3])
	}
	actualSignerSecret := actions[0].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualSignerSecret.Name != signerName {
		t.Errorf("expected signer secret name to be %s, got %s", signerName, actualSignerSecret.Name)
	}
	actualCABundleConfigMap := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
	if actualCABundleConfigMap.Name != caName {
		t.Errorf("expected CA bundle configmap name to be %s, got %s", signerName, actualCABundleConfigMap.Name)
	}
	actualFirstTargetSecret := actions[2].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualFirstTargetSecret.Name != targetFirstName {
		t.Errorf("expected first target secret name to be %s, got %s", signerName, actualFirstTargetSecret.Name)
	}
	actualSecondTargetSecret := actions[3].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
	if actualSecondTargetSecret.Name != targetSecondName {
		t.Errorf("expected second target secret name to be %s, got %s", signerName, actualFirstTargetSecret.Name)
	}
	currentNumGoroutine := runtime.NumGoroutine()
	if currentNumGoroutine != initialNumGoroutine {
		t.Errorf("Goroutine leak detected, expected %d but was %d", initialNumGoroutine, currentNumGoroutine)
	}
}

package certrotation

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

type MockStatusReporter struct {
}

func (s MockStatusReporter) Report(ctx context.Context, controllerName string, syncErr error) (bool, error) {
	return false, nil
}

func TestRotatedSigningCASecretController(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	client := kubefake.NewSimpleClientset()
	recorder := events.NewInMemoryRecorder("test")

	c := &RotatedSigningCASecretController{
		Signer: &RotatedSigningCASecret{
			Namespace:           "ns",
			Name:                "signer-secret",
			Validity:            24 * time.Hour,
			Refresh:             12 * time.Hour,
			Client:              client.CoreV1(),
			Lister:              corev1listers.NewSecretLister(indexer),
			EventRecorder:       recorder,
			UseSecretUpdateOnly: false,
		},
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}
	err := c.Sync(context.TODO(), factory.NewSyncContext("test", recorder))
	if err != nil {
		t.Fatal(err)
	}
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
}

func TestRotatedSigningCASecretControllerParallel(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	client := kubefake.NewSimpleClientset()
	recorder := events.NewInMemoryRecorder("test")

	var workerWg sync.WaitGroup
	nParallel := 4
	for range nParallel {
		workerWg.Add(1)
		go func() {
			c := &RotatedSigningCASecretController{
				Signer: &RotatedSigningCASecret{
					Namespace:           "ns",
					Name:                "signer-secret",
					Validity:            24 * time.Hour,
					Refresh:             12 * time.Hour,
					Client:              client.CoreV1(),
					Lister:              corev1listers.NewSecretLister(indexer),
					EventRecorder:       recorder,
					UseSecretUpdateOnly: false,
				},
				StatusReporter: MockStatusReporter{},
				name:           "test",
			}
			c.Sync(context.TODO(), factory.NewSyncContext("test", recorder))
			workerWg.Done()
		}()
	}

	workerWg.Wait()
	actions := client.Actions()
	if len(actions) != nParallel*2 {
		t.Fatal(spew.Sdump(actions))
	}
	created := false
	for i := 0; i < nParallel*2; i += 2 {
		if !actions[i].Matches("get", "secrets") {
			t.Error(actions[i])
		}
		updateOrCreate := "create"
		if created {
			updateOrCreate = "update"
		} else {
			created = true
		}
		if !actions[i+1].Matches(updateOrCreate, "secrets") {
			t.Error(actions[i+1])
		}
	}
}

func TestRotatedCABundleController(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	client := kubefake.NewSimpleClientset()
	recorder := events.NewInMemoryRecorder("test")
	ctx := context.TODO()
	syncCtx := factory.NewSyncContext("test", recorder)

	signer := &RotatedSigningCASecret{
		Namespace:           "ns",
		Name:                "signer-secret",
		Validity:            24 * time.Hour,
		Refresh:             12 * time.Hour,
		Client:              client.CoreV1(),
		Lister:              corev1listers.NewSecretLister(indexer),
		EventRecorder:       recorder,
		UseSecretUpdateOnly: false,
	}
	signerCtrl := &RotatedSigningCASecretController{
		Signer:         signer,
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}

	err := signerCtrl.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions := client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	signerSecret := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
	indexer.Add(signerSecret)
	client.ClearActions()

	c := &RotatedCABundleController{
		CABundle: &CABundleConfigMap{
			Namespace:     "ns",
			Name:          "cabundle",
			Client:        client.CoreV1(),
			Lister:        corev1listers.NewConfigMapLister(indexer),
			EventRecorder: recorder,
		},
		Signers:        []*RotatedSigningCASecret{signer},
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}
	err = c.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions = client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	if !actions[0].Matches("get", "configmaps") {
		t.Error(actions[0])
	}
	if !actions[1].Matches("create", "configmaps") {
		t.Error(actions[1])
	}
}

func TestRotatedCABundleControllerParallel(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	client := kubefake.NewSimpleClientset()
	recorder := events.NewInMemoryRecorder("test")
	ctx := context.TODO()
	syncCtx := factory.NewSyncContext("test", recorder)

	signer := &RotatedSigningCASecret{
		Namespace:           "ns",
		Name:                "signer-secret",
		Validity:            24 * time.Hour,
		Refresh:             12 * time.Hour,
		Client:              client.CoreV1(),
		Lister:              corev1listers.NewSecretLister(indexer),
		EventRecorder:       recorder,
		UseSecretUpdateOnly: false,
	}
	signerCtrl := &RotatedSigningCASecretController{
		Signer:         signer,
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}

	err := signerCtrl.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions := client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	signerSecret := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
	indexer.Add(signerSecret)
	client.ClearActions()

	var workerWg sync.WaitGroup
	nParallel := 4
	for range nParallel {
		workerWg.Add(1)
		go func() {
			c := &RotatedCABundleController{
				CABundle: &CABundleConfigMap{
					Namespace:     "ns",
					Name:          "cabundle",
					Client:        client.CoreV1(),
					Lister:        corev1listers.NewConfigMapLister(indexer),
					EventRecorder: recorder,
				},
				Signers:        []*RotatedSigningCASecret{signer},
				StatusReporter: MockStatusReporter{},
				name:           "test",
			}
			c.Sync(ctx, syncCtx)
			workerWg.Done()
		}()
	}
	workerWg.Wait()

	actions = client.Actions()
	if len(actions) != nParallel+1 {
		t.Fatal(spew.Sdump(actions))
	}
	if !actions[0].Matches("get", "configmaps") {
		t.Error(actions[0])
	}
	if !actions[1].Matches("create", "configmaps") {
		t.Error(actions[1])
	}
	for i := 2; i < nParallel; i++ {
		if !actions[i].Matches("get", "configmaps") {
			t.Error(actions[i])
		}
	}
}

func TestRotatedCABundleMultipleSignersController(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	client := kubefake.NewSimpleClientset()
	recorder := events.NewInMemoryRecorder("test")
	ctx := context.TODO()
	syncCtx := factory.NewSyncContext("test", recorder)

	signers := []*RotatedSigningCASecret{}
	signerCerts := []string{}
	nSigners := 3
	for i := range nSigners {
		signer := &RotatedSigningCASecret{
			Namespace:           "ns",
			Name:                fmt.Sprintf("signer-%d-secret", i),
			Validity:            24 * time.Hour,
			Refresh:             12 * time.Hour,
			Client:              client.CoreV1(),
			Lister:              corev1listers.NewSecretLister(indexer),
			EventRecorder:       recorder,
			UseSecretUpdateOnly: false,
		}
		signers = append(signers, signer)

		signerCtrl := &RotatedSigningCASecretController{
			Signer:         signer,
			StatusReporter: MockStatusReporter{},
			name:           "test",
		}

		err := signerCtrl.Sync(ctx, syncCtx)
		if err != nil {
			t.Fatal(err)
		}
		actions := client.Actions()
		if len(actions) != 2 {
			t.Fatal(spew.Sdump(actions))
		}
		client.ClearActions()
		signerSecret := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
		signerContents, ok := signerSecret.Data["tls.crt"]
		if !ok {
			t.Fatal(spew.Sdump(signerContents))
		}
		signerCerts = append(signerCerts, string(signerContents))
		indexer.Add(signerSecret)
	}

	c := &RotatedCABundleController{
		CABundle: &CABundleConfigMap{
			Namespace:     "ns",
			Name:          "cabundle",
			Client:        client.CoreV1(),
			Lister:        corev1listers.NewConfigMapLister(indexer),
			EventRecorder: recorder,
		},
		Signers:        signers,
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}
	err := c.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
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
	caBundleConfigMap := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
	caBundleContents, ok := caBundleConfigMap.Data["ca-bundle.crt"]
	if !ok {
		t.Fatal(spew.Sdump(caBundleContents))
	}
	for i := range nSigners {
		signer := signerCerts[i]
		if !strings.Contains(caBundleContents, signer) {
			t.Fatalf("Missing signer #%d", i)
		}
	}

}

func TestRotatedTargetSecretController(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	client := kubefake.NewSimpleClientset()
	recorder := events.NewInMemoryRecorder("test")
	ctx := context.TODO()
	syncCtx := factory.NewSyncContext("test", recorder)

	signer := &RotatedSigningCASecret{
		Namespace:           "ns",
		Name:                "signer-secret",
		Validity:            24 * time.Hour,
		Refresh:             12 * time.Hour,
		Client:              client.CoreV1(),
		Lister:              corev1listers.NewSecretLister(indexer),
		EventRecorder:       recorder,
		UseSecretUpdateOnly: false,
	}
	signerCtrl := &RotatedSigningCASecretController{
		Signer:         signer,
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}

	err := signerCtrl.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions := client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	signerSecret := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
	indexer.Add(signerSecret)
	client.ClearActions()

	caBundle := &CABundleConfigMap{
		Namespace:     "ns",
		Name:          "cabundle",
		Client:        client.CoreV1(),
		Lister:        corev1listers.NewConfigMapLister(indexer),
		EventRecorder: recorder,
	}
	caBundleCtrl := &RotatedCABundleController{
		CABundle:       caBundle,
		Signers:        []*RotatedSigningCASecret{signer},
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}
	err = caBundleCtrl.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions = client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	caBundleConfigMap := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
	indexer.Add(caBundleConfigMap)
	client.ClearActions()

	targetCtrl := &RotatedTargetSecretController{
		CABundle: caBundle,
		Signer:   signer,
		Target: RotatedSelfSignedCertKeySecret{
			Namespace:           "ns",
			Name:                "target",
			Validity:            24 * time.Hour,
			Refresh:             12 * time.Hour,
			Client:              client.CoreV1(),
			Lister:              corev1listers.NewSecretLister(indexer),
			EventRecorder:       recorder,
			UseSecretUpdateOnly: false,
			CertCreator: &ClientRotation{
				UserInfo: &user.DefaultInfo{Name: "system:test"},
			},
		},
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}
	err = targetCtrl.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions = client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	if !actions[0].Matches("get", "secrets") {
		t.Error(actions[0])
	}
	if !actions[1].Matches("create", "secrets") {
		t.Error(actions[1])
	}
}

func TestRotatedTargetSecretControllerParallel(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	client := kubefake.NewSimpleClientset()
	recorder := events.NewInMemoryRecorder("test")
	ctx := context.TODO()
	syncCtx := factory.NewSyncContext("test", recorder)

	signer := &RotatedSigningCASecret{
		Namespace:           "ns",
		Name:                "signer-secret",
		Validity:            24 * time.Hour,
		Refresh:             12 * time.Hour,
		Client:              client.CoreV1(),
		Lister:              corev1listers.NewSecretLister(indexer),
		EventRecorder:       recorder,
		UseSecretUpdateOnly: false,
	}
	signerCtrl := &RotatedSigningCASecretController{
		Signer:         signer,
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}

	err := signerCtrl.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions := client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	signerSecret := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
	indexer.Add(signerSecret)
	client.ClearActions()

	caBundle := &CABundleConfigMap{
		Namespace:     "ns",
		Name:          "cabundle",
		Client:        client.CoreV1(),
		Lister:        corev1listers.NewConfigMapLister(indexer),
		EventRecorder: recorder,
	}
	caBundleCtrl := &RotatedCABundleController{
		CABundle:       caBundle,
		Signers:        []*RotatedSigningCASecret{signer},
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}
	err = caBundleCtrl.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions = client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	caBundleConfigMap := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
	indexer.Add(caBundleConfigMap)
	client.ClearActions()

	var workerWg sync.WaitGroup
	nParallel := 4
	for range nParallel {
		workerWg.Add(1)
		go func() {
			c := &RotatedTargetSecretController{
				CABundle: caBundle,
				Signer:   signer,
				Target: RotatedSelfSignedCertKeySecret{
					Namespace:           "ns",
					Name:                "target",
					Validity:            24 * time.Hour,
					Refresh:             12 * time.Hour,
					Client:              client.CoreV1(),
					Lister:              corev1listers.NewSecretLister(indexer),
					EventRecorder:       recorder,
					UseSecretUpdateOnly: false,
					CertCreator: &ClientRotation{
						UserInfo: &user.DefaultInfo{Name: "system:test"},
					},
				},
				StatusReporter: MockStatusReporter{},
				name:           "test",
			}
			c.Sync(ctx, syncCtx)
			workerWg.Done()
		}()
	}
	workerWg.Wait()
	actions = client.Actions()
	if len(actions) != nParallel*2 {
		t.Fatal(spew.Sdump(actions))
	}
	created := false
	for i := 0; i < nParallel*2; i += 2 {
		if !actions[i].Matches("get", "secrets") {
			t.Error(actions[i])
		}
		updateOrCreate := "create"
		if created {
			updateOrCreate = "update"
		} else {
			created = true
		}
		if !actions[i+1].Matches(updateOrCreate, "secrets") {
			t.Error(actions[i+1])
		}
	}
}

func TestMultipleRotatedTargetSecretController(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	client := kubefake.NewSimpleClientset()
	recorder := events.NewInMemoryRecorder("test")
	ctx := context.TODO()
	syncCtx := factory.NewSyncContext("test", recorder)

	signer := &RotatedSigningCASecret{
		Namespace:           "ns",
		Name:                "signer-secret",
		Validity:            24 * time.Hour,
		Refresh:             12 * time.Hour,
		Client:              client.CoreV1(),
		Lister:              corev1listers.NewSecretLister(indexer),
		EventRecorder:       recorder,
		UseSecretUpdateOnly: false,
	}
	signerCtrl := &RotatedSigningCASecretController{
		Signer:         signer,
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}

	err := signerCtrl.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions := client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	signerSecret := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
	indexer.Add(signerSecret)
	client.ClearActions()

	caBundle := &CABundleConfigMap{
		Namespace:     "ns",
		Name:          "cabundle",
		Client:        client.CoreV1(),
		Lister:        corev1listers.NewConfigMapLister(indexer),
		EventRecorder: recorder,
	}
	caBundleCtrl := &RotatedCABundleController{
		CABundle:       caBundle,
		Signers:        []*RotatedSigningCASecret{signer},
		StatusReporter: MockStatusReporter{},
		name:           "test",
	}
	err = caBundleCtrl.Sync(ctx, syncCtx)
	if err != nil {
		t.Fatal(err)
	}
	actions = client.Actions()
	if len(actions) != 2 {
		t.Fatal(spew.Sdump(actions))
	}
	caBundleConfigMap := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
	indexer.Add(caBundleConfigMap)
	client.ClearActions()

	nTargets := 3
	for i := range nTargets {
		targetCtrl := &RotatedTargetSecretController{
			CABundle: caBundle,
			Signer:   signer,
			Target: RotatedSelfSignedCertKeySecret{
				Namespace:           "ns",
				Name:                fmt.Sprintf("target-%d", i),
				Validity:            24 * time.Hour,
				Refresh:             12 * time.Hour,
				Client:              client.CoreV1(),
				Lister:              corev1listers.NewSecretLister(indexer),
				EventRecorder:       recorder,
				UseSecretUpdateOnly: false,
				CertCreator: &ClientRotation{
					UserInfo: &user.DefaultInfo{Name: "system:user-one"},
				},
			},
			StatusReporter: MockStatusReporter{},
			name:           "test",
		}
		err = targetCtrl.Sync(ctx, syncCtx)
		if err != nil {
			t.Fatal(err)
		}
	}

	actions = client.Actions()
	if len(actions) != nTargets*2 {
		t.Fatal(spew.Sdump(actions))
	}
	for i := 0; i < nTargets*2; i += 2 {
		if !actions[i].Matches("get", "secrets") {
			t.Error(actions[i])
		}
		if !actions[i+1].Matches("create", "secrets") {
			t.Error(actions[i+1])
		}
	}
}

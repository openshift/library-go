package controller

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

func newTestSignerGetter(t *testing.T, pc clock.PassiveClock, cn string) SignerGetter {
	certCfg, err := crypto.NewSigningCertificate(cn, crypto.RSAKeyPairGenerator{Bits: 2048}, crypto.WithNowFunc(pc.Now), crypto.WithLifetime(time.Hour))
	if err != nil {
		t.Fatalf("generating signing certificate: %v", err)
	}

	return &mockSignerGetter{
		signer: &crypto.CA{
			Config:          certCfg,
			SerialGenerator: &crypto.RandomSerialGenerator{},
		},
	}
}

type sharedSignerGetter struct {
	signerGetter SignerGetter
}

func (ssg *sharedSignerGetter) GetSignerGetter(t *testing.T, pc clock.PassiveClock, name string) SignerGetter {
	if ssg.signerGetter == nil {
		ssg.signerGetter = newTestSignerGetter(t, pc, name)
	}

	return ssg.signerGetter
}

func TestCABundleControllerSync(t *testing.T) {
	type testcase struct {
		name               string
		signerGetterFns    []func(*testing.T, clock.PassiveClock) SignerGetter
		metadataFn         CABundleMetadataFn
		validateActions    func(*testing.T, []clienttesting.Action)
		initialConfigMapFn func(*testing.T, clock.PassiveClock) *corev1.ConfigMap
		expectedErr        error
		lister             corev1listers.ConfigMapLister
	}

	// used to create a signer getter that returns the same value once initialized
	sharedSignerGetter := &sharedSignerGetter{}

	testcases := []testcase{
		{
			name: "no existing resource, single signer getter successfully returns signer, successfully creates desired ConfigMap",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					certCfg, err := crypto.NewSigningCertificate("test", crypto.RSAKeyPairGenerator{Bits: 2048}, crypto.WithNowFunc(pc.Now), crypto.WithLifetime(time.Hour))
					if err != nil {
						t.Fatalf("generating signing certificate: %v", err)
					}

					return &mockSignerGetter{
						signer: &crypto.CA{
							Config:          certCfg,
							SerialGenerator: &crypto.RandomSerialGenerator{},
						},
					}
				},
			},
			metadataFn:       func(_ *corev1.ConfigMap) bool { return false },
			initialConfigMapFn: nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("create", "configmaps") {
					t.Fatalf("expected action to be a create on configmaps but got %v", action)
				}

				createAction, ok := action.(clienttesting.CreateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.CreateAction but got %T", action)
				}

				obj := createAction.GetObject()

				configmap, ok := obj.(*corev1.ConfigMap)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.ConfigMap but got %T", obj)
				}

				if configmap.Data == nil {
					t.Fatal("expected configmap to contain data but it did not")
				}

				caBundleStr, ok := configmap.Data["ca-bundle.crt"]
				if !ok {
					t.Fatal("expected configmap to contain key 'ca-bundle.crt' but it did not")
				}

				if len(caBundleStr) == 0 {
					t.Fatal("configmap key 'ca-bundle.crt' is empty")
				}

				certs, err := cert.ParseCertsPEM([]byte(caBundleStr))
				if err != nil {
					t.Fatalf("could not parse PEM-encoded certs from configmap key 'ca-bundle.crt' contents: %v", err)
				}

				if len(certs) != 1 {
					t.Fatalf("expected exactly 1 CA certificate in the CA bundle, but got %d", len(certs))
				}

				cert := certs[0]

				if err := cert.CheckSignatureFrom(cert); err != nil {
					t.Fatalf("expected the CA certificate in the bundle to be a self-signed certificate but it was not: %v", err)
				}

				if !strings.HasPrefix(cert.Subject.CommonName, "test") {
					t.Fatalf("expected the CA certificate to have a subject with common name containing prefix %q but got %q", "test", cert.Subject.CommonName)
				}
			},
		},
		{
			name: "no existing resource, signer getter returns error, error",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					return &mockSignerGetter{
						err: fmt.Errorf("boom"),
					}
				},
			},
			metadataFn:       func(_ *corev1.ConfigMap) bool { return false },
			initialConfigMapFn: nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 0 {
					t.Fatalf("expected no actions to occur but got %d", len(a))
				}
			},
			expectedErr: fmt.Errorf("getting signers: boom"),
		},
		{
			name: "no existing resource, multiple signers with identical certs are deduplicated, creates configmap with single cert",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					return sharedSignerGetter.GetSignerGetter(t, pc, "test")
				},
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					return sharedSignerGetter.GetSignerGetter(t, pc, "test")
				},
			},
			metadataFn:       func(_ *corev1.ConfigMap) bool { return false },
			initialConfigMapFn: nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("create", "configmaps") {
					t.Fatalf("expected action to be a create on configmaps but got %v", action)
				}

				createAction, ok := action.(clienttesting.CreateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.CreateAction but got %T", action)
				}

				configmap := createAction.GetObject().(*corev1.ConfigMap)

				caBundleStr, ok := configmap.Data["ca-bundle.crt"]
				if !ok {
					t.Fatal("expected configmap to contain key 'ca-bundle.crt' but it did not")
				}

				certs, err := cert.ParseCertsPEM([]byte(caBundleStr))
				if err != nil {
					t.Fatalf("could not parse PEM-encoded certs: %v", err)
				}

				if len(certs) != 1 {
					t.Fatalf("expected exactly 1 CA certificate after deduplication, but got %d", len(certs))
				}
			},
		},
		{
			name: "existing resource with expired cert, new signer added, expired cert pruned and new signer added to bundle",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					certCfg, err := crypto.NewSigningCertificate("test-new", crypto.RSAKeyPairGenerator{Bits: 2048}, crypto.WithNowFunc(pc.Now), crypto.WithLifetime(time.Hour))
					if err != nil {
						t.Fatalf("generating signing certificate: %v", err)
					}

					return &mockSignerGetter{
						signer: &crypto.CA{
							Config:          certCfg,
							SerialGenerator: &crypto.RandomSerialGenerator{},
						},
					}
				},
			},
			metadataFn: func(_ *corev1.ConfigMap) bool { return false },
			initialConfigMapFn: func(t *testing.T, pc clock.PassiveClock) *corev1.ConfigMap {
				oldClock := clocktesting.NewFakeClock(time.Now().Add(-2 * time.Hour))
				certCfg, err := crypto.NewSigningCertificate("test-old", crypto.RSAKeyPairGenerator{Bits: 2048}, crypto.WithNowFunc(oldClock.Now), crypto.WithLifetime(time.Hour))
				if err != nil {
					t.Fatalf("generating signing certificate: %v", err)
				}

				certs := []*x509.Certificate{certCfg.Certs[0]}
				caBytes, err := crypto.EncodeCertificates(certs...)
				if err != nil {
					t.Fatalf("encoding certificates: %v", err)
				}

				return &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "bundle",
					},
					Data: map[string]string{
						"ca-bundle.crt": string(caBytes),
					},
				}
			},
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "configmaps") {
					t.Fatalf("expected action to be an update on configmaps but got %v", action)
				}

				updateAction, ok := action.(clienttesting.UpdateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.UpdateAction but got %T", action)
				}

				configmap := updateAction.GetObject().(*corev1.ConfigMap)

				caBundleStr, ok := configmap.Data["ca-bundle.crt"]
				if !ok {
					t.Fatal("expected configmap to contain key 'ca-bundle.crt' but it did not")
				}

				certs, err := cert.ParseCertsPEM([]byte(caBundleStr))
				if err != nil {
					t.Fatalf("could not parse PEM-encoded certs: %v", err)
				}

				if len(certs) != 1 {
					t.Fatalf("expected exactly 1 CA certificate after pruning expired, but got %d", len(certs))
				}

				if !strings.HasPrefix(certs[0].Subject.CommonName, "test-new") {
					t.Fatalf("expected certificate to be from test-new signer but got %q", certs[0].Subject.CommonName)
				}
			},
		},
		{
			name: "existing resource with nil data, metadata update required, initializes data and updates metadata",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					certCfg, err := crypto.NewSigningCertificate("test", crypto.RSAKeyPairGenerator{Bits: 2048}, crypto.WithNowFunc(pc.Now), crypto.WithLifetime(time.Hour))
					if err != nil {
						t.Fatalf("generating signing certificate: %v", err)
					}

					return &mockSignerGetter{
						signer: &crypto.CA{
							Config:          certCfg,
							SerialGenerator: &crypto.RandomSerialGenerator{},
						},
					}
				},
			},
			metadataFn: func(cm *corev1.ConfigMap) bool {
				if cm.Annotations == nil {
					cm.Annotations = map[string]string{}
				}
				cm.Annotations["test.io/metadata"] = "value"
				return true
			},
			initialConfigMapFn: func(t *testing.T, pc clock.PassiveClock) *corev1.ConfigMap {
				return &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "bundle",
					},
					Data: nil,
				}
			},
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "configmaps") {
					t.Fatalf("expected action to be an update on configmaps but got %v", action)
				}

				updateAction := action.(clienttesting.UpdateAction)
				configmap := updateAction.GetObject().(*corev1.ConfigMap)

				if configmap.Data == nil {
					t.Fatal("expected configmap data to be initialized but it was nil")
				}

				_, ok := configmap.Data["ca-bundle.crt"]
				if !ok {
					t.Fatal("expected configmap to contain key 'ca-bundle.crt' but it did not")
				}

				annotation, ok := configmap.Annotations["test.io/metadata"]
				if !ok {
					t.Fatal("expected configmap to contain annotation 'test.io/metadata' but it did not")
				}

				if annotation != "value" {
					t.Fatalf("expected annotation to have value 'value' but got %q", annotation)
				}
			},
		},
		{
			name: "existing resource, no metadata update needed, no signer data changes, no update performed",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					return sharedSignerGetter.GetSignerGetter(t, pc, "test")
				},
			},
			metadataFn: func(_ *corev1.ConfigMap) bool { return false },
			initialConfigMapFn: func(t *testing.T, pc clock.PassiveClock) *corev1.ConfigMap {
				sg := sharedSignerGetter.GetSignerGetter(t, pc, "test")
				ca, err := sg.GetSigner(nil)
				if err != nil {
					t.Fatalf("getting shared signer: %v", err)
				}

				caBytes, err := crypto.EncodeCertificates(ca.Config.Certs[0])
				if err != nil {
					t.Fatalf("encoding ca bytes: %v", err)
				}

				return &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "bundle",
					},
					Data: map[string]string{
						"ca-bundle.crt": string(caBytes),
					},
				}
			},
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 0 {
					t.Fatalf("expected no actions to occur but got %d", len(a))
				}
			},
		},
		{
			name: "existing resource, metadata update required but no signer data changes, updates metadata only",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					return sharedSignerGetter.GetSignerGetter(t, pc, "test")
				},
			},
			metadataFn: func(cm *corev1.ConfigMap) bool {
				if cm.Labels == nil {
					cm.Labels = map[string]string{}
				}
				cm.Labels["test.io/managed"] = "true"
				return true
			},
			initialConfigMapFn: func(t *testing.T, pc clock.PassiveClock) *corev1.ConfigMap {
				ca := sharedSignerGetter.GetSignerGetter(t, pc, "test").(*mockSignerGetter).signer
				caBytes, err := crypto.EncodeCertificates(ca.Config.Certs[0])
				if err != nil {
					t.Fatalf("encoding ca bytes: %v", err)
				}

				return &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "bundle",
					},
					Data: map[string]string{
						"ca-bundle.crt": string(caBytes),
					},
				}
			},
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "configmaps") {
					t.Fatalf("expected action to be an update on configmaps but got %v", action)
				}

				updateAction := action.(clienttesting.UpdateAction)
				configmap := updateAction.GetObject().(*corev1.ConfigMap)

				label, ok := configmap.Labels["test.io/managed"]
				if !ok {
					t.Fatal("expected configmap to contain label 'test.io/managed' but it did not")
				}

				if label != "true" {
					t.Fatalf("expected label 'test.io/managed' to have value 'true' but got %q", label)
				}

				caBundleStr, ok := configmap.Data["ca-bundle.crt"]
				if !ok {
					t.Fatal("expected configmap to contain key 'ca-bundle.crt' but it did not")
				}

				if len(caBundleStr) == 0 {
					t.Fatal("configmap key 'ca-bundle.crt' is empty")
				}
			},
		},
		{
			name: "existing resource with malformed cert data, error parsing existing certificates",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					return newTestSignerGetter(t, pc, "test")
				},
			},
			metadataFn: func(_ *corev1.ConfigMap) bool { return false },
			initialConfigMapFn: func(t *testing.T, pc clock.PassiveClock) *corev1.ConfigMap {
				return &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "bundle",
					},
					Data: map[string]string{
						"ca-bundle.crt": "this is not valid PEM data\n-----BEGIN CERTIFICATE-----\ninvalid",
					},
				}
			},
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 0 {
					t.Fatalf("expected no actions to occur but got %d", len(a))
				}
			},
			expectedErr: fmt.Errorf("updating CA contents: could not parse existing certificates: data does not contain any valid RSA or ECDSA certificates"),
		},
		{
			name: "fail to get existing configmap, error",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{
				func(t *testing.T, pc clock.PassiveClock) SignerGetter {
					return newTestSignerGetter(t, pc, "test")
				},
			},
			metadataFn:         func(_ *corev1.ConfigMap) bool { return false },
			initialConfigMapFn: nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 0 {
					t.Fatalf("expected no actions to occur but got %d", len(a))
				}
			},
			lister:      &failingConfigMapLister{err: errors.New("boom")},
			expectedErr: errors.New("getting configmap \"test/bundle\": boom"),
		},
		{
			name: "no existing resource, no signers provided, still creates configmap with empty bundle",
			signerGetterFns: []func(*testing.T, clock.PassiveClock) SignerGetter{},
			metadataFn:       func(_ *corev1.ConfigMap) bool { return false },
			initialConfigMapFn: nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("create", "configmaps") {
					t.Fatalf("expected action to be a create on configmaps but got %v", action)
				}

				createAction := action.(clienttesting.CreateAction)
				configmap := createAction.GetObject().(*corev1.ConfigMap)

				if configmap.Data == nil {
					t.Fatal("expected configmap to contain data but it was nil")
				}

				caBundleStr, ok := configmap.Data["ca-bundle.crt"]
				if !ok {
					t.Fatal("expected configmap to contain key 'ca-bundle.crt' but it did not")
				}

				if len(caBundleStr) > 0 {
					certs, err := cert.ParseCertsPEM([]byte(caBundleStr))
					if err != nil {
						t.Fatalf("could not parse PEM-encoded certs: %v", err)
					}

					if len(certs) != 0 {
						t.Fatalf("expected no certs in bundle but got %d", len(certs))
					}
				}
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClock := clocktesting.NewFakeClock(time.Now())

			var initialConfigMap *corev1.ConfigMap
			if tc.initialConfigMapFn != nil {
				initialConfigMap = tc.initialConfigMapFn(t, fakeClock)
			}

			fakeClient := fake.NewSimpleClientset()
			if initialConfigMap != nil {
				fakeClient = fake.NewSimpleClientset(initialConfigMap)
			}

			informerFactory := informers.NewSharedInformerFactory(fakeClient, 0)

			configMapInformer := informerFactory.Core().V1().ConfigMaps()
			if initialConfigMap != nil {
				configMapInformer.Informer().GetIndexer().Add(initialConfigMap)
			}

			eventRecorder := events.NewInMemoryRecorder("test", fakeClock)

			signerGetters := []SignerGetter{}

			for _, signerGetterFn := range tc.signerGetterFns {
				signerGetters = append(signerGetters, signerGetterFn(t, fakeClock))
			}

			configMapLister := configMapInformer.Lister()
			if tc.lister != nil {
				configMapLister = tc.lister
			}

			caBundleController := &CABundle{
				namespace: "test",
				name:      "bundle",

				client:        fakeClient.CoreV1(),
				lister:        configMapLister,
				eventRecorder: eventRecorder,
				signerGetters: signerGetters,

				metadataFn: tc.metadataFn,
				clock:      fakeClock,
			}

			err := caBundleController.Sync(t.Context(), factory.NewSyncContext("test", eventRecorder))
			if err != nil {
				if tc.expectedErr != nil && err.Error() == tc.expectedErr.Error() {
					return
				}

				t.Fatalf("expected error %v but got %v", tc.expectedErr, err)
			}

			tc.validateActions(t, fakeClient.Actions())
		})
	}
}

type mockSignerGetter struct {
	signer *crypto.CA
	err    error
}

func (m *mockSignerGetter) GetSigner(_ context.Context) (*crypto.CA, error) {
	return m.signer, m.err
}

type failingConfigMapLister struct {
	err error
}

func (fcl *failingConfigMapLister) List(_ labels.Selector) ([]*corev1.ConfigMap, error) {
	return nil, fcl.err
}

func (fcl *failingConfigMapLister) ConfigMaps(_ string) corev1listers.ConfigMapNamespaceLister {
	return fcl
}

func (fcl *failingConfigMapLister) Get(_ string) (*corev1.ConfigMap, error) {
	return nil, fcl.err
}

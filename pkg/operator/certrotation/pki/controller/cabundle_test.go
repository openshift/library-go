package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestCABundleControllerSync(t *testing.T) {
	type testcase struct {
		name             string
		signerGetterFns  []func(*testing.T, clock.PassiveClock) SignerGetter
		metadataFn       CABundleMetadataFn
		validateActions  func(*testing.T, []clienttesting.Action)
		initialConfigMap *corev1.ConfigMap
		expectedErr      error
	}

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
			initialConfigMap: nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("create", "configmaps") {
					t.Fatalf("expected action to be a create on secrets but got %v", action)
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
		// TODO: more test cases
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()
			if tc.initialConfigMap != nil {
				fakeClient = fake.NewSimpleClientset(tc.initialConfigMap)
			}

			informerFactory := informers.NewSharedInformerFactory(fakeClient, 0)

			configMapInformer := informerFactory.Core().V1().ConfigMaps()
			if tc.initialConfigMap != nil {
				configMapInformer.Informer().GetIndexer().Add(tc.initialConfigMap)
			}

			fakeClock := clocktesting.NewFakeClock(time.Now())

			eventRecorder := events.NewInMemoryRecorder("test", fakeClock)

			signerGetters := []SignerGetter{}

			for _, signerGetterFn := range tc.signerGetterFns {
				signerGetters = append(signerGetters, signerGetterFn(t, fakeClock))
			}

			caBundleController := &CABundle{
				namespace: "test",
				name:      "bundle",

				client:        fakeClient.CoreV1(),
				lister:        configMapInformer.Lister(),
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

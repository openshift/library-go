package csr

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/csr/csrtestinghelpers"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/stretchr/testify/require"

	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	certificatesv1 "k8s.io/client-go/applyconfigurations/certificates/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/workqueue"
	clocktesting "k8s.io/utils/clock/testing"
)

const (
	testControllerNamespace  = "test-ns"
	testControllerSecretName = "test-secret"
	testControllerCSRName    = "test-csr"
)

func TestReset(t *testing.T) {
	ctrl, _ := newTestControllerWithClient()
	ctrl.csrName = "test-csr"
	ctrl.keyData = []byte("test-key")

	ctrl.reset()

	if ctrl.csrName != "" {
		t.Errorf("expected csrName to be empty, got %q", ctrl.csrName)
	}
	if ctrl.keyData != nil {
		t.Errorf("expected keyData to be nil, got %v", ctrl.keyData)
	}
}

func TestControllerSync(t *testing.T) {
	testCert := csrtestinghelpers.NewTestCert("test", time.Hour)

	tests := []struct {
		name              string
		ctrlPrepare       func(*clientCertificateController)
		fakeClientPrepare func(*fake.Clientset)
		errorExpected     bool
		errorContains     string
		validateCtrl      func(*testing.T, *clientCertificateController, error)
		validateSecret    func(*testing.T, *corev1.Secret, error)
	}{
		{
			name: "secret not found",
			fakeClientPrepare: func(fakeClient *fake.Clientset) {
				fakeClient.PrependReactor("get", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, testControllerSecretName)
				})
			},
			validateSecret: func(t *testing.T, secret *corev1.Secret, err error) {
				require.Equal(t, err, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, testControllerSecretName), "error message")
			},
		},
		{
			name: "secret get error",
			fakeClientPrepare: func(fakeClient *fake.Clientset) {
				fakeClient.PrependReactor("get", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("api error")
				})
			},
			errorExpected: true,
			errorContains: "api error",
			validateSecret: func(t *testing.T, secret *corev1.Secret, err error) {
				require.Equal(t, err, errors.New("api error"), "error message")
			},
		},
		{
			name: "secret exists",
			fakeClientPrepare: func(fakeClient *fake.Clientset) {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testControllerSecretName,
						Namespace: testControllerNamespace,
					},
					Data: map[string][]byte{
						TLSCertFile: []byte("some-cert-data"),
					},
				}
				fakeClient.PrependReactor("get", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, secret, nil
				})
			},
			validateSecret: func(t *testing.T, secret *corev1.Secret, err error) {
				require.NoError(t, err)
				require.NotNil(t, secret)
				require.NotNil(t, secret.Annotations)
				require.Equal(t, "test-component", secret.Annotations[annotations.OpenShiftComponent], "unexpected component")
			},
		},
		{
			name: "secret with metadata update",
			ctrlPrepare: func(ctrl *clientCertificateController) {
				ctrl.AdditionalAnnotations = certrotation.AdditionalAnnotations{
					JiraComponent: "test-component",
				}
			},
			fakeClientPrepare: func(fakeClient *fake.Clientset) {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testControllerSecretName,
						Namespace: testControllerNamespace,
					},
					Data: map[string][]byte{
						TLSCertFile: []byte("some-cert-data"),
					},
				}
				fakeClient.PrependReactor("get", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, secret, nil
				})
				fakeClient.PrependReactor("update", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, secret, nil
				})
			},
			validateSecret: func(t *testing.T, secret *corev1.Secret, err error) {
				require.NoError(t, err)
				require.NotNil(t, secret)
				require.NotNil(t, secret.Annotations)
				require.Equal(t, "test-component", secret.Annotations[annotations.OpenShiftComponent], "unexpected component")
			},
		},
		{
			name: "pending csr",
			ctrlPrepare: func(ctrl *clientCertificateController) {
				ctrl.csrName = testControllerCSRName
				ctrl.keyData = []byte("pending-key")

				// Mock approved CSR with certificate
				approvedCSR := csrtestinghelpers.NewApprovedCSR(csrtestinghelpers.CSRHolder{Name: testControllerCSRName})
				approvedCSR.Status.Certificate = testCert.Cert
				ctrl.hubCSRClient = &fakeCSRClient{
					csr: approvedCSR,
				}
				ctrl.keyData = testCert.Key
			},
			validateSecret: func(t *testing.T, secret *corev1.Secret, err error) {
				require.NoError(t, err)
				require.NotNil(t, secret)
				require.NotNil(t, secret.Annotations)
				require.Equal(t, "test-component", secret.Annotations[annotations.OpenShiftComponent], "unexpected component")
				require.NotNil(t, secret.Data)
				require.NotNil(t, secret.Data[corev1.TLSCertKey])
				require.Equal(t, testCert.Cert, secret.Data[corev1.TLSCertKey], "unexpected certificate")
				require.Equal(t, testCert.Key, secret.Data[corev1.TLSPrivateKeyKey], "unexpected private key")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl, fakeClient := newTestControllerWithClient()

			if tt.ctrlPrepare != nil {
				tt.ctrlPrepare(ctrl)
			}

			if tt.fakeClientPrepare != nil {
				tt.fakeClientPrepare(fakeClient)
			}

			ctx := context.Background()
			syncCtx := &testSyncContext{}
			err := ctrl.sync(ctx, syncCtx)

			if tt.errorExpected && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.errorExpected && err != nil && tt.validateCtrl == nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.errorContains != "" && (err == nil || !strings.Contains(err.Error(), tt.errorContains)) {
				t.Errorf("expected error to contain %q, got %q", tt.errorContains, err)
			}

			if tt.validateCtrl != nil {
				tt.validateCtrl(t, ctrl, err)
			}

			if tt.validateSecret != nil {
				secret, err := ctrl.spokeCoreClient.Secrets(testControllerNamespace).Get(ctx, testControllerSecretName, metav1.GetOptions{})
				tt.validateSecret(t, secret, err)
			}
		})
	}
}

// Test helper functions and types
func newTestController(client *fake.Clientset) *clientCertificateController {
	clientCertOption := ClientCertOption{
		SecretNamespace:     testControllerNamespace,
		SecretName:          testControllerSecretName,
		AdditonalSecretData: map[string][]byte{"test": []byte("data")},
		AdditionalAnnotations: certrotation.AdditionalAnnotations{
			JiraComponent: "test-component",
		},
	}
	csrOption := CSROption{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-csr-",
		},
		Subject:         &pkix.Name{CommonName: "test"},
		SignerName:      certificates.KubeAPIServerClientSignerName,
		DNSNames:        []string{"localhost"},
		EventFilterFunc: func(obj interface{}) bool { return true },
	}
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	return &clientCertificateController{
		clientCertOption,
		csrOption,
		informerFactory.Certificates().V1().CertificateSigningRequests().Lister(),
		client.CertificatesV1().CertificateSigningRequests(),
		client.CoreV1(),
		"test-controller",
		"",
		[]byte{},
	}
}

func newTestControllerWithClient() (*clientCertificateController, *fake.Clientset) {
	client := fake.NewSimpleClientset()
	ctrl := newTestController(client)
	return ctrl, client
}

type testSyncContext struct{}

func (t *testSyncContext) Queue() workqueue.RateLimitingInterface { return nil }
func (t *testSyncContext) QueueKey() string                       { return "test-key" }
func (t *testSyncContext) Recorder() events.Recorder {
	return events.NewInMemoryRecorder("test", clocktesting.NewFakeClock(time.Now()))
}

type fakeCSRClient struct {
	csr *certificates.CertificateSigningRequest
	err error
}

func (f *fakeCSRClient) Get(ctx context.Context, name string, opts metav1.GetOptions) (*certificates.CertificateSigningRequest, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.csr, nil
}

func (f *fakeCSRClient) Create(ctx context.Context, csr *certificates.CertificateSigningRequest, opts metav1.CreateOptions) (*certificates.CertificateSigningRequest, error) {
	if f.err != nil {
		return nil, f.err
	}
	csr.Name = "test-csr"
	return csr, nil
}

func (f *fakeCSRClient) Update(ctx context.Context, csr *certificates.CertificateSigningRequest, opts metav1.UpdateOptions) (*certificates.CertificateSigningRequest, error) {
	panic("not implemented")
}

func (f *fakeCSRClient) UpdateStatus(ctx context.Context, csr *certificates.CertificateSigningRequest, opts metav1.UpdateOptions) (*certificates.CertificateSigningRequest, error) {
	panic("not implemented")
}

func (f *fakeCSRClient) UpdateApproval(ctx context.Context, certificateSigningRequestName string, certificateSigningRequest *certificates.CertificateSigningRequest, opts metav1.UpdateOptions) (*certificates.CertificateSigningRequest, error) {
	panic("not implemented")
}

func (f *fakeCSRClient) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	panic("not implemented")
}

func (f *fakeCSRClient) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	panic("not implemented")
}

func (f *fakeCSRClient) List(ctx context.Context, opts metav1.ListOptions) (*certificates.CertificateSigningRequestList, error) {
	panic("not implemented")
}

func (f *fakeCSRClient) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	panic("not implemented")
}

func (f *fakeCSRClient) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (*certificates.CertificateSigningRequest, error) {
	panic("not implemented")
}

func (f *fakeCSRClient) Apply(ctx context.Context, certificateSigningRequest *certificatesv1.CertificateSigningRequestApplyConfiguration, opts metav1.ApplyOptions) (*certificates.CertificateSigningRequest, error) {
	panic("not implemented")
}

func (f *fakeCSRClient) ApplyStatus(ctx context.Context, certificateSigningRequest *certificatesv1.CertificateSigningRequestApplyConfiguration, opts metav1.ApplyOptions) (*certificates.CertificateSigningRequest, error) {
	panic("not implemented")
}

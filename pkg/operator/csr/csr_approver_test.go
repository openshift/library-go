package csr

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	"github.com/stretchr/testify/require"

	certapiv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	certv1listers "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/openshift/library-go/pkg/operator/events"
)

func Test_csrApproverController_sync(t *testing.T) {
	var alwaysApprove alwaysApproveApprover
	var deny denyApprover
	var noOpinion noOpinionApprover

	tests := []struct {
		name           string
		csrApprover    CSRApprover
		csrName        string
		csrs           []*certapiv1.CertificateSigningRequest
		expectApproved corev1.ConditionStatus
		expectDenied   corev1.ConditionStatus
		wantErr        bool
	}{
		{
			name:        "no CSRSs",
			csrApprover: &alwaysApprove,
			csrName:     "testCSR",
		},
		{
			name:        "CSR waiting for approval - approved",
			csrApprover: &alwaysApprove,
			csrName:     "test-csr",
			csrs: []*certapiv1.CertificateSigningRequest{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-csr"},
					Spec:       certapiv1.CertificateSigningRequestSpec{Request: genCSR(t, "somesubject")},
				},
			},
			expectApproved: corev1.ConditionTrue,
			expectDenied:   corev1.ConditionUnknown,
		},
		{
			name:        "CSR waiting for approval - denied",
			csrApprover: &deny,
			csrName:     "test-csr",
			csrs: []*certapiv1.CertificateSigningRequest{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-csr"},
					Spec:       certapiv1.CertificateSigningRequestSpec{Request: genCSR(t, "somesubject")},
				},
			},
			expectApproved: corev1.ConditionUnknown,
			expectDenied:   corev1.ConditionTrue,
		},
		{
			name:        "CSR waiting for approval - no opinion",
			csrApprover: &noOpinion,
			csrName:     "test-csr",
			csrs: []*certapiv1.CertificateSigningRequest{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-csr"},
					Spec:       certapiv1.CertificateSigningRequestSpec{Request: genCSR(t, "somesubject")},
				},
			},
			expectApproved: corev1.ConditionUnknown,
			expectDenied:   corev1.ConditionUnknown,
		},
		{
			name:        "CSR waiting for approval - invalid CSR in request",
			csrApprover: &noOpinion,
			csrName:     "test-csr",
			csrs: []*certapiv1.CertificateSigningRequest{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-csr"},
					Spec: certapiv1.CertificateSigningRequestSpec{
						Request: []byte(`
// -----BEGIN CERTIFICATE REQUEST-----
// hithere
// -----END CERTIFICATE REQUEST-----`),
					},
				},
			},
			expectApproved: corev1.ConditionUnknown,
			expectDenied:   corev1.ConditionUnknown,
			wantErr:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeObjects := []runtime.Object{}
			csrIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, c := range tt.csrs {
				fakeObjects = append(fakeObjects, c)
				require.NoError(t, csrIndexer.Add(c))
			}

			csrLister := certv1listers.NewCertificateSigningRequestLister(csrIndexer)

			fakeClient := fake.NewSimpleClientset(fakeObjects...)
			c := &csrApproverController{
				csrClient:   fakeClient.CertificatesV1().CertificateSigningRequests(),
				csrLister:   csrLister,
				csrApprover: tt.csrApprover,
			}
			if err := c.sync(
				context.Background(),
				fakeSyncContext{queueKey: tt.csrName, eventRecorder: events.NewInMemoryRecorder("csr-approver-test", clocktesting.NewFakePassiveClock(time.Now()))},
			); (err != nil) != tt.wantErr {
				t.Errorf("csrApproverController.sync() error = %v, wantErr %v", err, tt.wantErr)
			}

			csr, _ := fakeClient.CertificatesV1().CertificateSigningRequests().Get(context.Background(), tt.csrName, metav1.GetOptions{})

			if len(tt.csrs) > 0 {
				gotApproved, gotDenied := corev1.ConditionUnknown, corev1.ConditionUnknown
				for _, cond := range csr.Status.Conditions {
					if cond.Type == certapiv1.CertificateApproved {
						gotApproved = cond.Status
					}
					if cond.Type == certapiv1.CertificateDenied {
						gotDenied = cond.Status
					}
				}
				require.Equal(t, tt.expectApproved, gotApproved)
				require.Equal(t, tt.expectDenied, gotDenied)
			}
		})
	}
}

func TestServiceAccountApprover(t *testing.T) {
	const (
		testSA        = "system:serviceaccount:test:test-sa"
		testSubject   = "CN=therealyou"
		testSubjectCN = "therealyou"
	)

	testSAApprover := NewServiceAccountApprover("test", "test-sa", testSubject)

	tests := []struct {
		name           string
		csr            *certapiv1.CertificateSigningRequest
		expectDecision CSRApprovalDecision
		expectReason   string
		wantErr        bool
	}{
		{
			name:           "nil csr",
			expectDecision: CSRDenied,
			expectReason:   "Error",
			wantErr:        true,
		},
		{
			name: "CSR created by someone else - username",
			csr: &certapiv1.CertificateSigningRequest{
				Spec: certapiv1.CertificateSigningRequestSpec{
					Username: "system:serviceaccount:test:someone-else",
					Request:  genCSR(t, "unexpectedsubject"),
				},
			},
			expectDecision: CSRDenied,
			expectReason:   "CSR \"\" was created by an unexpected user: \"system:serviceaccount:test:someone-else\"",
		},
		{
			name: "CSR created by someone else - different group",
			csr: &certapiv1.CertificateSigningRequest{
				Spec: certapiv1.CertificateSigningRequestSpec{
					Username: testSA,
					Groups: []string{
						"system:serviceaccounts",
						"system:serviceaccounts:different-group",
						"system:authenticated",
					},
					Request: genCSR(t, "unexpectedsubject"),
				},
			},
			expectDecision: CSRDenied,
			expectReason:   "CSR \"\" was created by a user with unexpected groups: [system:authenticated system:serviceaccounts system:serviceaccounts:different-group]",
		},
		{
			name: "CSR created by someone else - empty groups",
			csr: &certapiv1.CertificateSigningRequest{
				Spec: certapiv1.CertificateSigningRequestSpec{
					Username: testSA,
					Groups:   []string{},
					Request:  genCSR(t, "unexpectedsubject"),
				},
			},
			expectDecision: CSRDenied,
			expectReason:   "CSR \"\" was created by a user with unexpected groups: []",
		},
		{
			name: "no actual CSR block",
			csr: &certapiv1.CertificateSigningRequest{
				Spec: certapiv1.CertificateSigningRequestSpec{
					Username: testSA,
					Groups: []string{
						"system:serviceaccounts",
						"system:serviceaccounts:test",
						"system:authenticated",
					},
				},
			},
			expectDecision: CSRDenied,
			expectReason:   "Error",
			wantErr:        true,
		},
		{
			name: "CSR with unexpected subject",
			csr: &certapiv1.CertificateSigningRequest{
				Spec: certapiv1.CertificateSigningRequestSpec{
					Username: testSA,
					Groups: []string{
						"system:serviceaccounts",
						"system:serviceaccounts:test",
						"system:authenticated",
					},
					Request: genCSR(t, "unexpectedsubject"),
				},
			},
			expectDecision: CSRDenied,
			expectReason:   "expected the CSR's subject to be one of [\"CN=therealyou\"], but it is \"CN=unexpectedsubject\"",
		},
		{
			name: "this CSR is fine",
			csr: &certapiv1.CertificateSigningRequest{
				Spec: certapiv1.CertificateSigningRequestSpec{
					Username: testSA,
					Groups: []string{
						"system:serviceaccounts",
						"system:serviceaccounts:test",
						"system:authenticated",
					},
					Request: genCSR(t, testSubjectCN),
				},
			},
			expectDecision: CSRApproved,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var x509CSR *x509.CertificateRequest
			if tt.csr != nil && tt.csr.Spec.Request != nil {
				csrPEM, _ := pem.Decode(tt.csr.Spec.Request)
				require.NotNil(t, csrPEM)

				var err error
				x509CSR, err = x509.ParseCertificateRequest(csrPEM.Bytes)
				require.NoError(t, err)
			}
			gotDecision, gotReason, gotErr := testSAApprover.Approve(tt.csr, x509CSR)

			require.Equal(t, tt.expectDecision, gotDecision)
			require.Equal(t, tt.expectReason, gotReason)
			if tt.wantErr {
				require.Error(t, gotErr)
			} else {
				require.NoError(t, gotErr)
			}
		})
	}
}

func TestServiceAccountMultiSubjectsApprover(t *testing.T) {
	approver := NewServiceAccountMultiSubjectsApprover("test", "test-sa", []string{"CN=sub-1", "CN=sub-2"})

	tests := []struct {
		name             string
		subject          string
		expectedDecision CSRApprovalDecision
		expectedReason   string
	}{
		{
			name:             "sub-1",
			subject:          "sub-1",
			expectedDecision: CSRApproved,
		},
		{
			name:             "sub-2",
			subject:          "sub-2",
			expectedDecision: CSRApproved,
		},
		{
			name:             "unfamiliar",
			subject:          "unfamiliar",
			expectedDecision: CSRDenied,
			expectedReason:   "expected the CSR's subject to be one of [\"CN=sub-1\" \"CN=sub-2\"], but it is \"CN=unfamiliar\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := &certapiv1.CertificateSigningRequest{
				Spec: certapiv1.CertificateSigningRequestSpec{
					Username: "system:serviceaccount:test:test-sa",
					Groups: []string{
						"system:serviceaccounts",
						"system:serviceaccounts:test",
						"system:authenticated",
					},
					Request: genCSR(t, tt.subject),
				},
			}

			csrPEM, _ := pem.Decode(csr.Spec.Request)
			require.NotNil(t, csrPEM)

			x509CSR, err := x509.ParseCertificateRequest(csrPEM.Bytes)
			require.NoError(t, err)

			decision, reason, err := approver.Approve(csr, x509CSR)
			require.Equal(t, tt.expectedDecision, decision)
			require.Equal(t, tt.expectedReason, reason)
			require.NoError(t, err)
		})
	}
}

type denyApprover func(_ *certapiv1.CertificateSigningRequest, _ *x509.CertificateRequest) (CSRApprovalDecision, string, error)
type alwaysApproveApprover func(_ *certapiv1.CertificateSigningRequest, _ *x509.CertificateRequest) (CSRApprovalDecision, string, error)
type noOpinionApprover func(_ *certapiv1.CertificateSigningRequest, _ *x509.CertificateRequest) (CSRApprovalDecision, string, error)

func (a *denyApprover) Approve(_ *certapiv1.CertificateSigningRequest, _ *x509.CertificateRequest) (CSRApprovalDecision, string, error) {
	return CSRDenied, "BecauseReasons", nil
}

func (a *alwaysApproveApprover) Approve(_ *certapiv1.CertificateSigningRequest, _ *x509.CertificateRequest) (CSRApprovalDecision, string, error) {
	return CSRApproved, "", nil
}

func (a *noOpinionApprover) Approve(_ *certapiv1.CertificateSigningRequest, _ *x509.CertificateRequest) (CSRApprovalDecision, string, error) {
	return CSRNoOpinion, "", nil
}

func genCSR(t *testing.T, subjectCN string) []byte {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "failed to generate a private key: %v", err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: subjectCN},
		},
		key,
	)
	require.NoError(t, err, "failed to create a CSR: %v", err)

	csrPEM, err := pemEncodeCSR(csrDER)
	require.NoError(t, err, "failed to PEM-encode the CSR: %v", err)

	return csrPEM
}

func pemEncodeCSR(csrDER []byte) ([]byte, error) {
	buffer := bytes.Buffer{}

	if err := pem.Encode(&buffer,
		&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER},
	); err != nil {
		return nil, fmt.Errorf("failed to convert DER CSR into a PEM-formatted block: %w", err)
	}

	return buffer.Bytes(), nil
}

type fakeSyncContext struct {
	eventRecorder events.Recorder
	queueKey      string
}

func (c fakeSyncContext) Queue() workqueue.RateLimitingInterface {
	return nil
}

func (c fakeSyncContext) QueueKey() string {
	return c.queueKey
}

func (c fakeSyncContext) Recorder() events.Recorder {
	return c.eventRecorder
}

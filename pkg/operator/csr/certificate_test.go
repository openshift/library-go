package csr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/operator/csr/csrtestinghelpers"
	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"
)

func TestIsCSRApproved(t *testing.T) {
	cases := []struct {
		name        string
		csr         *certificates.CertificateSigningRequest
		csrApproved bool
	}{
		{
			name: "pending csr",
			csr:  csrtestinghelpers.NewCSR(csrtestinghelpers.CSRHolder{}),
		},
		{
			name: "denied csr",
			csr:  csrtestinghelpers.NewDeniedCSR(csrtestinghelpers.CSRHolder{}),
		},
		{
			name:        "approved csr",
			csr:         csrtestinghelpers.NewApprovedCSR(csrtestinghelpers.CSRHolder{}),
			csrApproved: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csrApproved := isCSRApproved(c.csr)
			if csrApproved != c.csrApproved {
				t.Errorf("expected %t, but got %t", c.csrApproved, csrApproved)
			}
		})
	}
}

func TestHasValidHubKubeconfig(t *testing.T) {
	cases := []struct {
		name    string
		secret  *corev1.Secret
		subject *pkix.Name
		isValid bool
	}{
		{
			name:   "no data",
			secret: csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", nil, nil),
		},
		{
			name:   "no kubeconfig",
			secret: csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", nil, map[string][]byte{}),
		},
		{
			name: "no key",
			secret: csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", nil, map[string][]byte{
				KubeconfigFile: csrtestinghelpers.NewKubeconfig(nil, nil),
			}),
		},
		{
			name: "no cert",
			secret: csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", &csrtestinghelpers.TestCert{Key: []byte("key")}, map[string][]byte{
				KubeconfigFile: csrtestinghelpers.NewKubeconfig(nil, nil),
			}),
		},
		{
			name: "bad cert",
			secret: csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", &csrtestinghelpers.TestCert{Key: []byte("key"), Cert: []byte("bad cert")}, map[string][]byte{
				KubeconfigFile: csrtestinghelpers.NewKubeconfig(nil, nil),
			}),
		},
		{
			name: "expired cert",
			secret: csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", csrtestinghelpers.NewTestCert("test", -60*time.Second), map[string][]byte{
				KubeconfigFile: csrtestinghelpers.NewKubeconfig(nil, nil),
			}),
		},
		{
			name: "invalid common name",
			secret: csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", csrtestinghelpers.NewTestCert("test", 60*time.Second), map[string][]byte{
				KubeconfigFile: csrtestinghelpers.NewKubeconfig(nil, nil),
			}),
			subject: &pkix.Name{
				CommonName: "wrong-common-name",
			},
		},
		{
			name: "valid kubeconfig",
			secret: csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", csrtestinghelpers.NewTestCert("test", 60*time.Second), map[string][]byte{
				KubeconfigFile: csrtestinghelpers.NewKubeconfig(nil, nil),
			}),
			subject: &pkix.Name{
				CommonName: "test",
			},
			isValid: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			isValid := HasValidHubKubeconfig(c.secret, c.subject)
			if isValid != c.isValid {
				t.Errorf("expected %t, but got %t", c.isValid, isValid)
			}
		})
	}
}

func TestIsCertificateValid(t *testing.T) {
	cases := []struct {
		name     string
		testCert *csrtestinghelpers.TestCert
		subject  *pkix.Name
		isValid  bool
	}{
		{
			name:     "no cert",
			testCert: &csrtestinghelpers.TestCert{},
		},
		{
			name:     "bad cert",
			testCert: &csrtestinghelpers.TestCert{Cert: []byte("bad cert")},
		},
		{
			name:     "expired cert",
			testCert: csrtestinghelpers.NewTestCert("test", -60*time.Second),
		},
		{
			name:     "invalid common name",
			testCert: csrtestinghelpers.NewTestCert("test", 60*time.Second),
			subject: &pkix.Name{
				CommonName: "wrong-common-name",
			},
		},
		{
			name: "valid cert",
			testCert: csrtestinghelpers.NewTestCertWithSubject(pkix.Name{
				CommonName: "test",
			}, 60*time.Second),
			subject: &pkix.Name{
				CommonName: "test",
			},
			isValid: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := IsCertificateValid(c.testCert.Cert, c.subject)
			isValid := err == nil
			if isValid != c.isValid {
				t.Errorf("expected %t, but got %t: %v", c.isValid, isValid, err)
			}
		})
	}
}

func TestGetCertValidityPeriod(t *testing.T) {
	certs := []byte{}
	certs = append(certs, csrtestinghelpers.NewTestCert("cluster0", 10*time.Second).Cert...)
	secondCert := csrtestinghelpers.NewTestCert("cluster0", 5*time.Second).Cert
	certs = append(certs, secondCert...)
	expectedCerts, _ := certutil.ParseCertsPEM(secondCert)
	cases := []struct {
		name         string
		secret       *corev1.Secret
		expectedCert *x509.Certificate
		expectedErr  string
	}{
		{
			name:        "no data",
			secret:      csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", nil, nil),
			expectedErr: "no client certificate found in secret \"testns/testsecret\"",
		},
		{
			name:        "no cert",
			secret:      csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", nil, map[string][]byte{}),
			expectedErr: "no client certificate found in secret \"testns/testsecret\"",
		},
		{
			name:        "bad cert",
			secret:      csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", &csrtestinghelpers.TestCert{Cert: []byte("bad cert")}, map[string][]byte{}),
			expectedErr: "unable to parse TLS certificates: data does not contain any valid RSA or ECDSA certificates",
		},
		{
			name:         "valid cert",
			secret:       csrtestinghelpers.NewHubKubeconfigSecret(testNamespace, testSecretName, "", &csrtestinghelpers.TestCert{Cert: certs}, map[string][]byte{}),
			expectedCert: expectedCerts[0],
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			notBefore, notAfter, err := getCertValidityPeriod(c.secret)
			csrtestinghelpers.AssertError(t, err, c.expectedErr)
			if c.expectedCert == nil {
				return
			}
			if !c.expectedCert.NotBefore.Equal(*notBefore) {
				t.Errorf("expect %v, but got %v", expectedCerts[0].NotBefore, *notBefore)
			}
			if !c.expectedCert.NotAfter.Equal(*notAfter) {
				t.Errorf("expect %v, but got %v", expectedCerts[0].NotAfter, *notAfter)
			}
		})
	}
}

// KubeconfigFile is the name of the kubeconfig file in kubeconfigSecret
var KubeconfigFile = "kubeconfig"

// HasValidClientCertificate checks if there exists a valid client certificate in the given secret
// Returns true if all the conditions below are met:
//   1. KubeconfigFile exists when hasKubeconfig is true
//   2. TLSKeyFile exists
//   3. TLSCertFile exists and the certificate is not expired
//   4. If subject is specified, it matches the subject in the certificate stored in TLSCertFile
func HasValidHubKubeconfig(secret *corev1.Secret, subject *pkix.Name) bool {
	if len(secret.Data) == 0 {
		klog.V(4).Infof("No data found in secret %q", secret.Namespace+"/"+secret.Name)
		return false
	}

	if _, ok := secret.Data[KubeconfigFile]; !ok {
		klog.V(4).Infof("No %q found in secret %q", KubeconfigFile, secret.Namespace+"/"+secret.Name)
		return false
	}

	if _, ok := secret.Data[TLSKeyFile]; !ok {
		klog.V(4).Infof("No %q found in secret %q", TLSKeyFile, secret.Namespace+"/"+secret.Name)
		return false
	}

	certData, ok := secret.Data[TLSCertFile]
	if !ok {
		klog.V(4).Infof("No %q found in secret %q", TLSCertFile, secret.Namespace+"/"+secret.Name)
		return false
	}

	err := IsCertificateValid(certData, subject)
	if err != nil {
		klog.V(4).Infof("Unable to validate certificate in secret %s: %v", secret.Namespace+"/"+secret.Name, err)
		return false
	}

	return (err == nil)
}

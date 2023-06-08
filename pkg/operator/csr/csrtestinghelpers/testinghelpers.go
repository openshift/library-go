package csrtestinghelpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/events/eventstesting"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/workqueue"
)

const (
	TestManagedClusterName = "testmanagedcluster"
)

type FakeSyncContext struct {
	spokeName string
	recorder  events.Recorder
	queue     workqueue.RateLimitingInterface
}

func (f FakeSyncContext) Queue() workqueue.RateLimitingInterface { return f.queue }
func (f FakeSyncContext) QueueKey() string                       { return f.spokeName }
func (f FakeSyncContext) Recorder() events.Recorder              { return f.recorder }

func NewFakeSyncContext(t *testing.T, clusterName string) *FakeSyncContext {
	return &FakeSyncContext{
		spokeName: clusterName,
		recorder:  eventstesting.NewTestingEventRecorder(t),
		queue:     workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}
}

type CSRHolder struct {
	Name         string
	Labels       map[string]string
	SignerName   string
	CN           string
	Orgs         []string
	Username     string
	ReqBlockType string
}

func NewCSR(holder CSRHolder) *certv1.CertificateSigningRequest {
	insecureRand := rand.New(rand.NewSource(0))
	pk, err := ecdsa.GenerateKey(elliptic.P256(), insecureRand)
	if err != nil {
		panic(err)
	}
	csrb, err := x509.CreateCertificateRequest(insecureRand, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   holder.CN,
			Organization: holder.Orgs,
		},
		DNSNames:       []string{},
		EmailAddresses: []string{},
		IPAddresses:    []net.IP{},
	}, pk)
	if err != nil {
		panic(err)
	}
	return &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:         holder.Name,
			GenerateName: "csr-",
			Labels:       holder.Labels,
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Username:   holder.Username,
			Usages:     []certv1.KeyUsage{},
			SignerName: holder.SignerName,
			Request:    pem.EncodeToMemory(&pem.Block{Type: holder.ReqBlockType, Bytes: csrb}),
		},
	}
}

func NewDeniedCSR(holder CSRHolder) *certv1.CertificateSigningRequest {
	csr := NewCSR(holder)
	csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:   certv1.CertificateDenied,
		Status: corev1.ConditionTrue,
	})
	return csr
}

func NewApprovedCSR(holder CSRHolder) *certv1.CertificateSigningRequest {
	csr := NewCSR(holder)
	csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:   certv1.CertificateApproved,
		Status: corev1.ConditionTrue,
	})
	return csr
}

func NewKubeconfig(key, cert []byte) []byte {
	var clientKey, clientCertificate string
	var clientKeyData, clientCertificateData []byte
	if key != nil {
		clientKeyData = key
	} else {
		clientKey = corev1.TLSPrivateKeyKey
	}
	if cert != nil {
		clientCertificateData = cert
	} else {
		clientCertificate = corev1.TLSCertKey
	}

	kubeconfig := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{"default-cluster": {
			Server:                "https://127.0.0.1:6001",
			InsecureSkipTLSVerify: true,
		}},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"default-auth": {
			ClientCertificate:     clientCertificate,
			ClientCertificateData: clientCertificateData,
			ClientKey:             clientKey,
			ClientKeyData:         clientKeyData,
		}},
		Contexts: map[string]*clientcmdapi.Context{"default-context": {
			Cluster:   "default-cluster",
			AuthInfo:  "default-auth",
			Namespace: "default",
		}},
		CurrentContext: "default-context",
	}

	kubeconfigData, err := clientcmd.Write(kubeconfig)
	if err != nil {
		panic(err)
	}
	return kubeconfigData
}

type TestCert struct {
	Cert []byte
	Key  []byte
}

func NewHubKubeconfigSecret(namespace, name, resourceVersion string, cert *TestCert, data map[string][]byte) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            name,
			ResourceVersion: resourceVersion,
		},
		Data: data,
	}
	if cert != nil && cert.Cert != nil {
		secret.Data[corev1.TLSCertKey] = cert.Cert
	}
	if cert != nil && cert.Key != nil {
		secret.Data[corev1.TLSPrivateKeyKey] = cert.Key
	}
	return secret
}

func NewTestCertWithSubject(subject pkix.Name, duration time.Duration) *TestCert {
	caKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	caCert, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "open-cluster-management.io"}, caKey)
	if err != nil {
		panic(err)
	}

	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	certDERBytes, err := x509.CreateCertificate(
		cryptorand.Reader,
		&x509.Certificate{
			Subject:      subject,
			SerialNumber: big.NewInt(1),
			NotBefore:    caCert.NotBefore,
			NotAfter:     time.Now().Add(duration).UTC(),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		caCert,
		key.Public(),
		caKey,
	)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		panic(err)
	}

	return &TestCert{
		Cert: pem.EncodeToMemory(&pem.Block{
			Type:  certutil.CertificateBlockType,
			Bytes: cert.Raw,
		}),
		Key: pem.EncodeToMemory(&pem.Block{
			Type:  keyutil.RSAPrivateKeyBlockType,
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}),
	}
}

func NewTestCert(commonName string, duration time.Duration) *TestCert {
	return NewTestCertWithSubject(pkix.Name{
		CommonName: commonName,
	}, duration)
}

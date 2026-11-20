// Package paritytest provides the v1 <-> v2 parity harness: run the v1
// SyncWorker and the v2 Reconciler against the same starting state and
// compare what they produce. The on-cluster contract is byte-compatible by
// design; this harness is what proves it, scenario by scenario, with the
// scenarios drawn from the v1 bug history.
package paritytest

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/cert"
	clock "k8s.io/utils/clock"

	certrotationv1 "github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
	"github.com/openshift/library-go/pkg/operator/events"
	certrotationv2 "github.com/openshift/library-go/pkg/operator/pki/certrotation"
)

// Config describes one rotation under test, in terms both v1 and v2 can
// build.
type Config struct {
	Namespace  string
	SignerName string
	BundleName string
	TargetName string
	Validity   time.Duration
	Refresh    time.Duration
	// TargetRefresh overrides the target's refresh period when non-zero;
	// the default is Refresh, matching the signer.
	TargetRefresh time.Duration
	JiraComponent string
	TestName      string
}

// DefaultConfig returns a client-cert rotation matching the common consumer
// shape.
func DefaultConfig() Config {
	return Config{
		Namespace:     "parity-ns",
		SignerName:    "parity-signer",
		BundleName:    "parity-ca-bundle",
		TargetName:    "parity-client",
		Validity:      24 * time.Hour,
		Refresh:       12 * time.Hour,
		JiraComponent: "parity-component",
		TestName:      "parity-e2e",
	}
}

func (c Config) targetRefresh() time.Duration {
	if c.TargetRefresh != 0 {
		return c.TargetRefresh
	}
	return c.Refresh
}

// userInfo satisfies both v1's user.Info requirement and v2's.
type parityUser struct {
	Name string
}

func (u *parityUser) GetName() string               { return u.Name }
func (u *parityUser) GetUID() string                { return "" }
func (u *parityUser) GetGroups() []string           { return nil }
func (u *parityUser) GetExtra() map[string][]string { return nil }

// RunV1 performs one v1 SyncWorker pass over the config against the given
// client. It mirrors how consumers construct the v1 option structs.
func RunV1(t *testing.T, cfg Config, client kubernetes.Interface, refreshOnlyWhenExpired bool) error {
	t.Helper()
	informers := kubeinformers.NewSharedInformerFactory(client, time.Minute)
	secretInformer := informers.Core().V1().Secrets()
	configMapInformer := informers.Core().V1().ConfigMaps()

	rotation := certrotationv1.RotatedSelfSignedCertKeySecret{
		Validity: cfg.Validity,
		Refresh:  cfg.Refresh,
		Owner:    nil,
		AdditionalAnnotations: certrotationv1.AdditionalAnnotations{
			JiraComponent: cfg.JiraComponent,
			TestName:      cfg.TestName,
		},
		CertCreator: &certrotationv1.ClientRotation{UserInfo: &parityUser{Name: "system:parity"}},
	}
	signingCA := certrotationv1.RotatedSigningCASecret{
		Validity: cfg.Validity,
		Refresh:  cfg.Refresh,
		AdditionalAnnotations: certrotationv1.AdditionalAnnotations{
			JiraComponent: cfg.JiraComponent,
			TestName:      cfg.TestName,
		},
	}
	caBundle := certrotationv1.CABundleConfigMap{
		AdditionalAnnotations: certrotationv1.AdditionalAnnotations{
			JiraComponent: cfg.JiraComponent,
			TestName:      cfg.TestName,
		},
	}

	recorder := events.NewLoggingEventRecorder("paritytest", clock.RealClock{})
	targetNamespace := cfg.Namespace
	signingCA.EventRecorder = recorder
	signingCA.Namespace = cfg.Namespace
	signingCA.Name = cfg.SignerName
	signingCA.Informer = secretInformer
	signingCA.Lister = secretInformer.Lister()
	signingCA.Client = client.CoreV1()
	caBundle.EventRecorder = recorder
	caBundle.Namespace = cfg.Namespace
	caBundle.Name = cfg.BundleName
	caBundle.Informer = configMapInformer
	caBundle.Lister = configMapInformer.Lister()
	caBundle.Client = client.CoreV1()
	rotation.EventRecorder = recorder
	rotation.Namespace = targetNamespace
	rotation.Name = cfg.TargetName
	rotation.Informer = secretInformer
	rotation.Lister = secretInformer.Lister()
	rotation.Client = client.CoreV1()
	rotation.RefreshOnlyWhenExpired = refreshOnlyWhenExpired
	signingCA.RefreshOnlyWhenExpired = refreshOnlyWhenExpired

	stopCh := make(chan struct{})
	defer close(stopCh)
	informers.Start(stopCh)
	informers.WaitForCacheSync(stopCh)

	controller := certrotationv1.CertRotationController{
		RotatedSigningCASecret:         signingCA,
		CABundleConfigMap:              caBundle,
		RotatedSelfSignedCertKeySecret: rotation,
	}
	return controller.SyncWorker(context.Background())
}

// RotationV2 returns the equivalent v2 Rotation for the config.
func RotationV2(cfg Config) certrotationv2.Rotation {
	return certrotationv2.Rotation{
		Signer: certrotationv2.SignerConfig{
			Location: certrotationv2.Location{Namespace: cfg.Namespace, Name: cfg.SignerName},
			Validity: cfg.Validity,
			Refresh:  cfg.Refresh,
			Metadata: certrotationv2.Metadata{JiraComponent: cfg.JiraComponent, TestName: cfg.TestName},
		},
		Bundle: certrotationv2.BundleConfig{
			Location: certrotationv2.Location{Namespace: cfg.Namespace, Name: cfg.BundleName},
			Metadata: certrotationv2.Metadata{JiraComponent: cfg.JiraComponent, TestName: cfg.TestName},
		},
		Targets: []certrotationv2.Target{
			{
				Name:     cfg.TargetName,
				Location: certrotationv2.Location{Namespace: cfg.Namespace, Name: cfg.TargetName},
				Validity: cfg.Validity,
				Refresh:  cfg.Refresh,
				Metadata: certrotationv2.Metadata{JiraComponent: cfg.JiraComponent, TestName: cfg.TestName},
				Cert:     certrotationv2.ClientCert{User: &parityUser{Name: "system:parity"}},
			},
		},
	}
}

// RunV2 performs one v2 Reconcile pass over the config against the given
// client.
func RunV2(t *testing.T, cfg Config, client kubernetes.Interface, role certrotationv2.Role) (certrotationv2.Result, error) {
	t.Helper()
	reconciler, err := certrotationv2.NewReconciler(RotationV2(cfg), certrotationv2.Options{
		Role:       role,
		KubeClient: client,
		PKI:        certrotationv2.LegacyPKI(),
		Recorder:   events.NewLoggingEventRecorder("paritytest", clock.RealClock{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return reconciler.Reconcile(context.Background())
}

// AssertArtifactsEqual compares the v1-produced and v2-produced artifacts:
// byte-equal where the contract is deterministic (labels, Secret type,
// caller metadata annotations, data keys) and semantically equal where
// issuance is random (certificate subjects, lifetimes, key usages).
func AssertArtifactsEqual(t *testing.T, cfg Config, v1Client, v2Client kubernetes.Interface) {
	t.Helper()
	assertSecretEqual(t, cfg, cfg.SignerName, "signer", v1Client, v2Client)
	assertConfigMapEqual(t, cfg, v1Client, v2Client)
	assertSecretEqual(t, cfg, cfg.TargetName, "target", v1Client, v2Client)
}

func assertSecretEqual(t *testing.T, cfg Config, name, kind string, v1Client, v2Client kubernetes.Interface) {
	t.Helper()
	v1Secret, err := v1Client.CoreV1().Secrets(cfg.Namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("v1 %s secret: %v", kind, err)
	}
	v2Secret, err := v2Client.CoreV1().Secrets(cfg.Namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("v2 %s secret: %v", kind, err)
	}

	if v1Secret.Type != v2Secret.Type {
		t.Errorf("%s secret type: v1 %q, v2 %q", kind, v1Secret.Type, v2Secret.Type)
	}
	if v1Secret.Labels[contract.ManagedCertificateTypeLabelName] != v2Secret.Labels[contract.ManagedCertificateTypeLabelName] {
		t.Errorf("%s secret label: v1 %q, v2 %q", kind, v1Secret.Labels, v2Secret.Labels)
	}
	for _, key := range []string{"openshift.io/owning-component", contract.CertificateTestNameAnnotation, contract.CertificateRefreshPeriodAnnotation} {
		if v1Secret.Annotations[key] != v2Secret.Annotations[key] {
			t.Errorf("%s secret annotation %q: v1 %q, v2 %q", kind, key, v1Secret.Annotations[key], v2Secret.Annotations[key])
		}
	}
	// The validity annotations embed the issuance instant; v1 and v2 issue
	// at slightly different real-time instants, so compare with tolerance.
	for _, key := range []string{contract.CertificateNotBeforeAnnotation, contract.CertificateNotAfterAnnotation} {
		v1Time, err1 := time.Parse(time.RFC3339, v1Secret.Annotations[key])
		v2Time, err2 := time.Parse(time.RFC3339, v2Secret.Annotations[key])
		if err1 != nil || err2 != nil {
			t.Errorf("%s secret annotation %q unparseable: v1 %q (err %v), v2 %q (err %v)", kind, key, v1Secret.Annotations[key], err1, v2Secret.Annotations[key], err2)
			continue
		}
		if diff := v1Time.Sub(v2Time); diff < -2*time.Second || diff > 2*time.Second {
			t.Errorf("%s secret annotation %q: v1 %q, v2 %q", kind, key, v1Secret.Annotations[key], v2Secret.Annotations[key])
		}
	}
	// The issuer annotation is the signer CN, which embeds the issuance unix
	// timestamp; v1 and v2 issue at slightly different instants, so compare
	// with the timestamp trimmed.
	if trimUnixSuffix(v1Secret.Annotations[contract.CertificateIssuer]) != trimUnixSuffix(v2Secret.Annotations[contract.CertificateIssuer]) {
		t.Errorf("%s secret issuer annotation: v1 %q, v2 %q", kind, v1Secret.Annotations[contract.CertificateIssuer], v2Secret.Annotations[contract.CertificateIssuer])
	}
	for _, key := range []string{contract.SecretCertKey, contract.SecretKeyKey} {
		if len(v1Secret.Data[key]) == 0 || len(v2Secret.Data[key]) == 0 {
			t.Errorf("%s secret data key %q missing on one side", kind, key)
		}
	}

	assertCertsEquivalent(t, kind, v1Secret.Data[contract.SecretCertKey], v2Secret.Data[contract.SecretCertKey])
}

func assertConfigMapEqual(t *testing.T, cfg Config, v1Client, v2Client kubernetes.Interface) {
	t.Helper()
	v1ConfigMap, err := v1Client.CoreV1().ConfigMaps(cfg.Namespace).Get(context.Background(), cfg.BundleName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("v1 bundle: %v", err)
	}
	v2ConfigMap, err := v2Client.CoreV1().ConfigMaps(cfg.Namespace).Get(context.Background(), cfg.BundleName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("v2 bundle: %v", err)
	}
	if v1ConfigMap.Labels[contract.ManagedCertificateTypeLabelName] != v2ConfigMap.Labels[contract.ManagedCertificateTypeLabelName] {
		t.Errorf("bundle label: v1 %q, v2 %q", v1ConfigMap.Labels, v2ConfigMap.Labels)
	}
	v1Certs, err := cert.ParseCertsPEM([]byte(v1ConfigMap.Data[contract.CABundleConfigMapKey]))
	if err != nil {
		t.Fatalf("v1 bundle parse: %v", err)
	}
	v2Certs, err := cert.ParseCertsPEM([]byte(v2ConfigMap.Data[contract.CABundleConfigMapKey]))
	if err != nil {
		t.Fatalf("v2 bundle parse: %v", err)
	}
	if len(v1Certs) != len(v2Certs) {
		t.Errorf("bundle length: v1 %d, v2 %d", len(v1Certs), len(v2Certs))
	}
}

// assertCertsEquivalent compares the semantic fields of the first
// certificate of each PEM: subject, key usage, lifetime length. Bytes,
// serials and signatures are random and excluded.
func assertCertsEquivalent(t *testing.T, kind string, v1PEM, v2PEM []byte) {
	t.Helper()
	v1Certs, err := cert.ParseCertsPEM(v1PEM)
	if err != nil {
		t.Fatalf("v1 %s cert parse: %v", kind, err)
	}
	v2Certs, err := cert.ParseCertsPEM(v2PEM)
	if err != nil {
		t.Fatalf("v2 %s cert parse: %v", kind, err)
	}
	if len(v1Certs) == 0 || len(v2Certs) == 0 {
		t.Fatalf("%s cert missing on one side", kind)
	}
	v1Cert, v2Cert := v1Certs[0], v2Certs[0]
	if v1Cert.Subject.CommonName != v2Cert.Subject.CommonName {
		// Subject CNs embed the issuance unix timestamp; compare the prefix.
		if trimUnixSuffix(v1Cert.Subject.CommonName) != trimUnixSuffix(v2Cert.Subject.CommonName) {
			t.Errorf("%s cert CN: v1 %q, v2 %q", kind, v1Cert.Subject.CommonName, v2Cert.Subject.CommonName)
		}
	}
	v1Validity := v1Cert.NotAfter.Sub(v1Cert.NotBefore)
	v2Validity := v2Cert.NotAfter.Sub(v2Cert.NotBefore)
	if diff := v1Validity - v2Validity; diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("%s cert validity: v1 %s, v2 %s", kind, v1Validity, v2Validity)
	}
	if fmt.Sprint(v1Cert.KeyUsage) != fmt.Sprint(v2Cert.KeyUsage) {
		t.Errorf("%s cert key usage: v1 %v, v2 %v", kind, v1Cert.KeyUsage, v2Cert.KeyUsage)
	}
}

// trimUnixSuffix removes a trailing "@<unix>" timestamp from a subject CN.
func trimUnixSuffix(cn string) string {
	for i := len(cn) - 1; i >= 0; i-- {
		if cn[i] == '@' {
			return cn[:i]
		}
	}
	return cn
}

// CopyCluster seeds a fresh fake client with the secrets and configmaps of
// the source client, so v1 and v2 (or two roles) can run against identical
// starting state.
func CopyCluster(t *testing.T, src kubernetes.Interface, namespace string, objects ...runtime.Object) *fake.Clientset {
	t.Helper()
	dst := fake.NewSimpleClientset(objects...)
	secrets, err := src.CoreV1().Secrets(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range secrets.Items {
		if err := dst.Tracker().Add(&secrets.Items[i]); err != nil {
			t.Fatal(err)
		}
	}
	configMaps, err := src.CoreV1().ConfigMaps(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range configMaps.Items {
		if err := dst.Tracker().Add(&configMaps.Items[i]); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// CountWrites returns the number of create and update actions a fake client
// performed.
func CountWrites(client *fake.Clientset) int {
	count := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "update" {
			count++
		}
	}
	return count
}

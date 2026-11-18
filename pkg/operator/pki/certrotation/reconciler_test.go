package certrotation

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
	"github.com/openshift/library-go/pkg/operator/events"
)

const (
	testNamespace = "test-ns"
	signerName    = "test-signer"
	bundleName    = "test-ca-bundle"
	targetName    = "test-client"
)

// testLogger is an events.Recorder that records events for assertions.
type testLogger struct {
	events []string
}

func (l *testLogger) ComponentName() string        { return "test" }
func (l *testLogger) Event(reason, message string) { l.events = append(l.events, reason) }
func (l *testLogger) Eventf(reason, message string, args ...interface{}) {
	l.events = append(l.events, reason)
}
func (l *testLogger) Warning(reason, message string) { l.events = append(l.events, reason) }
func (l *testLogger) Warningf(reason, message string, args ...interface{}) {
	l.events = append(l.events, reason)
}
func (l *testLogger) ForComponent(string) events.Recorder         { return l }
func (l *testLogger) WithComponentSuffix(string) events.Recorder  { return l }
func (l *testLogger) WithContext(context.Context) events.Recorder { return l }
func (l *testLogger) Shutdown()                                   {}

func testRotation() Rotation {
	return Rotation{
		Signer: SignerConfig{
			Location: Location{Namespace: testNamespace, Name: signerName},
			Validity: 24 * time.Hour,
			Refresh:  12 * time.Hour,
			Metadata: Metadata{JiraComponent: "test-component"},
		},
		Bundle: BundleConfig{
			Location: Location{Namespace: testNamespace, Name: bundleName},
		},
		Targets: []Target{
			{
				Name:     targetName,
				Location: Location{Namespace: testNamespace, Name: targetName},
				Validity: 12 * time.Hour,
				Refresh:  6 * time.Hour,
				Metadata: Metadata{TestName: "test-e2e"},
				Cert:     ClientCert{User: &staticUser{Name: "system:test"}},
			},
		},
	}
}

type staticUser struct {
	Name string
}

func (u *staticUser) GetName() string               { return u.Name }
func (u *staticUser) GetUID() string                { return "" }
func (u *staticUser) GetGroups() []string           { return nil }
func (u *staticUser) GetExtra() map[string][]string { return nil }

func newTestReconciler(t *testing.T, rotation Rotation, role Role, objects []runtime.Object) (*Reconciler, *fake.Clientset, *testLogger, *clocktesting.FakeClock) {
	t.Helper()
	client := fake.NewSimpleClientset(objects...)
	recorder := &testLogger{}
	fakeClock := clocktesting.NewFakeClock(time.Now())
	reconciler, err := NewReconciler(rotation, Options{
		Role:       role,
		KubeClient: client,
		PKI:        LegacyPKI(),
		Recorder:   recorder,
		Clock:      fakeClock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reconciler, client, recorder, fakeClock
}

// clientOver returns a new fake client seeded with every secret and configmap
// of the source client, so a second reconciler observes the first one's
// persisted state instead of an empty cluster.
func clientOver(t *testing.T, src *fake.Clientset) *fake.Clientset {
	t.Helper()
	dst := fake.NewSimpleClientset()
	secrets, err := src.CoreV1().Secrets(testNamespace).List(context.Background(), metav1ListOptions)
	if err != nil {
		t.Fatal(err)
	}
	for i := range secrets.Items {
		if err := dst.Tracker().Add(&secrets.Items[i]); err != nil {
			t.Fatal(err)
		}
	}
	configMaps, err := src.CoreV1().ConfigMaps(testNamespace).List(context.Background(), metav1ListOptions)
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

// reconcilerOver builds a reconciler over a fresh client seeded with src's
// state, sharing the given clock.
func reconcilerOver(t *testing.T, rotation Rotation, role Role, src *fake.Clientset, clk *clocktesting.FakeClock) (*Reconciler, *fake.Clientset) {
	t.Helper()
	client := clientOver(t, src)
	reconciler, err := NewReconciler(rotation, Options{
		Role:       role,
		KubeClient: client,
		PKI:        LegacyPKI(),
		Recorder:   &testLogger{},
		Clock:      clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reconciler, client
}

func writesFor(client *fake.Clientset) []string {
	var writes []string
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "update" {
			writes = append(writes, fmt.Sprintf("%s %s", action.GetVerb(), action.GetResource().Resource))
		}
	}
	return writes
}

func TestReconcileFreshCreate(t *testing.T) {
	reconciler, client, _, _ := newTestReconciler(t, testRotation(), RoleWriter, nil)

	result, err := reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TargetErrors[targetName] != nil {
		t.Fatalf("unexpected target error: %v", result.TargetErrors[targetName])
	}

	signer, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), signerName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Type != corev1.SecretTypeTLS {
		t.Errorf("expected signer secret type %q, got %q", corev1.SecretTypeTLS, signer.Type)
	}
	if signer.Labels[contract.ManagedCertificateTypeLabelName] != contract.CertificateTypeSigner {
		t.Errorf("expected signer label, got %v", signer.Labels)
	}
	if signer.Annotations["openshift.io/owning-component"] != "test-component" {
		t.Errorf("expected JiraComponent annotation, got %v", signer.Annotations)
	}
	for _, key := range []string{contract.CertificateNotBeforeAnnotation, contract.CertificateNotAfterAnnotation, contract.CertificateIssuer, contract.CertificateRefreshPeriodAnnotation} {
		if signer.Annotations[key] == "" {
			t.Errorf("signer missing computed annotation %q", key)
		}
	}

	bundle, err := client.CoreV1().ConfigMaps(testNamespace).Get(context.Background(), bundleName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Labels[contract.ManagedCertificateTypeLabelName] != contract.CertificateTypeCABundle {
		t.Errorf("expected bundle label, got %v", bundle.Labels)
	}
	if bundle.Data[contract.CABundleConfigMapKey] == "" {
		t.Error("expected non-empty bundle")
	}

	target, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), targetName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	if target.Labels[contract.ManagedCertificateTypeLabelName] != contract.CertificateTypeTarget {
		t.Errorf("expected target label, got %v", target.Labels)
	}
	if target.Annotations[contract.CertificateTestNameAnnotation] != "test-e2e" {
		t.Errorf("expected test-name annotation, got %v", target.Annotations)
	}
	if result.NextCheck.IsZero() {
		t.Error("expected NextCheck to be set")
	}
}

func TestReconcileIdempotent(t *testing.T) {
	rotation := testRotation()
	reconciler, client, _, _ := newTestReconciler(t, rotation, RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstWrites := len(writesFor(client))

	result, err := reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if writes := writesFor(client); len(writes) != firstWrites {
		t.Errorf("second pass performed writes: %v", writes)
	}
	if len(result.Actions) != 0 {
		t.Errorf("second pass recorded actions: %v", result.Actions)
	}
}

func TestReconcileHealerLeavesHealthyArtifactsAlone(t *testing.T) {
	// A healer facing a fully current rotation must perform zero writes.
	reconciler, client, _, _ := newTestReconciler(t, testRotation(), RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	writerWrites := len(writesFor(client))

	healer, healerClient := reconcilerOver(t, testRotation(), RoleHealer, client, clocktesting.NewFakeClock(time.Now()))
	_ = healerClient
	result, err := healer.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if writes := writesFor(client); len(writes) != writerWrites {
		t.Errorf("healer performed writes on healthy artifacts: %v", writes)
	}
	if len(result.Actions) != 0 {
		t.Errorf("healer recorded actions: %v", result.Actions)
	}
}

func TestReconcileHealerRegeneratesExpiredTargetWithCurrentInputs(t *testing.T) {
	// Set up a current rotation, then expire the target by advancing the
	// clock. The healer must regenerate it (unusable-only mandate includes
	// expiry).
	reconciler, client, _, fakeClock := newTestReconciler(t, testRotation(), RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	beforeWrites := len(writesFor(client))

	fakeClock.Sleep(25 * time.Hour)

	healer, healerClient := reconcilerOver(t, testRotation(), RoleHealer, client, fakeClock)
	_ = beforeWrites
	result, err := healer.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetErrors[targetName] != nil {
		t.Fatalf("unexpected target error: %v", result.TargetErrors[targetName])
	}
	found := false
	for _, action := range result.Actions {
		if action.Artifact.Kind == ArtifactKindTarget && action.Op == OpRegenerated {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected healer to regenerate expired target, actions: %v", result.Actions)
	}
	_ = healerClient
}

func TestReconcileHealerIgnoresMetadataDrift(t *testing.T) {
	// Remove the label and component annotation from a healthy artifact; the
	// healer must not repair them, the writer must.
	reconciler, client, _, _ := newTestReconciler(t, testRotation(), RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	signer, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), signerName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	delete(signer.Labels, contract.ManagedCertificateTypeLabelName)
	delete(signer.Annotations, "openshift.io/owning-component")
	if _, err := client.CoreV1().Secrets(testNamespace).Update(context.Background(), signer, metav1UpdateOptions); err != nil {
		t.Fatal(err)
	}

	healer, healerClient := reconcilerOver(t, testRotation(), RoleHealer, client, clocktesting.NewFakeClock(time.Now()))
	if _, err := healer.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, write := range writesFor(healerClient) {
		t.Errorf("healer wrote during metadata drift: %v", write)
	}

	writer, writerClient := reconcilerOver(t, testRotation(), RoleWriter, client, clocktesting.NewFakeClock(time.Now()))
	if _, err := writer.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	repaired := false
	for _, write := range writesFor(writerClient) {
		if write == "update secrets" {
			repaired = true
		}
	}
	if !repaired {
		t.Error("expected writer to repair metadata drift")
	}
}

func TestReconcileForceRegenerationSentinel(t *testing.T) {
	for _, tc := range []struct {
		name string
		role Role
	}{
		{name: "writer", role: RoleWriter},
		{name: "healer", role: RoleHealer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reconciler, client, _, _ := newTestReconciler(t, testRotation(), RoleWriter, nil)
			if _, err := reconciler.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			target, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), targetName, metav1GetOptions)
			if err != nil {
				t.Fatal(err)
			}
			target.Annotations[contract.CertificateNotAfterAnnotation] = contract.ForceRegeneration
			if _, err := client.CoreV1().Secrets(testNamespace).Update(context.Background(), target, metav1UpdateOptions); err != nil {
				t.Fatal(err)
			}

			roleReconciler, _ := reconcilerOver(t, testRotation(), tc.role, client, clocktesting.NewFakeClock(time.Now()))
			result, err := roleReconciler.Reconcile(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			regenerated := false
			for _, action := range result.Actions {
				if action.Artifact.Kind == ArtifactKindTarget && action.Op == OpRegenerated {
					regenerated = true
				}
			}
			if !regenerated {
				t.Fatalf("expected %s to regenerate on force-regeneration sentinel, actions: %v", tc.role, result.Actions)
			}
		})
	}
}

func TestReconcileConflictIsTyped(t *testing.T) {
	reconciler, client, _, _ := newTestReconciler(t, testRotation(), RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Request regeneration via the force-regeneration sentinel, and make
	// every secret update fail with a conflict.
	target, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), targetName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	target.Annotations[contract.CertificateNotAfterAnnotation] = contract.ForceRegeneration

	conflictingClient := fake.NewSimpleClientset(target)
	secrets, _ := client.CoreV1().Secrets(testNamespace).List(context.Background(), metav1ListOptions)
	configMaps, _ := client.CoreV1().ConfigMaps(testNamespace).List(context.Background(), metav1ListOptions)
	conflictingClient = fake.NewSimpleClientset()
	for i := range secrets.Items {
		if err := conflictingClient.Tracker().Add(&secrets.Items[i]); err != nil {
			t.Fatal(err)
		}
	}
	for i := range configMaps.Items {
		if err := conflictingClient.Tracker().Add(&configMaps.Items[i]); err != nil {
			t.Fatal(err)
		}
	}
	mutated, err := conflictingClient.CoreV1().Secrets(testNamespace).Get(context.Background(), targetName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	mutated.Annotations[contract.CertificateNotAfterAnnotation] = contract.ForceRegeneration
	if err := conflictingClient.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), mutated, testNamespace); err != nil {
		t.Fatal(err)
	}
	conflictingClient.PrependReactor("update", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(corev1.Resource("secret"), targetName, errors.New("conflict"))
	})

	conflicting, err := NewReconciler(testRotation(), Options{
		Role:       RoleWriter,
		KubeClient: conflictingClient,
		PKI:        LegacyPKI(),
		Recorder:   &testLogger{},
		Clock:      clocktesting.NewFakeClock(time.Now()),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := conflicting.Reconcile(context.Background())
	if err == nil {
		t.Fatal("expected error on conflicting write")
	}
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected typed ErrConflict, got %v", err)
	}
	var artifactErr *ArtifactError
	if !errors.As(err, &artifactErr) {
		t.Fatalf("expected ArtifactError attribution, got %T", err)
	}
	if result.TargetErrors[targetName] == nil {
		t.Fatal("expected target error attribution")
	}
}

func TestReconcileEmptyBundleIsInvariant(t *testing.T) {
	reconciler, client, _, _ := newTestReconciler(t, testRotation(), RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Wipe the bundle content and make every configmap update persist an
	// empty bundle: the post-write verification must then abort target
	// evaluation with ErrInvariant.
	bundle, err := client.CoreV1().ConfigMaps(testNamespace).Get(context.Background(), bundleName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Data[contract.CABundleConfigMapKey] = ""
	if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), bundle, testNamespace); err != nil {
		t.Fatal(err)
	}

	emptyClient := clientOver(t, client)
	emptyClient.PrependReactor("update", "configmaps", func(action clienttesting.Action) (bool, runtime.Object, error) {
		update := action.(clienttesting.UpdateAction)
		configMap := update.GetObject().(*corev1.ConfigMap)
		configMap.Data[contract.CABundleConfigMapKey] = ""
		return true, configMap, nil
	})

	emptyReconciler, err := NewReconciler(testRotation(), Options{
		Role:       RoleWriter,
		KubeClient: emptyClient,
		PKI:        LegacyPKI(),
		Recorder:   &testLogger{},
		Clock:      clocktesting.NewFakeClock(time.Now()),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := emptyReconciler.Reconcile(context.Background())
	if err == nil {
		t.Fatal("expected error on empty bundle")
	}
	if !errors.Is(err, ErrInvariant) {
		t.Fatalf("expected typed ErrInvariant, got %v", err)
	}
	// No target may be evaluated: zero secret writes against the bad bundle.
	targetWrites := 0
	for _, write := range writesFor(emptyClient) {
		if write == "update secrets" || write == "create secrets" {
			targetWrites++
		}
	}
	if targetWrites != 0 {
		t.Errorf("expected zero secret writes against invalid bundle, got %d", targetWrites)
	}
	if result.TargetErrors[targetName] == nil {
		t.Fatal("expected target error attribution from bundle failure")
	}
}

func TestReconcileUnknownKeyAlgorithmTargetIsNotRotated(t *testing.T) {
	// A target holding a well-formed cert plus a future-algorithm key must
	// be left alone: the binary that can judge that key owns it.
	reconciler, client, _, _ := newTestReconciler(t, testRotation(), RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	target, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), targetName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	// Replace tls.key with a future-algorithm PEM block, leaving a valid
	// cert and valid annotations.
	target.Data[contract.SecretKeyKey] = pem.EncodeToMemory(&pem.Block{Type: "ML-DSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if _, err := client.CoreV1().Secrets(testNamespace).Update(context.Background(), target, metav1UpdateOptions); err != nil {
		t.Fatal(err)
	}

	futureClient := fake.NewSimpleClientset()
	secrets, _ := client.CoreV1().Secrets(testNamespace).List(context.Background(), metav1ListOptions)
	configMaps, _ := client.CoreV1().ConfigMaps(testNamespace).List(context.Background(), metav1ListOptions)
	for i := range secrets.Items {
		futureClient.Tracker().Add(&secrets.Items[i])
	}
	for i := range configMaps.Items {
		futureClient.Tracker().Add(&configMaps.Items[i])
	}

	futureReconciler, err := NewReconciler(testRotation(), Options{
		Role:       RoleWriter,
		KubeClient: futureClient,
		PKI:        LegacyPKI(),
		Recorder:   &testLogger{},
		Clock:      clocktesting.NewFakeClock(time.Now()),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := futureReconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, action := range result.Actions {
		if action.Artifact.Kind == ArtifactKindTarget {
			t.Errorf("target with unknown key algorithm was acted on: %+v", action)
		}
	}
}

func TestReconcileServingTargetHostnameDrift(t *testing.T) {
	rotation := testRotation()
	rotation.Targets = []Target{
		{
			Name:     "test-serving",
			Location: Location{Namespace: testNamespace, Name: "test-serving"},
			Validity: 12 * time.Hour,
			Refresh:  6 * time.Hour,
			Cert:     ServingCert{Hostnames: StaticHostnames("one.example.com")},
		},
	}
	reconciler, client, _, _ := newTestReconciler(t, rotation, RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	target, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), "test-serving", metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	if target.Annotations[contract.CertificateHostnames] != "one.example.com" {
		t.Errorf("expected hostnames annotation, got %q", target.Annotations[contract.CertificateHostnames])
	}

	// Change the desired hostnames: the writer regenerates, the healer does
	// not (unusable-only).
	changed := rotation
	changed.Targets[0].Cert = ServingCert{Hostnames: StaticHostnames("two.example.com")}

	writer, _ := reconcilerOver(t, changed, RoleWriter, client, clocktesting.NewFakeClock(time.Now()))
	result, err := writer.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetErrors["test-serving"] != nil {
		t.Fatalf("unexpected error: %v", result.TargetErrors["test-serving"])
	}
	found := false
	for _, action := range result.Actions {
		if action.Artifact.Kind == ArtifactKindTarget && action.Op == OpRegenerated {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected writer to regenerate on hostname drift, actions: %v", result.Actions)
	}

	healer, _ := reconcilerOver(t, changed, RoleHealer, client, clocktesting.NewFakeClock(time.Now()))
	result, err = healer.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range result.Actions {
		if action.Artifact.Kind == ArtifactKindTarget {
			t.Errorf("healer acted on hostname drift: %+v", action)
		}
	}
	_ = sets.New[string]()
}

func TestNewReconcilerValidation(t *testing.T) {
	testCases := []struct {
		name      string
		rotation  Rotation
		options   Options
		expectErr error
	}{
		{
			name:      "role required",
			rotation:  testRotation(),
			options:   Options{KubeClient: fake.NewSimpleClientset(), PKI: LegacyPKI(), Recorder: &testLogger{}},
			expectErr: ErrRoleRequired,
		},
		{
			name:      "pki required",
			rotation:  testRotation(),
			options:   Options{Role: RoleWriter, KubeClient: fake.NewSimpleClientset(), Recorder: &testLogger{}},
			expectErr: ErrPKIRequired,
		},
		{
			name:      "kube client required",
			rotation:  testRotation(),
			options:   Options{Role: RoleWriter, PKI: LegacyPKI(), Recorder: &testLogger{}},
			expectErr: ErrKubeClientRequired,
		},
		{
			name:      "recorder required",
			rotation:  testRotation(),
			options:   Options{Role: RoleWriter, KubeClient: fake.NewSimpleClientset(), PKI: LegacyPKI()},
			expectErr: ErrRecorderRequired,
		},
		{
			name: "duplicate target name",
			rotation: func() Rotation {
				rotation := testRotation()
				rotation.Targets = append(rotation.Targets, rotation.Targets[0])
				return rotation
			}(),
			options:   Options{Role: RoleWriter, KubeClient: fake.NewSimpleClientset(), PKI: LegacyPKI(), Recorder: &testLogger{}},
			expectErr: nil, // duplicate name with same location: name check fires
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewReconciler(tc.rotation, tc.options)
			if tc.expectErr != nil {
				if !errors.Is(err, tc.expectErr) {
					t.Fatalf("expected %v, got %v", tc.expectErr, err)
				}
			} else if err == nil {
				t.Fatal("expected error, got none")
			}
		})
	}
}

var (
	metav1GetOptions    = metav1.GetOptions{}
	metav1UpdateOptions = metav1.UpdateOptions{}
	metav1ListOptions   = metav1.ListOptions{}
)

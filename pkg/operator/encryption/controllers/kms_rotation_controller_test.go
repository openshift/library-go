package controllers

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clocktesting "k8s.io/utils/clock/testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/events"
)

type fakeConvergedKEKReporter struct {
	kekID     string
	converged bool
}

func (f *fakeConvergedKEKReporter) ConvergedKekID() (string, bool) {
	return f.kekID, f.converged
}

func TestKMSRotationControllerAnnotationMutators(t *testing.T) {
	t.Run("bootstrap sets equal target and migrated", func(t *testing.T) {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
		changed, err := setKekBootstrapAnnotations(s, "kek-1")
		if err != nil || !changed {
			t.Fatalf("setKekBootstrapAnnotations() changed=%v err=%v", changed, err)
		}
		if s.Annotations[secrets.EncryptionSecretTargetKekID] != "kek-1" || s.Annotations[secrets.EncryptionSecretMigratedKekID] != "kek-1" {
			t.Fatalf("unexpected annotations: %#v", s.Annotations)
		}
	})

	t.Run("convergence clock starts on new candidate", func(t *testing.T) {
		now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			secrets.EncryptionSecretTargetKekID: "kek-old",
		}}}
		changed, err := setKekConvergenceClock(s, "kek-new", now)
		if err != nil || !changed {
			t.Fatalf("setKekConvergenceClock() changed=%v err=%v", changed, err)
		}
		if s.Annotations[secrets.EncryptionSecretKekConvergedID] != "kek-new" {
			t.Fatalf("unexpected converged id: %q", s.Annotations[secrets.EncryptionSecretKekConvergedID])
		}
		if s.Annotations[secrets.EncryptionSecretKekConvergedAt] != now.Format(time.RFC3339) {
			t.Fatalf("unexpected converged at: %q", s.Annotations[secrets.EncryptionSecretKekConvergedAt])
		}
	})

	t.Run("promote target after convergence delay", func(t *testing.T) {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			secrets.EncryptionSecretTargetKekID:    "kek-old",
			secrets.EncryptionSecretKekConvergedID:   "kek-new",
			secrets.EncryptionSecretKekConvergedAt:   time.Now().Format(time.RFC3339),
			secrets.EncryptionSecretMigratedKekID:    "kek-old",
		}}}
		changed, err := promoteConvergedKekToTarget(s, "kek-new")
		if err != nil || !changed {
			t.Fatalf("promoteConvergedKekToTarget() changed=%v err=%v", changed, err)
		}
		if s.Annotations[secrets.EncryptionSecretTargetKekID] != "kek-new" {
			t.Fatalf("target = %q", s.Annotations[secrets.EncryptionSecretTargetKekID])
		}
		if _, ok := s.Annotations[secrets.EncryptionSecretKekConvergedID]; ok {
			t.Fatalf("expected converged id cleared")
		}
	})

	t.Run("clear convergence annotations", func(t *testing.T) {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			secrets.EncryptionSecretKekConvergedID: "kek-new",
			secrets.EncryptionSecretKekConvergedAt: time.Now().Format(time.RFC3339),
		}}}
		changed, err := clearKekConvergenceAnnotations(s)
		if err != nil || !changed {
			t.Fatalf("clearKekConvergenceAnnotations() changed=%v err=%v", changed, err)
		}
		if len(s.Annotations) != 0 {
			t.Fatalf("expected annotations cleared, got %#v", s.Annotations)
		}
	})
}

func TestKMSRotationControllerReconcileKekAnnotations(t *testing.T) {
	grs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

	t.Run("bootstrap after initial migration", func(t *testing.T) {
		secret := encryptiontesting.CreateEncryptionKeySecretWithKMSPluginConfig("kms", grs, 1)
		secret.Annotations[secrets.EncryptionSecretMigratedTimestamp] = now.Format(time.RFC3339)
		c := &kmsRotationController{
			now: func() time.Time { return now },
		}
		writeKey, err := secrets.ToKeyState(secret)
		if err != nil {
			t.Fatal(err)
		}
		fakeClient := fake.NewSimpleClientset(secret)
		c.secretClient = fakeClient.CoreV1()
		eventRecorder := events.NewRecorder(fakeClient.CoreV1().Events("operator"), "test-kms-rotation", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(now))
		syncCtx := factory.NewSyncContext("test", eventRecorder)
		if err := c.reconcileKekAnnotations(context.Background(), syncCtx, secret, writeKey, "kek-1", grs); err != nil {
			t.Fatal(err)
		}
		updated, err := fakeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if updated.Annotations[secrets.EncryptionSecretTargetKekID] != "kek-1" || updated.Annotations[secrets.EncryptionSecretMigratedKekID] != "kek-1" {
			t.Fatalf("unexpected annotations: %#v", updated.Annotations)
		}
	})

	t.Run("promote after convergence delay", func(t *testing.T) {
		secret := encryptiontesting.CreateEncryptionKeySecretWithKMSPluginConfig("kms", grs, 1)
		secret.Annotations[secrets.EncryptionSecretTargetKekID] = "kek-old"
		secret.Annotations[secrets.EncryptionSecretMigratedKekID] = "kek-old"
		secret.Annotations[secrets.EncryptionSecretKekConvergedID] = "kek-new"
		secret.Annotations[secrets.EncryptionSecretKekConvergedAt] = now.Add(-secrets.KekConvergenceDelay).Format(time.RFC3339)
		c := &kmsRotationController{
			now: func() time.Time { return now },
		}
		writeKey, err := secrets.ToKeyState(secret)
		if err != nil {
			t.Fatal(err)
		}
		fakeClient := fake.NewSimpleClientset(secret)
		c.secretClient = fakeClient.CoreV1()
		eventRecorder := events.NewRecorder(fakeClient.CoreV1().Events("operator"), "test-kms-rotation", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(now))
		syncCtx := factory.NewSyncContext("test", eventRecorder)
		if err := c.reconcileKekAnnotations(context.Background(), syncCtx, secret, writeKey, "kek-new", grs); err != nil {
			t.Fatal(err)
		}
		updated, err := fakeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if updated.Annotations[secrets.EncryptionSecretTargetKekID] != "kek-new" {
			t.Fatalf("target = %q", updated.Annotations[secrets.EncryptionSecretTargetKekID])
		}
	})
}

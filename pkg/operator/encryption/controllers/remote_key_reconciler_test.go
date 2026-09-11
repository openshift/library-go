package controllers

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func TestReconcileRemoteKeyBootstrap(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "openshift-config-managed",
			Name:        "encryption-key-test-3",
			Annotations: map[string]string{},
		},
	}
	secrets.ApplyRemoteKeyAnnotations(secret.Annotations, state.RemoteKeyState{TargetRemoteKeyID: "remote-old"})
	client := fake.NewSimpleClientset(secret)

	writeKey := state.KeyState{
		Key:  apiserverconfigv1.Key{Name: "3", Secret: "c2VjcmV0"},
		Mode: state.KMS,
		Migrated: state.MigrationState{
			Resources: []schema.GroupResource{{Resource: "secrets"}},
		},
		KMS: &state.KMSState{
			RemoteKey: state.RemoteKeyState{TargetRemoteKeyID: "remote-old"},
		},
	}
	desired := map[schema.GroupResource]state.GroupResourceState{
		{Resource: "secrets"}: {WriteKey: writeKey},
	}
	status := &operatorv1.KMSEncryptionStatus{
		HealthReports: []operatorv1.KMSPluginHealthReport{
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "3", RemoteKeyID: "remote-new"},
		},
	}

	err := reconcileRemoteKeyRotation(context.Background(), client.CoreV1(), "test", []schema.GroupResource{{Resource: "secrets"}}, desired, status, clocktesting.NewFakeClock(time.Now()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := client.CoreV1().Secrets("openshift-config-managed").Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	rk, err := secrets.ReadRemoteKeyAnnotations(updated)
	if err != nil {
		t.Fatalf("read remote key annotations: %v", err)
	}
	if rk.MigratedRemoteKeyID != "remote-old" {
		t.Fatalf("expected bootstrap migrated-remote-key-id=remote-old, got %q", rk.MigratedRemoteKeyID)
	}
}

func TestReconcileRemoteKeyPromotion(t *testing.T) {
	start := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "openshift-config-managed",
			Name:        "encryption-key-test-3",
			Annotations: map[string]string{},
		},
	}
	secrets.ApplyRemoteKeyAnnotations(secret.Annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   "remote-old",
		MigratedRemoteKeyID: "remote-old",
		ConvergedID:         "remote-new",
		ConvergedAt:         start,
	})
	client := fake.NewSimpleClientset(secret)

	writeKey := state.KeyState{
		Key:  apiserverconfigv1.Key{Name: "3", Secret: "c2VjcmV0"},
		Mode: state.KMS,
		Migrated: state.MigrationState{
			Resources: []schema.GroupResource{{Resource: "secrets"}},
		},
		KMS: &state.KMSState{
			RemoteKey: state.RemoteKeyState{
				TargetRemoteKeyID:   "remote-old",
				MigratedRemoteKeyID: "remote-old",
				ConvergedID:         "remote-new",
				ConvergedAt:         start,
			},
		},
	}
	desired := map[schema.GroupResource]state.GroupResourceState{
		{Resource: "secrets"}: {WriteKey: writeKey},
	}
	status := &operatorv1.KMSEncryptionStatus{
		HealthReports: []operatorv1.KMSPluginHealthReport{
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "3", RemoteKeyID: "remote-new"},
		},
	}

	err := reconcileRemoteKeyRotation(context.Background(), client.CoreV1(), "test", []schema.GroupResource{{Resource: "secrets"}}, desired, status, clocktesting.NewFakeClock(start.Add(6*time.Minute)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := client.CoreV1().Secrets("openshift-config-managed").Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	rk, err := secrets.ReadRemoteKeyAnnotations(updated)
	if err != nil {
		t.Fatalf("read remote key annotations: %v", err)
	}
	if rk.TargetRemoteKeyID != "remote-new" {
		t.Fatalf("expected promoted target-remote-key-id=remote-new, got %q", rk.TargetRemoteKeyID)
	}
	if len(rk.ConvergedID) > 0 || !rk.ConvergedAt.IsZero() {
		t.Fatal("expected convergence annotations to be cleared after promotion")
	}
}

func TestReconcileRemoteKeyIgnoresOtherKeyIDReports(t *testing.T) {
	start := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "openshift-config-managed",
			Name:        "encryption-key-test-3",
			Annotations: map[string]string{},
		},
	}
	secrets.ApplyRemoteKeyAnnotations(secret.Annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   "remote-old",
		MigratedRemoteKeyID: "remote-old",
		ConvergedID:         "remote-new",
		ConvergedAt:         start,
	})
	client := fake.NewSimpleClientset(secret)

	writeKey := state.KeyState{
		Key:  apiserverconfigv1.Key{Name: "3", Secret: "c2VjcmV0"},
		Mode: state.KMS,
		Migrated: state.MigrationState{
			Resources: []schema.GroupResource{{Resource: "secrets"}},
		},
		KMS: &state.KMSState{
			RemoteKey: state.RemoteKeyState{
				TargetRemoteKeyID:   "remote-old",
				MigratedRemoteKeyID: "remote-old",
				ConvergedID:         "remote-new",
				ConvergedAt:         start,
			},
		},
	}
	desired := map[schema.GroupResource]state.GroupResourceState{
		{Resource: "secrets"}: {WriteKey: writeKey},
	}
	status := &operatorv1.KMSEncryptionStatus{
		HealthReports: []operatorv1.KMSPluginHealthReport{
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "2", RemoteKeyID: "remote-old"},
		},
	}

	err := reconcileRemoteKeyRotation(context.Background(), client.CoreV1(), "test", []schema.GroupResource{{Resource: "secrets"}}, desired, status, clocktesting.NewFakeClock(start.Add(6*time.Minute)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := client.CoreV1().Secrets("openshift-config-managed").Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	rk, err := secrets.ReadRemoteKeyAnnotations(updated)
	if err != nil {
		t.Fatalf("read remote key annotations: %v", err)
	}
	if rk.TargetRemoteKeyID != "remote-new" {
		t.Fatalf("expected promoted target-remote-key-id=remote-new, got %q", rk.TargetRemoteKeyID)
	}
}

func TestReconcileRemoteKeyDeferredPromotion(t *testing.T) {
	start := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "openshift-config-managed",
			Name:        "encryption-key-test-3",
			Annotations: map[string]string{},
		},
	}
	secrets.ApplyRemoteKeyAnnotations(secret.Annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   "remote-a",
		MigratedRemoteKeyID: "remote-old",
		ConvergedID:         "remote-b",
		ConvergedAt:         start,
	})
	client := fake.NewSimpleClientset(secret)

	writeKey := state.KeyState{
		Key:  apiserverconfigv1.Key{Name: "3", Secret: "c2VjcmV0"},
		Mode: state.KMS,
		Migrated: state.MigrationState{
			Resources: []schema.GroupResource{{Resource: "secrets"}},
		},
		KMS: &state.KMSState{
			RemoteKey: state.RemoteKeyState{
				TargetRemoteKeyID:   "remote-a",
				MigratedRemoteKeyID: "remote-old",
				ConvergedID:         "remote-b",
				ConvergedAt:         start,
			},
		},
	}
	desired := map[schema.GroupResource]state.GroupResourceState{
		{Resource: "secrets"}: {WriteKey: writeKey},
	}
	status := &operatorv1.KMSEncryptionStatus{
		HealthReports: []operatorv1.KMSPluginHealthReport{
			{KeyID: "3", RemoteKeyID: "remote-b"},
			{KeyID: "3", RemoteKeyID: "remote-b"},
		},
	}

	err := reconcileRemoteKeyRotation(context.Background(), client.CoreV1(), "test", []schema.GroupResource{{Resource: "secrets"}}, desired, status, clocktesting.NewFakeClock(start.Add(6*time.Minute)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := client.CoreV1().Secrets("openshift-config-managed").Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	rk, err := secrets.ReadRemoteKeyAnnotations(updated)
	if err != nil {
		t.Fatalf("read remote key annotations: %v", err)
	}
	if rk.TargetRemoteKeyID != "remote-a" {
		t.Fatalf("expected target to remain remote-a during in-flight migration, got %q", rk.TargetRemoteKeyID)
	}
}

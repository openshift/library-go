package preflight

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/pluginlifecycle"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacclientv1 "k8s.io/client-go/kubernetes/typed/rbac/v1"

	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	preflightPodName                    = "kms-preflight"
	preflightCheckContainerName         = "kms-preflight-check"
	preflightEncryptionConfigSecretName = "kms-preflight-encryption-config"
	preflightRBACName                   = "kms-preflight"
	preflightAppLabel                   = "openshift-kms-preflight"
)

var (
	labels = map[string]string{
		"app": preflightAppLabel,
	}
)

// PodPreflightDeployer creates a one-shot pod to run the preflight checker as a command,
// with the plugin injected as a sidecar container.
type PodPreflightDeployer struct {
	namespace string
	// It uses direct API client instead of a lister to be consistent with what
	// encryption controllers/components actually use.
	// In addition to that running the preflight check is not a very frequent operation.
	coreClient      corev1client.CoreV1Interface
	rbacClient      rbacclientv1.RbacV1Interface
	eventRecorder   events.Recorder
	operatorImage   string
	operatorCommand []string
	kmsCallTimeout  time.Duration
}

func (d *PodPreflightDeployer) Deploy(ctx context.Context, configHash string, encryptionConfigSecret *corev1.Secret) error {
	if configHash == "" {
		return fmt.Errorf("configHash is empty")
	}
	if encryptionConfigSecret == nil {
		return fmt.Errorf("encryptionConfigSecret is nil")
	}

	// ensure that there is nothing left over from previous runs
	if err := d.Cleanup(ctx); err != nil {
		return fmt.Errorf("failed to clean up existing preflight resources: %w", err)
	}

	encryptionConfigSecret = encryptionConfigSecret.DeepCopy()
	// rewrite the entire ObjectMeta to avoid copying resource versions or managed fields
	encryptionConfigSecret.ObjectMeta = metav1.ObjectMeta{Namespace: d.namespace, Name: preflightEncryptionConfigSecretName, Labels: labels}
	_, err := d.coreClient.Secrets(d.namespace).Create(ctx, encryptionConfigSecret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create preflight encryption config secret: %w", err)
	}

	pod, err := generatePodTemplate(
		preflightPodName,
		d.namespace,
		configHash,
		d.operatorImage,
		d.operatorCommand,
		d.kmsCallTimeout,
	)
	if err != nil {
		return fmt.Errorf("failed to generate preflight pod template: %w", err)
	}

	err = pluginlifecycle.NewKMSPluginBuilder().
		WithSecretRequired().
		FromEncryptionConfigSecret(d.namespace, preflightEncryptionConfigSecretName, d.coreClient).
		Apply(ctx, &pod.Spec, preflightCheckContainerName)
	if err != nil {
		return fmt.Errorf("failed to apply preflight plugin: %w", err)
	}

	// RBAC is applied but not cleaned up: the rules change rarely (and apply updates them
	// when they do), and the cost of leaving the service account, role, and role binding
	// in the namespace is negligible.
	if err = d.applyPreflightRBAC(ctx); err != nil {
		return fmt.Errorf("failed to apply preflight RBAC: %w", err)
	}

	_, err = d.coreClient.Pods(d.namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create preflight pod: %w", err)
	}

	return nil
}

func (d *PodPreflightDeployer) Status(ctx context.Context) (corev1.PodStatus, error) {
	// preflight status checks are not very frequent, so we use the live client instead of a cached lister
	pod, err := d.coreClient.Pods(d.namespace).Get(ctx, preflightPodName, metav1.GetOptions{})
	if err != nil {
		return corev1.PodStatus{}, fmt.Errorf("failed to get pod for preflight %s/%s: %w", d.namespace, preflightPodName, err)
	}

	return pod.Status, nil
}

func (d *PodPreflightDeployer) Cleanup(ctx context.Context) error {
	// See Deploy: preflight RBAC is intentionally not deleted here.
	var errs []error

	err := d.coreClient.Pods(d.namespace).Delete(ctx, preflightPodName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete pod %s/%s: %w", d.namespace, preflightPodName, err))
	}

	err = d.coreClient.Secrets(d.namespace).Delete(ctx, preflightEncryptionConfigSecretName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete secret %s/%s: %w", d.namespace, preflightEncryptionConfigSecretName, err))
	}

	return errors.Join(errs...)
}

func (d *PodPreflightDeployer) applyPreflightRBAC(ctx context.Context) error {

	_, _, err := resourceapply.ApplyServiceAccount(ctx, d.coreClient, d.eventRecorder, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightRBACName,
			Namespace: d.namespace,
			Labels:    labels,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to apply preflight service account: %w", err)
	}

	_, _, err = resourceapply.ApplyRole(ctx, d.rbacClient, d.eventRecorder, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightRBACName,
			Namespace: d.namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"update"},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to apply preflight role: %w", err)
	}

	_, _, err = resourceapply.ApplyRoleBinding(ctx, d.rbacClient, d.eventRecorder, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightRBACName,
			Namespace: d.namespace,
			Labels:    labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     preflightRBACName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      preflightRBACName,
				Namespace: d.namespace,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to apply preflight role binding: %w", err)
	}

	return nil
}

func NewPodPreflightDeployer(
	namespace string,
	coreClient corev1client.CoreV1Interface,
	rbacClient rbacclientv1.RbacV1Interface,
	eventRecorder events.Recorder,
	operatorImage string,
	operatorCommand []string,
	kmsCallTimeout time.Duration,
) *PodPreflightDeployer {
	return &PodPreflightDeployer{
		namespace:       namespace,
		coreClient:      coreClient,
		rbacClient:      rbacClient,
		eventRecorder:   eventRecorder,
		operatorImage:   operatorImage,
		operatorCommand: operatorCommand,
		kmsCallTimeout:  kmsCallTimeout,
	}
}

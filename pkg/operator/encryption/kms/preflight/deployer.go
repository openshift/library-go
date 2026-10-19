package preflight

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/pluginlifecycle"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	batchv1client "k8s.io/client-go/kubernetes/typed/batch/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacclientv1 "k8s.io/client-go/kubernetes/typed/rbac/v1"
)

const (
	// PodName is the fixed name of the preflight Job (and historically the
	// fixed-name Pod). Job pods use generated names; select them by app label.
	PodName = "kms-preflight"
	// CheckContainerName is the container that runs the preflight checker command.
	CheckContainerName = "kms-preflight-check"
	// EncryptionConfigSecretName is the secret Deploy creates for the preflight pod.
	EncryptionConfigSecretName = "kms-preflight-encryption-config"

	// configHashAnnotation records, on the preflight Job, the config hash it was
	// deployed for. It is set at render time (see assets/kms-preflight-pod.yaml,
	// copied onto the Job) and read back by Status so the controller can detect a
	// stale workload even when no pod ever ran.
	configHashAnnotation = "encryption.apiserver.operator.openshift.io/kms-preflight-config-hash"

	preflightRBACName = "kms-preflight"
	// PreflightAppLabel is stamped on the Job and its pods (network AllowLists, e2e).
	PreflightAppLabel = "openshift-kms-preflight"

	// Bound Job retries for SNO API blips / pod disappearance. A reported KMS
	// verdict exits 0 so the Job Completes and stops retrying.
	preflightJobBackoffLimit          = int32(6)
	preflightJobActiveDeadlineSeconds = int64(20 * 60)
)

var (
	labels = map[string]string{
		"app": PreflightAppLabel,
	}

	propagationBackground = metav1.DeletePropagationBackground
)

// PodPreflightDeployer creates a Job whose pod template runs the preflight
// checker as a command, with the plugin injected as a sidecar container.
type PodPreflightDeployer struct {
	namespace string
	// It uses direct API client instead of a lister to be consistent with what
	// encryption controllers/components actually use.
	// In addition to that running the preflight check is not a very frequent operation.
	coreClient      corev1client.CoreV1Interface
	rbacClient      rbacclientv1.RbacV1Interface
	batchClient     batchv1client.BatchV1Interface
	eventRecorder   events.Recorder
	operatorImage   string
	operatorCommand []string
	kmsCallTimeout  time.Duration
	// virtualStaticPod will use settings like a static pod, e.g. hostNetwork=True, but run as a normal pod
	virtualStaticPod bool
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
	encryptionConfigSecret.ObjectMeta = metav1.ObjectMeta{Namespace: d.namespace, Name: EncryptionConfigSecretName, Labels: labels}
	_, err := d.coreClient.Secrets(d.namespace).Create(ctx, encryptionConfigSecret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create preflight encryption config secret: %w", err)
	}

	pod, err := renderPreflightPodTemplate(
		PodName,
		d.namespace,
		configHash,
		d.operatorImage,
		d.operatorCommand,
		d.kmsCallTimeout,
		d.virtualStaticPod,
	)
	if err != nil {
		return fmt.Errorf("failed to generate preflight pod template: %w", err)
	}

	err = pluginlifecycle.NewKMSPluginBuilder().
		WithSecretRequired().
		WithPreflightChecker().
		FromEncryptionConfigSecret(d.namespace, EncryptionConfigSecretName, d.coreClient).
		Apply(ctx, &pod.Spec, CheckContainerName)
	if err != nil {
		return fmt.Errorf("failed to apply preflight plugin: %w", err)
	}

	// RBAC is applied but not cleaned up: the rules change rarely (and apply updates them
	// when they do), and the cost of leaving the service account, role, and role binding
	// in the namespace is negligible.
	if err = d.applyPreflightRBAC(ctx); err != nil {
		return fmt.Errorf("failed to apply preflight RBAC: %w", err)
	}

	backoffLimit := preflightJobBackoffLimit
	activeDeadlineSeconds := preflightJobActiveDeadlineSeconds
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        PodName,
			Namespace:   d.namespace,
			Labels:      labels,
			Annotations: pod.Annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          &backoffLimit,
			ActiveDeadlineSeconds: &activeDeadlineSeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels,
					Annotations: pod.Annotations,
				},
				Spec: pod.Spec,
			},
		},
	}

	_, err = d.batchClient.Jobs(d.namespace).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create preflight job: %w", err)
	}

	return nil
}

// Status returns the config hash the current preflight Job was deployed for
// (from its configHashAnnotation) along with a PodStatus projected from the Job.
// The hash lets the controller detect a stale workload regardless of whether a
// pod ever ran. Custom KMS check conditions on the Job survive pod GC.
func (d *PodPreflightDeployer) Status(ctx context.Context) (string, corev1.PodStatus, error) {
	// preflight status checks are not very frequent, so we use the live client instead of a cached lister
	job, err := d.batchClient.Jobs(d.namespace).Get(ctx, PodName, metav1.GetOptions{})
	if err != nil {
		return "", corev1.PodStatus{}, fmt.Errorf("failed to get job for preflight %s/%s: %w", d.namespace, PodName, err)
	}

	return job.Annotations[configHashAnnotation], projectJobToPodStatus(job), nil
}

func (d *PodPreflightDeployer) Cleanup(ctx context.Context) error {
	// TODO: Cleanup is called on every controller sync, including syncs where
	// Deploy was never called. Track whether resources were deployed and make
	// this a no-op when there is nothing to remove.
	// See Deploy: preflight RBAC is intentionally not deleted here.
	var errs []error

	err := d.batchClient.Jobs(d.namespace).Delete(ctx, PodName, metav1.DeleteOptions{
		PropagationPolicy: &propagationBackground,
	})
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete job %s/%s: %w", d.namespace, PodName, err))
	}

	err = d.coreClient.Secrets(d.namespace).Delete(ctx, EncryptionConfigSecretName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete secret %s/%s: %w", d.namespace, EncryptionConfigSecretName, err))
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
				APIGroups: []string{"batch"},
				Resources: []string{"jobs"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"jobs/status"},
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
	batchClient batchv1client.BatchV1Interface,
	eventRecorder events.Recorder,
	operatorImage string,
	operatorCommand []string,
	kmsCallTimeout time.Duration,
) *PodPreflightDeployer {
	return &PodPreflightDeployer{
		namespace:       namespace,
		coreClient:      coreClient,
		rbacClient:      rbacClient,
		batchClient:     batchClient,
		eventRecorder:   eventRecorder,
		operatorImage:   operatorImage,
		operatorCommand: operatorCommand,
		kmsCallTimeout:  kmsCallTimeout,
	}
}

// NewStaticPodPreflightDeployer creates a deployer that virtualizes a static pod
// (e.g. hostNetwork=true) while still running as a normal Job pod.
func NewStaticPodPreflightDeployer(
	namespace string,
	coreClient corev1client.CoreV1Interface,
	rbacClient rbacclientv1.RbacV1Interface,
	batchClient batchv1client.BatchV1Interface,
	eventRecorder events.Recorder,
	operatorImage string,
	operatorCommand []string,
	kmsCallTimeout time.Duration,
) *PodPreflightDeployer {
	deployer := NewPodPreflightDeployer(namespace, coreClient, rbacClient, batchClient, eventRecorder, operatorImage, operatorCommand, kmsCallTimeout)
	deployer.virtualStaticPod = true
	return deployer
}

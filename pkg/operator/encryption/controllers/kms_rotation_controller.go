package controllers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

// ConvergedKEKReporter provides the cluster-converged KMS KEK identity from health aggregation.
type ConvergedKEKReporter interface {
	ConvergedKekID() (kekID string, converged bool)
}

type kmsRotationController struct {
	instanceName             string
	controllerInstanceName   string
	operatorClient           operatorv1helpers.OperatorClient
	secretClient             corev1client.SecretsGetter
	encryptionSecretSelector metav1.ListOptions
	deployer                 statemachine.Deployer
	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled
	convergedKEKReporter     ConvergedKEKReporter
	now                      func() time.Time
}

func NewKMSRotationController(
	instanceName string,
	provider Provider,
	deployer statemachine.Deployer,
	preconditionsFulfilledFn preconditionsFulfilled,
	convergedKEKReporter ConvergedKEKReporter,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerConfigInformer configv1informers.APIServerInformer,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	secretClient corev1client.SecretsGetter,
	encryptionSecretSelector metav1.ListOptions,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &kmsRotationController{
		instanceName:             instanceName,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionKMSRotation"),
		operatorClient:           operatorClient,
		encryptionSecretSelector: encryptionSecretSelector,
		secretClient:             secretClient,
		deployer:                 deployer,
		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
		convergedKEKReporter:     convergedKEKReporter,
		now:                      time.Now,
	}

	return factory.New().ResyncEvery(time.Minute).WithSync(c.sync).WithControllerInstanceName(c.controllerInstanceName).WithInformers(
		operatorClient.Informer(),
		kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets().Informer(),
		kubeInformersForNamespaces.InformersFor("openshift-config").Core().V1().ConfigMaps().Informer(),
		apiServerConfigInformer.Informer(),
		deployer,
	).ToController(
		c.controllerInstanceName,
		eventRecorder.WithComponentSuffix("encryption-kms-rotation-controller"),
	)
}

func (c *kmsRotationController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if ready, err := shouldRunEncryptionController(c.operatorClient, c.preconditionsFulfilledFn, c.provider.ShouldRunEncryptionControllers); err != nil || !ready {
		return err
	}

	_, _, encryptionSecrets, isTransitionalReason, err := statemachine.GetEncryptionConfigAndState(
		ctx, c.deployer, c.secretClient, c.encryptionSecretSelector, c.provider.EncryptedGRs(),
	)
	if err != nil {
		return err
	}
	if len(isTransitionalReason) > 0 {
		return nil
	}

	writeKeySecret, writeKeyState, ok := latestKMSWriteKeySecret(encryptionSecrets)
	if !ok {
		return nil
	}

	convergedKekID, converged := c.convergedKEKReporter.ConvergedKekID()
	if !converged || convergedKekID == "" {
		return c.updateWriteKeySecret(ctx, syncCtx, writeKeySecret, clearKekConvergenceAnnotations)
	}

	return c.reconcileKekAnnotations(ctx, syncCtx, writeKeySecret, writeKeyState, convergedKekID, c.provider.EncryptedGRs())
}

func latestKMSWriteKeySecret(encryptionSecrets []*corev1.Secret) (*corev1.Secret, state.KeyState, bool) {
	var latestSecret *corev1.Secret
	var latestKey state.KeyState
	var latestKeyID uint64
	for _, s := range encryptionSecrets {
		ks, err := secrets.ToKeyState(s)
		if err != nil || ks.Mode != state.KMS {
			continue
		}
		keyID, valid := state.NameToKeyID(s.Name)
		if !valid {
			continue
		}
		if latestSecret == nil || keyID > latestKeyID {
			latestSecret = s
			latestKey = ks
			latestKeyID = keyID
		}
	}
	return latestSecret, latestKey, latestSecret != nil
}

func (c *kmsRotationController) reconcileKekAnnotations(
	ctx context.Context,
	syncCtx factory.SyncContext,
	writeKeySecret *corev1.Secret,
	writeKeyState state.KeyState,
	convergedKekID string,
	encryptedGRs []schema.GroupResource,
) error {
	kekMigration := secrets.KekMigrationFromSecret(writeKeySecret)

	// Bootstrap: initial migration complete, no kekId annotations yet.
	if kekMigration.TargetKekID == "" && kekMigration.MigratedKekID == "" {
		allMigrated, _, _ := state.MigratedFor(encryptedGRs, writeKeyState)
		if !allMigrated {
			return nil
		}
		return c.updateWriteKeySecret(ctx, syncCtx, writeKeySecret, func(s *corev1.Secret) (bool, error) {
			return setKekBootstrapAnnotations(s, convergedKekID)
		})
	}

	// Steady state or migration in flight: converged kekId matches current target.
	if convergedKekID == kekMigration.TargetKekID {
		if kekMigration.KekConvergedID != "" || !kekMigration.KekConvergedAt.IsZero() {
			return c.updateWriteKeySecret(ctx, syncCtx, writeKeySecret, clearKekConvergenceAnnotations)
		}
		return nil
	}

	// Candidate kekId differs from target: start or maintain the convergence clock.
	if convergedKekID != kekMigration.KekConvergedID {
		return c.updateWriteKeySecret(ctx, syncCtx, writeKeySecret, func(s *corev1.Secret) (bool, error) {
			return setKekConvergenceClock(s, convergedKekID, c.now())
		})
	}

	if kekMigration.KekConvergedAt.IsZero() {
		return c.updateWriteKeySecret(ctx, syncCtx, writeKeySecret, func(s *corev1.Secret) (bool, error) {
			return setKekConvergenceClock(s, convergedKekID, c.now())
		})
	}

	if c.now().Sub(kekMigration.KekConvergedAt) >= secrets.KekConvergenceDelay {
		return c.updateWriteKeySecret(ctx, syncCtx, writeKeySecret, func(s *corev1.Secret) (bool, error) {
			return promoteConvergedKekToTarget(s, convergedKekID)
		})
	}

	return nil
}

type secretAnnotationMutator func(s *corev1.Secret) (changed bool, err error)

func (c *kmsRotationController) updateWriteKeySecret(ctx context.Context, syncCtx factory.SyncContext, writeKeySecret *corev1.Secret, mutate secretAnnotationMutator) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		s, err := c.secretClient.Secrets(writeKeySecret.Namespace).Get(ctx, writeKeySecret.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get key secret %s/%s: %w", writeKeySecret.Namespace, writeKeySecret.Name, err)
		}

		changed, err := mutate(s)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}

		_, updateErr := c.secretClient.Secrets(s.Namespace).Update(ctx, s, metav1.UpdateOptions{})
		resourcehelper.ReportUpdateEvent(syncCtx.Recorder(), s, updateErr)
		return updateErr
	})
}

func setKekBootstrapAnnotations(s *corev1.Secret, kekID string) (bool, error) {
	if kekID == "" {
		return false, nil
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	if s.Annotations[secrets.EncryptionSecretTargetKekID] == kekID &&
		s.Annotations[secrets.EncryptionSecretMigratedKekID] == kekID {
		return false, nil
	}
	s.Annotations[secrets.EncryptionSecretTargetKekID] = kekID
	s.Annotations[secrets.EncryptionSecretMigratedKekID] = kekID
	delete(s.Annotations, secrets.EncryptionSecretKekConvergedAt)
	delete(s.Annotations, secrets.EncryptionSecretKekConvergedID)
	klog.V(2).Infof("bootstrapped KMS kekId annotations on secret %s/%s to %q", s.Namespace, s.Name, kekID)
	return true, nil
}

func setKekConvergenceClock(s *corev1.Secret, kekID string, now time.Time) (bool, error) {
	if kekID == "" {
		return false, nil
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	changed := false
	if s.Annotations[secrets.EncryptionSecretKekConvergedID] != kekID {
		s.Annotations[secrets.EncryptionSecretKekConvergedID] = kekID
		s.Annotations[secrets.EncryptionSecretKekConvergedAt] = now.Format(time.RFC3339)
		changed = true
	} else if s.Annotations[secrets.EncryptionSecretKekConvergedAt] == "" {
		s.Annotations[secrets.EncryptionSecretKekConvergedAt] = now.Format(time.RFC3339)
		changed = true
	}
	if changed {
		klog.V(2).Infof("started KMS kekId convergence clock on secret %s/%s for candidate %q", s.Namespace, s.Name, kekID)
	}
	return changed, nil
}

func promoteConvergedKekToTarget(s *corev1.Secret, kekID string) (bool, error) {
	if kekID == "" {
		return false, nil
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	if s.Annotations[secrets.EncryptionSecretTargetKekID] == kekID &&
		s.Annotations[secrets.EncryptionSecretKekConvergedID] == "" &&
		s.Annotations[secrets.EncryptionSecretKekConvergedAt] == "" {
		return false, nil
	}
	s.Annotations[secrets.EncryptionSecretTargetKekID] = kekID
	delete(s.Annotations, secrets.EncryptionSecretKekConvergedAt)
	delete(s.Annotations, secrets.EncryptionSecretKekConvergedID)
	klog.V(2).Infof("updated target-kek-id on secret %s/%s to %q after convergence delay", s.Namespace, s.Name, kekID)
	return true, nil
}

func clearKekConvergenceAnnotations(s *corev1.Secret) (bool, error) {
	if s.Annotations == nil {
		return false, nil
	}
	_, hasID := s.Annotations[secrets.EncryptionSecretKekConvergedID]
	_, hasAt := s.Annotations[secrets.EncryptionSecretKekConvergedAt]
	if !hasID && !hasAt {
		return false, nil
	}
	delete(s.Annotations, secrets.EncryptionSecretKekConvergedID)
	delete(s.Annotations, secrets.EncryptionSecretKekConvergedAt)
	klog.V(4).Infof("cleared KMS kekId convergence clock on secret %s/%s", s.Namespace, s.Name)
	return true, nil
}

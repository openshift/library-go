package certrotation

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/condition"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	// RunOnceContextKey is a context value key that can be used to call the controller Sync() and make it only run the syncWorker once and report error.
	RunOnceContextKey = "cert-rotation-controller.openshift.io/run-once"
)

// StatusReporter knows how to report the status of cert rotation
type StatusReporter interface {
	Report(ctx context.Context, controllerName string, syncErr error) (updated bool, updateErr error)
}

var _ StatusReporter = (*StaticPodConditionStatusReporter)(nil)

type StaticPodConditionStatusReporter struct {
	// Plumbing:
	OperatorClient v1helpers.StaticPodOperatorClient
}

func (s *StaticPodConditionStatusReporter) Report(ctx context.Context, controllerName string, syncErr error) (bool, error) {
	newCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf(condition.CertRotationDegradedConditionTypeFmt, controllerName),
		Status: operatorv1.ConditionFalse,
	}
	if syncErr != nil {
		newCondition.Status = operatorv1.ConditionTrue
		newCondition.Reason = "RotationError"
		newCondition.Message = syncErr.Error()
	}
	_, updated, updateErr := v1helpers.UpdateStaticPodStatus(ctx, s.OperatorClient, v1helpers.UpdateStaticPodConditionFn(newCondition))
	return updated, updateErr
}

// CertRotationController does:
//
// 1) continuously create a self-signed signing CA (via SigningCAConfig) and store it in a secret.
// 2) maintain a CA bundle ConfigMap with all not yet expired CA certs.
// 3) continuously create a target cert and key signed by the latest signing CA and store it in a secret.
type CertRotationController struct {
	// Name is the controller name.
	Name string
	// SigningCA holds the configuration for the signing CA secret.
	SigningCA SigningCAConfig
	// CABundle holds the configuration for the CA bundle config map.
	CABundle CABundleConfig
	// TargetCert holds the configuration for the target certificate secret.
	TargetCert TargetCertKeyPairConfig

	// StatusReporter reports the status of cert rotation.
	StatusReporter StatusReporter

	kubeClient    kubernetes.Interface
	kubeInformers v1helpers.KubeInformersForNamespaces
	eventRecorder events.Recorder
}

func NewCertRotationController(
	name string,
	signingCA SigningCAConfig,
	caBundle CABundleConfig,
	targetCert TargetCertKeyPairConfig,
	kubeClient kubernetes.Interface,
	kubeInformers v1helpers.KubeInformersForNamespaces,
	recorder events.Recorder,
	reporter StatusReporter,
) factory.Controller {
	c := &CertRotationController{
		Name:           name,
		SigningCA:      signingCA,
		CABundle:       caBundle,
		TargetCert:     targetCert,
		StatusReporter: reporter,
		kubeClient:     kubeClient,
		kubeInformers:  kubeInformers,
		eventRecorder:  recorder,
	}

	signerSecretInformer := kubeInformers.InformersFor(signingCA.Namespace).Core().V1().Secrets()
	caBundleConfigMapInformer := kubeInformers.InformersFor(caBundle.Namespace).Core().V1().ConfigMaps()
	targetSecretInformer := kubeInformers.InformersFor(targetCert.Namespace).Core().V1().Secrets()

	return factory.New().
		ResyncEvery(time.Minute).
		WithSync(c.Sync).
		WithFilteredEventsInformers(
			func(obj interface{}) bool {
				if cm, ok := obj.(*corev1.ConfigMap); ok {
					return cm.Namespace == caBundle.Namespace && cm.Name == caBundle.Name
				}
				if secret, ok := obj.(*corev1.Secret); ok {
					if secret.Namespace == signingCA.Namespace && secret.Name == signingCA.Name {
						return true
					}
					if secret.Namespace == targetCert.Namespace && secret.Name == targetCert.Name {
						return true
					}
					return false
				}
				return true
			},
			signerSecretInformer.Informer(),
			caBundleConfigMapInformer.Informer(),
			targetSecretInformer.Informer(),
		).
		WithPostStartHooks(
			c.targetCertRecheckerPostRunHook,
		).
		ToController(
			"CertRotationController", // don't change what is passed here unless you also remove the old FooDegraded condition
			recorder.WithComponentSuffix("cert-rotation-controller").WithComponentSuffix(name),
		)
}

func (c CertRotationController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	syncErr := c.SyncWorker(ctx)

	// running this function with RunOnceContextKey value context will make this "run-once" without updating status.
	isRunOnce, ok := ctx.Value(RunOnceContextKey).(bool)
	if ok && isRunOnce {
		return syncErr
	}

	updated, updateErr := c.StatusReporter.Report(ctx, c.Name, syncErr)
	if updateErr != nil {
		return updateErr
	}
	if updated && syncErr != nil {
		syncCtx.Recorder().Warningf("RotationError", syncErr.Error())
	}

	return syncErr
}

func (c CertRotationController) getSigningCertKeyPairLocation() string {
	return fmt.Sprintf("%s/%s", c.SigningCA.Namespace, c.SigningCA.Name)
}

func (c CertRotationController) SyncWorker(ctx context.Context) error {
	signingCertKeyPair, _, err := c.ensureSigningCertKeyPair(ctx)
	if err != nil {
		return err
	}
	// If no signingCertKeyPair returned due to update conflict or otherwise, return an error
	if signingCertKeyPair == nil {
		return fmt.Errorf("signingCertKeyPair is nil")
	}

	cabundleCerts, err := c.ensureConfigMapCABundle(ctx, signingCertKeyPair)
	if err != nil {
		return err
	}
	// If no ca bundle returned due to update conflict or otherwise, return an error
	if cabundleCerts == nil {
		return fmt.Errorf("cabundleCerts is nil")
	}

	if _, err := c.ensureTargetCertKeyPair(ctx, signingCertKeyPair, cabundleCerts); err != nil {
		return err
	}

	return nil
}

func (c CertRotationController) targetCertRecheckerPostRunHook(ctx context.Context, syncCtx factory.SyncContext) error {
	serving, ok := c.TargetCert.CertConfig.(ServingCertConfig)
	if !ok || serving.HostnamesChanged == nil {
		return nil
	}
	go wait.Until(func() {
		for {
			select {
			case <-serving.HostnamesChanged:
				syncCtx.Queue().Add(factory.DefaultQueueKey)
			case <-ctx.Done():
				return
			}
		}
	}, time.Minute, ctx.Done())

	<-ctx.Done()
	return nil
}
package certrotation

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

const (
	// CertificateNotBeforeAnnotation contains the certificate expiration date in RFC3339 format.
	CertificateNotBeforeAnnotation = "auth.openshift.io/certificate-not-before"
	// CertificateNotAfterAnnotation contains the certificate expiration date in RFC3339 format.
	CertificateNotAfterAnnotation = "auth.openshift.io/certificate-not-after"
	// CertificateIssuer contains the common name of the certificate that signed another certificate.
	CertificateIssuer = "auth.openshift.io/certificate-issuer"
	// CertificateHostnames contains the hostnames used by a signer.
	CertificateHostnames = "auth.openshift.io/certificate-hostnames"
	// RunOnceContextKey is a context value key that can be used to call the controller Sync() and make it only run the syncWorker once and report error.
	RunOnceContextKey = "cert-rotation-controller.openshift.io/run-once"
)

// RotatedSigningCASecretController continuously creates a self-signed signing CA (via RotatedSigningCASecret) and store it in a secret.
type RotatedSigningCASecretController struct {
	name string

	// Signer rotates a self-signed signing CA stored in a secret.
	Signer *RotatedSigningCASecret
	// Plumbing:
	StatusReporter StatusReporter
}

func NewRotatedSigningCASecretController(
	signer *RotatedSigningCASecret,
	recorder events.Recorder,
	reporter StatusReporter,
) factory.Controller {
	name := fmt.Sprintf("signer %s/%s", signer.Namespace, signer.Name)
	c := &RotatedSigningCASecretController{
		Signer:         signer,
		StatusReporter: reporter,
		name:           name,
	}
	return factory.New().
		ResyncEvery(time.Minute).
		WithSync(c.Sync).
		WithInformers(
			signer.Informer.Informer(),
		).
		ToController("CertRotationController", recorder.WithComponentSuffix("cert-rotation-controller").WithComponentSuffix(name))
}

func (c RotatedSigningCASecretController) SyncWorker(ctx context.Context, syncCtx factory.SyncContext) error {
	_, _, err := c.Signer.EnsureSigningCertKeyPair(ctx)
	return err
}

func (c RotatedSigningCASecretController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	syncErr := c.SyncWorker(ctx, syncCtx)

	// running this function with RunOnceContextKey value context will make this "run-once" without updating status.
	isRunOnce, ok := ctx.Value(RunOnceContextKey).(bool)
	if ok && isRunOnce {
		return syncErr
	}

	updated, updateErr := c.StatusReporter.Report(ctx, c.name, syncErr)
	if updateErr != nil {
		return updateErr
	}
	if updated && syncErr != nil {
		syncCtx.Recorder().Warningf("RotationError", syncErr.Error())
	}

	return syncErr
}

// RotatedCABundleController maintains a CA bundle ConfigMap with all not yet expired CA certs.
type RotatedCABundleController struct {
	name string

	CABundle *CABundleConfigMap
	Signers  []*RotatedSigningCASecret
	// Plumbing:
	StatusReporter StatusReporter
}

func NewRotatedCABundleConfigMapController(
	cabundle *CABundleConfigMap,
	signers []*RotatedSigningCASecret,
	recorder events.Recorder,
	reporter StatusReporter,
) factory.Controller {
	name := fmt.Sprintf("cabundle %s/%s", cabundle.Namespace, cabundle.Name)
	c := &RotatedCABundleController{
		CABundle:       cabundle,
		Signers:        signers,
		StatusReporter: reporter,
		name:           name,
	}
	ctrlFactory := factory.New().
		ResyncEvery(time.Minute).
		WithSync(c.Sync).
		WithInformers(
			cabundle.Informer.Informer(),
		)
	for _, signer := range signers {
		ctrlFactory = ctrlFactory.WithInformers(signer.Informer.Informer())
	}

	return ctrlFactory.
		ToController("CertRotationController", recorder.WithComponentSuffix("cert-rotation-controller").WithComponentSuffix(name))
}

func (c RotatedCABundleController) SyncWorker(ctx context.Context, syncCtx factory.SyncContext) error {
	var errs []error
	var signers []*x509.Certificate
	for _, signer := range c.Signers {
		signingCertKeyPair, err := signer.getSigningCertKeyPair()
		if err != nil {
			errs = append(errs, err)
		}
		if signingCertKeyPair == nil {
			continue
		}
		signers = append(signers, signingCertKeyPair.Config.Certs[0])
	}
	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}
	if len(signers) == 0 {
		return fmt.Errorf("No signers received yet")
	}
	_, err := c.CABundle.ensureConfigMapCABundleFromCerts(ctx, signers)
	return err
}

func (c RotatedCABundleController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	syncErr := c.SyncWorker(ctx, syncCtx)

	// running this function with RunOnceContextKey value context will make this "run-once" without updating status.
	isRunOnce, ok := ctx.Value(RunOnceContextKey).(bool)
	if ok && isRunOnce {
		return syncErr
	}

	updated, updateErr := c.StatusReporter.Report(ctx, c.name, syncErr)
	if updateErr != nil {
		return updateErr
	}
	if updated && syncErr != nil {
		syncCtx.Recorder().Warningf("RotationError", syncErr.Error())
	}

	return syncErr
}

// RotatedTargetSecretController continuously creates a target cert and key signed by the latest signing CA and store it in a secret
type RotatedTargetSecretController struct {
	name string

	Target   RotatedSelfSignedCertKeySecret
	Signer   *RotatedSigningCASecret
	CABundle *CABundleConfigMap
	// Plumbing:
	StatusReporter StatusReporter
}

func NewRotatedTargetSecretController(
	target RotatedSelfSignedCertKeySecret,
	signer *RotatedSigningCASecret,
	cabundle *CABundleConfigMap,
	recorder events.Recorder,
	reporter StatusReporter,
) factory.Controller {
	name := fmt.Sprintf("target %s/%s", target.Namespace, target.Name)
	c := &RotatedTargetSecretController{
		Target:         target,
		Signer:         signer,
		CABundle:       cabundle,
		StatusReporter: reporter,
		name:           name,
	}
	return factory.New().
		ResyncEvery(time.Minute).
		WithSync(c.Sync).
		WithInformers(
			signer.Informer.Informer(),
			cabundle.Informer.Informer(),
			target.Informer.Informer(),
		).
		WithPostStartHooks(
			c.targetCertRecheckerPostRunHook,
		).
		ToController("CertRotationController", recorder.WithComponentSuffix("cert-rotation-controller").WithComponentSuffix(name))
}

func (c RotatedTargetSecretController) SyncWorker(ctx context.Context, syncCtx factory.SyncContext) error {
	signingCertKeyPair, err := c.Signer.getSigningCertKeyPair()
	if err != nil || signingCertKeyPair == nil {
		return err
	}
	cabundleCerts, err := c.CABundle.getConfigMapCABundle()
	if err != nil || cabundleCerts == nil {
		return err
	}
	if _, err := c.Target.EnsureTargetCertKeyPair(ctx, signingCertKeyPair, cabundleCerts); err != nil {
		return err
	}
	return nil
}

func (c RotatedTargetSecretController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	syncErr := c.SyncWorker(ctx, syncCtx)

	updated, updateErr := c.StatusReporter.Report(ctx, c.name, syncErr)
	if updateErr != nil {
		return updateErr
	}
	if updated && syncErr != nil {
		syncCtx.Recorder().Warningf("RotationError", syncErr.Error())
	}

	return syncErr
}

func (c RotatedTargetSecretController) targetCertRecheckerPostRunHook(ctx context.Context, syncCtx factory.SyncContext) error {
	if c.Target.CertCreator == nil {
		return nil
	}
	// If we have a need to force rechecking the cert, use this channel to do it.
	refresher, ok := c.Target.CertCreator.(TargetCertRechecker)
	if !ok {
		return nil
	}
	targetRefresh := refresher.RecheckChannel()
	go wait.Until(func() {
		for {
			select {
			case <-targetRefresh:
				syncCtx.Queue().Add(factory.DefaultQueueKey)
			case <-ctx.Done():
				return
			}
		}
	}, time.Minute, ctx.Done())

	<-ctx.Done()
	return nil
}

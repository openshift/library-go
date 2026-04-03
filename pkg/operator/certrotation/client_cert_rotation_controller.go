package certrotation

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/certs"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/condition"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/pkg/pki"
	"k8s.io/apimachinery/pkg/api/equality"
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

	kubeClient         kubernetes.Interface
	kubeInformers      v1helpers.KubeInformersForNamespaces
	eventRecorder      events.Recorder
	pkiProfileProvider pki.PKIProfileProvider
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
	pkiProvider pki.PKIProfileProvider,
) factory.Controller {
	c := &CertRotationController{
		Name:               name,
		SigningCA:          signingCA,
		CABundle:           caBundle,
		TargetCert:         targetCert,
		StatusReporter:     reporter,
		kubeClient:         kubeClient,
		kubeInformers:      kubeInformers,
		eventRecorder:      recorder,
		pkiProfileProvider: pkiProvider,
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

// ensureSigningCertKeyPair manages the entire lifecycle of a signer cert as a secret, from creation to continued rotation.
// It always returns the currently used CA pair, a bool indicating whether it was created/updated within this function call and an error.
func (c CertRotationController) ensureSigningCertKeyPair(ctx context.Context) (*crypto.CA, bool, error) {
	creationRequired := false
	updateRequired := false
	originalSigningCertKeyPairSecret, err := c.kubeInformers.SecretLister().Secrets(c.SigningCA.Namespace).Get(c.SigningCA.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, false, err
	}
	signingCertKeyPairSecret := originalSigningCertKeyPairSecret.DeepCopy()
	if apierrors.IsNotFound(err) {
		// create an empty one
		signingCertKeyPairSecret = &corev1.Secret{
			ObjectMeta: NewTLSArtifactObjectMeta(
				c.SigningCA.Name,
				c.SigningCA.Namespace,
				c.SigningCA.AdditionalAnnotations,
			),
			Type: corev1.SecretTypeTLS,
		}
		creationRequired = true
	}

	// run Update if metadata needs changing unless we're in RefreshOnlyWhenExpired mode
	if !c.SigningCA.RefreshOnlyWhenExpired {
		needsMetadataUpdate := ensureOwnerRefAndTLSAnnotations(signingCertKeyPairSecret, c.SigningCA.Owner, c.SigningCA.AdditionalAnnotations)
		needsTypeChange := ensureSecretTLSTypeSet(signingCertKeyPairSecret)
		updateRequired = needsMetadataUpdate || needsTypeChange
	}

	// run Update if signer content needs changing
	signerUpdated := false
	if needed, reason := needNewSigningCertKeyPair(signingCertKeyPairSecret, c.SigningCA.Refresh, c.SigningCA.RefreshOnlyWhenExpired); needed || creationRequired {
		if creationRequired {
			reason = "secret doesn't exist"
		}
		c.eventRecorder.Eventf("SignerUpdateRequired", "%q in %q requires a new signing cert/key pair: %v", c.SigningCA.Name, c.SigningCA.Namespace, reason)

		var ca *crypto.TLSCertificateConfig
		if c.pkiProfileProvider != nil {
			keyGen, resolveErr := resolveKeyPairGenerator(c.pkiProfileProvider, pki.CertificateTypeSigner, c.SigningCA.CertificateName)
			if resolveErr != nil {
				return nil, false, resolveErr
			}
			signerName := fmt.Sprintf("%s_%s@%d", signingCertKeyPairSecret.Namespace, signingCertKeyPairSecret.Name, time.Now().Unix())
			ca, err = crypto.NewSigningCertificate(signerName, keyGen, crypto.WithLifetime(c.SigningCA.Validity))
			if err != nil {
				return nil, false, err
			}
			certBytes := &bytes.Buffer{}
			keyBytes := &bytes.Buffer{}
			if err = ca.WriteCertConfig(certBytes, keyBytes); err != nil {
				return nil, false, err
			}
			if signingCertKeyPairSecret.Annotations == nil {
				signingCertKeyPairSecret.Annotations = map[string]string{}
			}
			if signingCertKeyPairSecret.Data == nil {
				signingCertKeyPairSecret.Data = map[string][]byte{}
			}
			signingCertKeyPairSecret.Data["tls.crt"] = certBytes.Bytes()
			signingCertKeyPairSecret.Data["tls.key"] = keyBytes.Bytes()
		} else {
			ca, err = setSigningCertKeyPairSecret(signingCertKeyPairSecret, c.SigningCA.Validity)
			if err != nil {
				return nil, false, err
			}
		}
		setTLSAnnotationsOnSigningCertKeyPairSecret(signingCertKeyPairSecret, ca, c.SigningCA.Refresh, c.SigningCA.AdditionalAnnotations)

		LabelAsManagedSecret(signingCertKeyPairSecret, CertificateTypeSigner)

		updateRequired = true
		signerUpdated = true
	}

	if creationRequired {
		actualSigningCertKeyPairSecret, err := c.kubeClient.CoreV1().Secrets(c.SigningCA.Namespace).Create(ctx, signingCertKeyPairSecret, metav1.CreateOptions{})
		resourcehelper.ReportCreateEvent(c.eventRecorder, actualSigningCertKeyPairSecret, err)
		if err != nil {
			return nil, false, err
		}
		klog.V(2).Infof("Created secret %s/%s", actualSigningCertKeyPairSecret.Namespace, actualSigningCertKeyPairSecret.Name)
		signingCertKeyPairSecret = actualSigningCertKeyPairSecret
	} else if updateRequired {
		actualSigningCertKeyPairSecret, err := c.kubeClient.CoreV1().Secrets(c.SigningCA.Namespace).Update(ctx, signingCertKeyPairSecret, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			// ignore error if its attempting to update outdated version of the secret
			return nil, false, nil
		}
		resourcehelper.ReportUpdateEvent(c.eventRecorder, actualSigningCertKeyPairSecret, err)
		if err != nil {
			return nil, false, err
		}
		klog.V(2).Infof("Updated secret %s/%s", actualSigningCertKeyPairSecret.Namespace, actualSigningCertKeyPairSecret.Name)
		signingCertKeyPairSecret = actualSigningCertKeyPairSecret
	}

	// at this point, the secret has the correct signer, so we should read that signer to be able to sign
	signingCertKeyPair, err := crypto.GetCAFromBytes(signingCertKeyPairSecret.Data["tls.crt"], signingCertKeyPairSecret.Data["tls.key"])
	if err != nil {
		return nil, signerUpdated, err
	}

	return signingCertKeyPair, signerUpdated, nil
}

func (c CertRotationController) ensureConfigMapCABundle(ctx context.Context, signingCertKeyPair *crypto.CA) ([]*x509.Certificate, error) {
	signingCertKeyPairLocation := c.getSigningCertKeyPairLocation()

	// by this point we have current signing cert/key pair.  We now need to make sure that the ca-bundle configmap has this cert and
	// doesn't have any expired certs
	updateRequired := false
	creationRequired := false

	originalCABundleConfigMap, err := c.kubeInformers.ConfigMapLister().ConfigMaps(c.CABundle.Namespace).Get(c.CABundle.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	caBundleConfigMap := originalCABundleConfigMap.DeepCopy()
	if apierrors.IsNotFound(err) {
		// create an empty one
		caBundleConfigMap = &corev1.ConfigMap{ObjectMeta: NewTLSArtifactObjectMeta(
			c.CABundle.Name,
			c.CABundle.Namespace,
			c.CABundle.AdditionalAnnotations,
		)}
		creationRequired = true
	}

	// run Update if metadata needs changing unless running in RefreshOnlyWhenExpired mode
	if !c.CABundle.RefreshOnlyWhenExpired {
		needsOwnerUpdate := false
		if c.CABundle.Owner != nil {
			needsOwnerUpdate = ensureOwnerReference(&caBundleConfigMap.ObjectMeta, c.CABundle.Owner)
		}
		needsMetadataUpdate := c.CABundle.AdditionalAnnotations.EnsureTLSMetadataUpdate(&caBundleConfigMap.ObjectMeta)
		updateRequired = needsOwnerUpdate || needsMetadataUpdate
	}

	updatedCerts, err := manageCABundleConfigMap(caBundleConfigMap, signingCertKeyPair.Config.Certs[0])
	if err != nil {
		return nil, err
	}
	if originalCABundleConfigMap == nil || originalCABundleConfigMap.Data == nil || !equality.Semantic.DeepEqual(originalCABundleConfigMap.Data, caBundleConfigMap.Data) {
		reason := ""
		if creationRequired {
			reason = "configmap doesn't exist"
		} else if originalCABundleConfigMap.Data == nil {
			reason = "configmap is empty"
		} else if !equality.Semantic.DeepEqual(originalCABundleConfigMap.Data, caBundleConfigMap.Data) {
			reason = fmt.Sprintf("signer update %s", signingCertKeyPairLocation)
		}
		c.eventRecorder.Eventf("CABundleUpdateRequired", "%q in %q requires a new cert: %s", c.CABundle.Name, c.CABundle.Namespace, reason)
		LabelAsManagedConfigMap(caBundleConfigMap, CertificateTypeCABundle)

		updateRequired = true
	}

	if creationRequired {
		actualCABundleConfigMap, err := c.kubeClient.CoreV1().ConfigMaps(c.CABundle.Namespace).Create(ctx, caBundleConfigMap, metav1.CreateOptions{})
		resourcehelper.ReportCreateEvent(c.eventRecorder, actualCABundleConfigMap, err)
		if err != nil {
			return nil, err
		}
		klog.V(2).Infof("Created ca-bundle.crt configmap %s/%s with:\n%s", certs.CertificateBundleToString(updatedCerts), caBundleConfigMap.Namespace, caBundleConfigMap.Name)
		caBundleConfigMap = actualCABundleConfigMap
	} else if updateRequired {
		actualCABundleConfigMap, err := c.kubeClient.CoreV1().ConfigMaps(c.CABundle.Namespace).Update(ctx, caBundleConfigMap, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			// ignore error if its attempting to update outdated version of the configmap
			return nil, nil
		}
		resourcehelper.ReportUpdateEvent(c.eventRecorder, actualCABundleConfigMap, err)
		if err != nil {
			return nil, err
		}
		klog.V(2).Infof("Updated ca-bundle.crt configmap %s/%s with:\n%s", certs.CertificateBundleToString(updatedCerts), caBundleConfigMap.Namespace, caBundleConfigMap.Name)
		caBundleConfigMap = actualCABundleConfigMap
	}

	caBundle := caBundleConfigMap.Data["ca-bundle.crt"]
	if len(caBundle) == 0 {
		return nil, fmt.Errorf("configmap/%s -n%s missing ca-bundle.crt", caBundleConfigMap.Name, caBundleConfigMap.Namespace)
	}
	certificates, err := cert.ParseCertsPEM([]byte(caBundle))
	if err != nil {
		return nil, err
	}

	return certificates, nil
}

func (c CertRotationController) ensureTargetCertKeyPair(ctx context.Context, signingCertKeyPair *crypto.CA, caBundleCerts []*x509.Certificate) (*corev1.Secret, error) {
	// at this point our trust bundle has been updated.  We don't know for sure that consumers have updated, but that's why we have a second
	// validity percentage.  We always check to see if we need to sign.  Often we are signing with an old key or we have no target
	// and need to mint one
	// TODO do the cross signing thing, but this shows the API consumers want and a very simple impl.

	creationRequired := false
	updateRequired := false
	originalTargetCertKeyPairSecret, err := c.kubeInformers.SecretLister().Secrets(c.TargetCert.Namespace).Get(c.TargetCert.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	targetCertKeyPairSecret := originalTargetCertKeyPairSecret.DeepCopy()
	if apierrors.IsNotFound(err) {
		// create an empty one
		targetCertKeyPairSecret = &corev1.Secret{
			ObjectMeta: NewTLSArtifactObjectMeta(
				c.TargetCert.Name,
				c.TargetCert.Namespace,
				c.TargetCert.AdditionalAnnotations,
			),
			Type: corev1.SecretTypeTLS,
		}
		creationRequired = true
	}

	// run Update if metadata needs changing unless we're in RefreshOnlyWhenExpired mode
	if !c.TargetCert.RefreshOnlyWhenExpired {
		needsMetadataUpdate := ensureOwnerRefAndTLSAnnotations(targetCertKeyPairSecret, c.TargetCert.Owner, c.TargetCert.AdditionalAnnotations)
		needsTypeChange := ensureSecretTLSTypeSet(targetCertKeyPairSecret)
		updateRequired = needsMetadataUpdate || needsTypeChange
	}

	// Determine hostnames function for serving certs
	var hostnames func() []string
	if serving, ok := c.TargetCert.CertConfig.(ServingCertConfig); ok {
		hostnames = serving.Hostnames
	}

	if reason := needNewTargetCertKeyPair(targetCertKeyPairSecret, signingCertKeyPair, caBundleCerts, c.TargetCert.Refresh, c.TargetCert.RefreshOnlyWhenExpired, creationRequired, hostnames); len(reason) > 0 {
		c.eventRecorder.Eventf("TargetUpdateRequired", "%q in %q requires a new target cert/key pair: %v", c.TargetCert.Name, c.TargetCert.Namespace, reason)

		if err := c.setTargetCertKeyPairSecret(targetCertKeyPairSecret, signingCertKeyPair); err != nil {
			return nil, err
		}

		LabelAsManagedSecret(targetCertKeyPairSecret, CertificateTypeTarget)

		updateRequired = true
	}
	if creationRequired {
		actualTargetCertKeyPairSecret, err := c.kubeClient.CoreV1().Secrets(c.TargetCert.Namespace).Create(ctx, targetCertKeyPairSecret, metav1.CreateOptions{})
		resourcehelper.ReportCreateEvent(c.eventRecorder, actualTargetCertKeyPairSecret, err)
		if err != nil {
			return nil, err
		}
		klog.V(2).Infof("Created secret %s/%s", actualTargetCertKeyPairSecret.Namespace, actualTargetCertKeyPairSecret.Name)
		targetCertKeyPairSecret = actualTargetCertKeyPairSecret
	} else if updateRequired {
		actualTargetCertKeyPairSecret, err := c.kubeClient.CoreV1().Secrets(c.TargetCert.Namespace).Update(ctx, targetCertKeyPairSecret, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			// ignore error if its attempting to update outdated version of the secret
			return nil, nil
		}
		resourcehelper.ReportUpdateEvent(c.eventRecorder, actualTargetCertKeyPairSecret, err)
		if err != nil {
			return nil, err
		}
		klog.V(2).Infof("Updated secret %s/%s", actualTargetCertKeyPairSecret.Namespace, actualTargetCertKeyPairSecret.Name)
		targetCertKeyPairSecret = actualTargetCertKeyPairSecret
	}

	return targetCertKeyPairSecret, nil
}

// setTargetCertKeyPairSecret creates a new cert/key pair, sets them in the secret, and applies TLS annotations.
func (c CertRotationController) setTargetCertKeyPairSecret(targetCertKeyPairSecret *corev1.Secret, signer *crypto.CA) error {
	if targetCertKeyPairSecret.Annotations == nil {
		targetCertKeyPairSecret.Annotations = map[string]string{}
	}
	if targetCertKeyPairSecret.Data == nil {
		targetCertKeyPairSecret.Data = map[string][]byte{}
	}

	// our annotation is based on our cert validity, so we want to make sure that we don't specify something past our signer
	targetValidity := c.TargetCert.Validity
	remainingSignerValidity := signer.Config.Certs[0].NotAfter.Sub(time.Now())
	if remainingSignerValidity < targetValidity {
		targetValidity = remainingSignerValidity
	}

	var certKeyPair *crypto.TLSCertificateConfig
	var err error
	if c.pkiProfileProvider != nil {
		certKeyPair, err = c.createTargetCertWithPKI(signer, targetValidity)
	} else {
		certKeyPair, err = c.createTargetCertLegacy(signer, targetValidity)
	}
	if err != nil {
		return err
	}

	targetCertKeyPairSecret.Data["tls.crt"], targetCertKeyPairSecret.Data["tls.key"], err = certKeyPair.GetPEMBytes()
	if err != nil {
		return err
	}

	// Set TLS annotations
	targetCertKeyPairSecret.Annotations[CertificateIssuer] = certKeyPair.Certs[0].Issuer.CommonName

	tlsAnnotations := c.TargetCert.AdditionalAnnotations
	tlsAnnotations.NotBefore = certKeyPair.Certs[0].NotBefore.Format(time.RFC3339)
	tlsAnnotations.NotAfter = certKeyPair.Certs[0].NotAfter.Format(time.RFC3339)
	tlsAnnotations.RefreshPeriod = c.TargetCert.Refresh.String()
	_ = tlsAnnotations.EnsureTLSMetadataUpdate(&targetCertKeyPairSecret.ObjectMeta)

	// Set hostname annotations for serving certs
	if _, ok := c.TargetCert.CertConfig.(ServingCertConfig); ok {
		hostnames := sets.Set[string]{}
		for _, ip := range certKeyPair.Certs[0].IPAddresses {
			hostnames.Insert(ip.String())
		}
		for _, dnsName := range certKeyPair.Certs[0].DNSNames {
			hostnames.Insert(dnsName)
		}
		// List does a sort so that we have a consistent representation
		targetCertKeyPairSecret.Annotations[CertificateHostnames] = strings.Join(sets.List(hostnames), ",")
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

func (c CertRotationController) createTargetCertWithPKI(signer *crypto.CA, targetValidity time.Duration) (*crypto.TLSCertificateConfig, error) {
	var certType pki.CertificateType
	switch c.TargetCert.CertConfig.(type) {
	case ClientCertConfig:
		certType = pki.CertificateTypeClient
	case ServingCertConfig:
		certType = pki.CertificateTypeServing
	case SignerCertConfig:
		certType = pki.CertificateTypeSigner
	default:
		return nil, fmt.Errorf("unknown target cert config type: %T", c.TargetCert.CertConfig)
	}

	keyGen, err := resolveKeyPairGenerator(c.pkiProfileProvider, certType, c.TargetCert.CertificateName)
	if err != nil {
		return nil, err
	}

	switch cfg := c.TargetCert.CertConfig.(type) {
	case ClientCertConfig:
		return signer.NewClientCertificate(cfg.UserInfo, keyGen, crypto.WithLifetime(targetValidity))
	case ServingCertConfig:
		if len(cfg.Hostnames()) == 0 {
			return nil, fmt.Errorf("no hostnames set")
		}
		return signer.NewServerCertificate(
			sets.New(cfg.Hostnames()...), keyGen,
			crypto.WithLifetime(targetValidity),
			crypto.WithExtensions(cfg.CertificateExtensionFn...),
		)
	case SignerCertConfig:
		signerName := fmt.Sprintf("%s_@%d", cfg.SignerName, time.Now().Unix())
		return crypto.NewSigningCertificate(signerName, keyGen,
			crypto.WithSigner(signer),
			crypto.WithLifetime(targetValidity),
		)
	default:
		return nil, fmt.Errorf("unknown target cert config type: %T", cfg)
	}
}

func (c CertRotationController) createTargetCertLegacy(signer *crypto.CA, targetValidity time.Duration) (*crypto.TLSCertificateConfig, error) {
	switch cfg := c.TargetCert.CertConfig.(type) {
	case ClientCertConfig:
		return signer.MakeClientCertificateForDuration(cfg.UserInfo, targetValidity)
	case ServingCertConfig:
		if len(cfg.Hostnames()) == 0 {
			return nil, fmt.Errorf("no hostnames set")
		}
		return signer.MakeServerCertForDuration(sets.New(cfg.Hostnames()...), targetValidity, cfg.CertificateExtensionFn...)
	case SignerCertConfig:
		signerName := fmt.Sprintf("%s_@%d", cfg.SignerName, time.Now().Unix())
		return crypto.MakeCAConfigForDuration(signerName, targetValidity, signer)
	default:
		return nil, fmt.Errorf("unknown target cert config type: %T", cfg)
	}
}

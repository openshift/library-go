package metrics

import (
	"fmt"
	"sync"
	"time"

	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openshift/library-go/pkg/crypto"
)

const (
	// ManagedCertificateTypeLabelName marks config map or secret as object that contains managed certificates.
	// This groups all objects that store certs and allow easy query to get them all.
	// Also any object with this label will be collected by prometheus and transformed to metrics.
	// The value of this label should be set to "true".
	ManagedCertificateTypeLabelName = "auth.openshift.io/managed-certificate-type"
)

type CertificateType string

var (
	CertificateTypeCABundle CertificateType = "ca-bundle"
	CertificateTypeSigner   CertificateType = "signer"
	CertificateTypeTarget   CertificateType = "target"
	CertificateTypeUnknown  CertificateType = "unknown"

	timeNowFn = time.Now
)

var (
	caBundleExpireHoursDesc = prometheus.NewDesc(
		"certificates_ca_bundle_expire_hours",
		"Number of hours until certificates in given CA bundle expire",
		[]string{"namespace", "name", "common_name", "signer_name", "valid_from"}, nil)

	signerExpireHoursDesc = prometheus.NewDesc(
		"certificates_signer_expire_hours",
		"Number of hours until certificates in given signer expire",
		[]string{"namespace", "name", "common_name", "signer_name", "valid_from"}, nil)

	targetExpireHoursDesc = prometheus.NewDesc(
		"certificates_target_expire_hours",
		"Number of hours until certificates in given target expire",
		[]string{"namespace", "name", "common_name", "signer_name", "valid_from"}, nil)
)

type certMetricsCollector struct {
	configLister corev1listers.ConfigMapLister
	secretLister corev1listers.SecretLister

	nowFn func() time.Time
}

// Describe implements the prometheus collector interface
func (c *certMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- caBundleExpireHoursDesc
	ch <- signerExpireHoursDesc
	ch <- targetExpireHoursDesc
}

// Collect implements the prometheus collector interface
func (c *certMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	// to speed up collection, do this in parallel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.collectCABundles(ch) }()
	go func() { defer wg.Done(); c.collectSignersAndTarget(ch) }()
	wg.Wait()
}

func (c *certMetricsCollector) collectSignersAndTarget(ch chan<- prometheus.Metric) {
	secrets, err := c.secretLister.List(getCertificateManagedLabelSelector())
	if err != nil {
		klog.Warningf("Failed to list signer secrets: %v", err)
		return
	}

	for _, secret := range secrets {
		var targetDescType *prometheus.Desc

		switch GetCertificateTypeFromObject(secret) {
		case CertificateTypeSigner:
			targetDescType = signerExpireHoursDesc
		case CertificateTypeTarget:
			targetDescType = targetExpireHoursDesc
		default:
			klog.Warningf("Secret %s/%s has unknown certificate type: %q", secret.Namespace, secret.Name, secret.Labels[ManagedCertificateTypeLabelName])
			continue
		}
		if secret.Data["tls.crt"] == nil || secret.Data["tls.key"] == nil {
			klog.V(4).Infof("Secret %s/%s does not have 'tls.crt' or 'tls.key'", secret.Namespace, secret.Name)
			continue
		}

		signingCertKeyPair, err := crypto.GetCAFromBytes(secret.Data["tls.crt"], secret.Data["tls.key"])
		if err != nil {
			continue
		}

		for _, certificate := range signingCertKeyPair.Config.Certs {
			expireHours := certificate.NotAfter.UTC().Sub(c.nowFn().UTC()).Hours()
			labelValues := []string{
				secret.Namespace,
				secret.Name,
				certificate.Subject.CommonName,
				certificate.Issuer.CommonName,
				fmt.Sprintf("%s", certificate.NotBefore.UTC()),
			}

			ch <- prometheus.MustNewConstMetric(
				targetDescType,
				prometheus.GaugeValue,
				float64(expireHours),
				labelValues...)
		}
	}
}

func (c *certMetricsCollector) collectCABundles(ch chan<- prometheus.Metric) {
	configs, err := c.configLister.List(getCertificateManagedLabelSelector())
	if err != nil {
		klog.Warningf("Failed to list configmaps: %v", err)
		return
	}

	for _, config := range configs {
		if GetCertificateTypeFromObject(config) != CertificateTypeCABundle {
			klog.Warningf("ConfigMap %s/%s is not CA bundle type: %q", config.Namespace, config.Name, config.Labels[ManagedCertificateTypeLabelName])
			continue
		}

		if _, exists := config.Data["ca-bundle.crt"]; !exists {
			klog.V(4).Infof("ConfigMap %s/%s does not have 'ca-bundle.crt'", config.Namespace, config.Name)
			continue
		}
		certificates, err := cert.ParseCertsPEM([]byte(config.Data["ca-bundle.crt"]))
		if err != nil {
			klog.V(2).Infof("ConfigMap %s/%s 'ca-bundle.crt' has invalid certificates: %v", config.Namespace, config.Name, err)
			continue
		}

		for _, certificate := range certificates {
			expireHours := certificate.NotAfter.UTC().Sub(c.nowFn().UTC()).Hours()
			labelValues := []string{
				config.Namespace,
				config.Name,
				certificate.Subject.CommonName,
				certificate.Issuer.CommonName,
				fmt.Sprintf("%s", certificate.NotBefore.UTC()),
			}

			ch <- prometheus.MustNewConstMetric(
				caBundleExpireHoursDesc,
				prometheus.GaugeValue,
				float64(expireHours),
				labelValues...)
		}
	}
}

// This is needed to avoid double registration for prometheus metrics.
var registered bool

// Register registers certificate monitoring metrics.
func Register(configMaps corev1listers.ConfigMapLister, secrets corev1listers.SecretLister) {
	if registered {
		return
	}
	defer func() {
		registered = true
	}()
	collector := &certMetricsCollector{
		configLister: configMaps,
		secretLister: secrets,
		nowFn:        timeNowFn,
	}
	prometheus.MustRegister(collector)
	klog.Infof("Prometheus: Registered managed certificates monitoring metrics")
}

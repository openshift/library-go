package certrotation

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openshift/library-go/pkg/crypto"
)

var (
	defaultTimeNowFn = time.Now
)

var (
	caBundleExpireHoursDesc = prometheus.NewDesc(
		"cert_ca_bundle_expire_in_hours",
		"Number of hours until certificates in given CA bundle expire",
		[]string{"namespace", "name", "common_name", "signer_name", "index", "valid_from"}, nil)

	signerExpireHoursDesc = prometheus.NewDesc(
		"cert_signer_expire_in_hours",
		"Number of hours until certificates in given signer expire",
		[]string{"namespace", "name", "common_name", "signer_name", "index", "valid_from"}, nil)

	targetExpireHoursDesc = prometheus.NewDesc(
		"cert_target_expire_in_hours",
		"Number of hours until certificates in given target expire",
		[]string{"namespace", "name", "common_name", "signer_name", "index", "valid_from"}, nil)
)

type certExpirationMetricsCollector struct {
	configLister corev1listers.ConfigMapLister
	secretLister corev1listers.SecretLister

	nowFn func() time.Time
}

// Describe implements the prometheus collector interface
func (c *certExpirationMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- caBundleExpireHoursDesc
	ch <- signerExpireHoursDesc
	ch <- targetExpireHoursDesc
}

// Collect implements the prometheus collector interface
func (c *certExpirationMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	// to speed up collection, do this in parallel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.collectCABundles(ch) }()
	go func() { defer wg.Done(); c.collectSignersAndTarget(ch) }()
	wg.Wait()
}

func (c *certExpirationMetricsCollector) collectSignersAndTarget(ch chan<- prometheus.Metric) {
	secrets, err := c.secretLister.List(managedCertificateLabelSelector())
	if err != nil {
		klog.Warningf("Failed to list signer secrets: %v", err)
		return
	}

	for _, secret := range secrets {
		var targetDescType *prometheus.Desc

		certType, err := CertificateTypeFromObject(secret)
		if err != nil {
			klog.Warningf("Error determining certificate type from secret %s/%s: %v", secret.Namespace, secret.Name, err)
			continue
		}
		switch certType {
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

		labelValues := []string{}
		for i, certificate := range signingCertKeyPair.Config.Certs {
			expireHours := certificate.NotAfter.UTC().Sub(c.nowFn().UTC()).Hours()
			labelValues = append(labelValues, []string{
				secret.Namespace,
				secret.Name,
				certificate.Subject.CommonName,
				certificate.Issuer.CommonName,
				fmt.Sprintf("%d", i),
				fmt.Sprintf("%s", certificate.NotBefore.UTC()),
			}...)

			ch <- prometheus.MustNewConstMetric(
				targetDescType,
				prometheus.GaugeValue,
				float64(expireHours),
				labelValues...)
		}
	}
}

func (c *certExpirationMetricsCollector) collectCABundles(ch chan<- prometheus.Metric) {
	configs, err := c.configLister.List(managedCertificateLabelSelector())
	if err != nil {
		klog.Warningf("Failed to list configmaps: %v", err)
		return
	}

	for _, config := range configs {
		fmt.Printf("processing %q\n", config.Name)
		certType, err := CertificateTypeFromObject(config)
		if err != nil {
			klog.Warningf("Error determining certificate type from config map %s/%s: %v", config.Namespace, config.Name, err)
		}

		if certType != CertificateTypeCABundle {
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

		for i, certificate := range certificates {
			labelValues := []string{}
			expireHours := certificate.NotAfter.UTC().Sub(c.nowFn().UTC()).Hours()
			// Do not report negative hours, if cert expired, the hours to expiration is zero.
			if expireHours < 0 {
				expireHours = 0
			}
			labelValues = append(labelValues, []string{
				config.Namespace,
				config.Name,
				certificate.Subject.CommonName,
				certificate.Issuer.CommonName,
				fmt.Sprintf("%d", i),
				fmt.Sprintf("%s", certificate.NotBefore.UTC()),
			}...)

			sample := prometheus.MustNewConstMetric(
				caBundleExpireHoursDesc,
				prometheus.GaugeValue,
				float64(expireHours),
				labelValues...)

			ch <- sample
		}
	}
}

// managedCertificateLabelSelector returns a label selector that can be used in list or watch to filter
// only secrets or configmaps that are labeled as managed.
func managedCertificateLabelSelector() labels.Selector {
	selector, err := labels.Parse(fmt.Sprintf("%s in (%s)", ManagedCertificateTypeLabelName, strings.Join([]string{
		string(CertificateTypeCABundle),
		string(CertificateTypeTarget),
		string(CertificateTypeSigner),
	}, ",")))
	if err != nil {
		panic(err)
	}
	return selector
}

// registerOnce guarantee that this prometheus metric collector will only be registered once.
// TODO: Provide more reliable metric registration system in future.
var registerOnce sync.Once

// registerCertExpirationMetrics registers certificate monitoring metrics.
func registerCertExpirationMetrics(configMaps corev1listers.ConfigMapLister, secrets corev1listers.SecretLister) {
	registerOnce.Do(func() {
		collector := &certExpirationMetricsCollector{
			configLister: configMaps,
			secretLister: secrets,
			nowFn:        defaultTimeNowFn,
		}

		prometheus.MustRegister(collector)
		klog.Infof("Prometheus: Registered managed certificates monitoring metrics")
	})
}

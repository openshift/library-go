package certrotation

import (
	"crypto/x509/pkix"
	"math"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kcorelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/crypto"
)

func makeCABundleConfigMap(name string, certs *crypto.CA, t *testing.T) *v1.ConfigMap {
	caBundleConfigMap := v1.ConfigMap{}
	caBundleConfigMap.Namespace = "test"
	caBundleConfigMap.Name = name
	caBundleConfigMap.Labels = map[string]string{
		ManagedCertificateTypeLabelName: string(CertificateTypeCABundle),
	}
	if certs != nil {
		caBytes, err := crypto.EncodeCertificates(certs.Config.Certs[0], certs.Config.Certs[0])
		if err != nil {
			t.Fatal(err)
		}
		caBundleConfigMap.Data = map[string]string{}
		caBundleConfigMap.Data["ca-bundle.crt"] = string(caBytes)
	}

	return &caBundleConfigMap
}

func parseMetricOrDie(metric prometheus.Metric) dto.Metric {
	var out dto.Metric
	if err := metric.Write(&out); err != nil {
		panic(err)
	}
	return out
}

func findMetricByName(name string, metrics []prometheus.Metric) *dto.Metric {
	for _, m := range metrics {
		parsed := parseMetricOrDie(m)
		for _, label := range parsed.GetLabel() {
			if label.GetName() == "name" && label.GetValue() == name {
				return &parsed
			}
		}
	}
	return nil
}

func evaluateLabelValue(name, observed, expected string, t *testing.T) {
	if len(expected) == 0 {
		return
	}
	if observed != expected {
		t.Errorf("expected label %q to have value %q, got %q", name, expected, observed)
	}
}

func evaluateLabelPairs(labels []*dto.LabelPair, t *testing.T, common_name, name, namespace, signer_name, valid_from string) {
	if len(labels) != 6 {
		t.Errorf("expected 6 labels, got %d", len(labels))
		return
	}
	for _, label := range labels {
		switch label.GetName() {
		case "common_name":
			evaluateLabelValue(label.GetName(), label.GetValue(), common_name, t)
		case "name":
			evaluateLabelValue(label.GetName(), label.GetValue(), name, t)
		case "namespace":
			evaluateLabelValue(label.GetName(), label.GetValue(), namespace, t)
		case "signer_name":
			evaluateLabelValue(label.GetName(), label.GetValue(), signer_name, t)
		case "valid_from":
			evaluateLabelValue(label.GetName(), label.GetValue(), valid_from, t)
		case "index":
		default:
			t.Errorf("untested label name %q found", label.GetName())
		}
	}
}

func defaultEmptySecrets() []*v1.Secret {
	return []*v1.Secret{}
}

func TestCertExpirationMetricsCollector(t *testing.T) {
	testCases := []struct {
		name           string
		initialConfigs func() []*v1.ConfigMap
		initialSecrets func() []*v1.Secret

		evaluateMetrics         func([]prometheus.Metric, *testing.T)
		expectedMetricCollected int
	}{
		{
			name: "CA bundle config map with single certs expiring in 1 hour",
			initialConfigs: func() []*v1.ConfigMap {
				certs, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: time.Hour}, time.Now)
				if err != nil {
					t.Error(err)
				}
				return []*v1.ConfigMap{makeCABundleConfigMap("test-ca", certs, t)}
			},
			initialSecrets:          defaultEmptySecrets,
			expectedMetricCollected: 1,
			evaluateMetrics: func(metrics []prometheus.Metric, t *testing.T) {
				caMetric := parseMetricOrDie(metrics[0])
				if value := math.Round(caMetric.GetGauge().GetValue()); value != 1.0 {
					t.Errorf("expected validatity 1 (hour), got %f", value)
				}
				evaluateLabelPairs(caMetric.GetLabel(), t, "signer-tests", "test-ca", "test", "signer-tests", "")
			},
		},
		{
			name: "CA bundle config maps with single cert",
			initialConfigs: func() []*v1.ConfigMap {
				oneHourCert, err := newTestCACertificate(pkix.Name{CommonName: "maciej"}, int64(1), metav1.Duration{Duration: time.Hour}, time.Now)
				if err != nil {
					t.Error(err)
				}
				oneDayCert, err := newTestCACertificate(pkix.Name{CommonName: "stefan"}, int64(1), metav1.Duration{Duration: 24 * time.Hour}, time.Now)
				if err != nil {
					t.Error(err)
				}
				expiredCert, err := newTestCACertificate(pkix.Name{CommonName: "david"}, int64(1), metav1.Duration{Duration: time.Hour}, func() time.Time {
					return time.Now().Add(-24 * time.Hour)
				})
				if err != nil {
					t.Error(err)
				}
				return []*v1.ConfigMap{
					makeCABundleConfigMap("test-ca-1-hour", oneHourCert, t),
					makeCABundleConfigMap("test-ca-1-day", oneDayCert, t),
					makeCABundleConfigMap("test-ca-expired", expiredCert, t),
				}
			},
			initialSecrets:          defaultEmptySecrets,
			expectedMetricCollected: 6,
			evaluateMetrics: func(metrics []prometheus.Metric, t *testing.T) {
				caOneHourMetric := findMetricByName("test-ca-1-hour", metrics)
				if caOneHourMetric == nil {
					t.Errorf("test-ca-1-hour metric not found")
				}
				if value := math.Round(caOneHourMetric.GetGauge().GetValue()); value != 1.0 {
					t.Errorf("expected hours to expire 1, got %f", value)
				}
				evaluateLabelPairs(caOneHourMetric.GetLabel(), t, "maciej", "test-ca-1-hour", "test", "maciej", "")

				caOneDayMetric := findMetricByName("test-ca-1-day", metrics)
				if caOneDayMetric == nil {
					t.Errorf("test-ca-1-day metric not found")
				}
				if value := math.Round(caOneDayMetric.GetGauge().GetValue()); value != 24.0 {
					t.Errorf("expected hours to expire 24, got %f", value)
				}
				evaluateLabelPairs(caOneDayMetric.GetLabel(), t, "stefan", "test-ca-1-day", "test", "stefan", "")

				caExpiredMetric := findMetricByName("test-ca-expired", metrics)
				if caExpiredMetric == nil {
					t.Errorf("test-ca-expired metric not found")
				}
				if value := math.Round(caExpiredMetric.GetGauge().GetValue()); value != 0.0 {
					t.Errorf("expected hours to expire be zero, got %f", value)
				}
				evaluateLabelPairs(caExpiredMetric.GetLabel(), t, "david", "test-ca-expired", "test", "david", "")
			},
		},
		{
			name: "CA bundle config map with empty cert",
			initialConfigs: func() []*v1.ConfigMap {
				config := makeCABundleConfigMap("test-ca", nil, t)
				return []*v1.ConfigMap{config}
			},
			initialSecrets:          defaultEmptySecrets,
			expectedMetricCollected: 0,
			evaluateMetrics:         func(metrics []prometheus.Metric, t *testing.T) {},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secretIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			configIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			for _, config := range tc.initialConfigs() {
				if err := configIndexer.Add(config); err != nil {
					t.Fatal(err)
				}
			}
			for _, secret := range tc.initialSecrets() {
				if err := secretIndexer.Add(secret); err != nil {
					t.Fatal(err)
				}
			}

			c := &certExpirationMetricsCollector{
				configLister: kcorelisters.NewConfigMapLister(configIndexer),
				secretLister: kcorelisters.NewSecretLister(secretIndexer),
				nowFn:        defaultTimeNowFn,
			}

			// start metric collection, wait until expected metric count is reached
			collectedMetrics := []prometheus.Metric{}
			collectionChan := make(chan prometheus.Metric)

			stopChan := make(chan struct{})
			go func() {
				defer close(collectionChan)
				c.Collect(collectionChan)
				<-stopChan
			}()

			for {
				select {
				case m := <-collectionChan:
					collectedMetrics = append(collectedMetrics, m)
				case <-time.After(time.Second * 5):
					if len(collectedMetrics) != tc.expectedMetricCollected {
						t.Fatalf("timeout receiving expected results (got %d, expected %d)", len(collectedMetrics), tc.expectedMetricCollected)
					}
				}

				if len(collectedMetrics) == tc.expectedMetricCollected {
					close(stopChan)
					break
				}
			}

			tc.evaluateMetrics(collectedMetrics, t)
		})
	}

}

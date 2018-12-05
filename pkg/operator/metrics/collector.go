package metrics

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"

	"k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	operatorv1 "github.com/openshift/api/operator/v1"
)

const (
	openshiftOperatorNamePrefix = "operator_v1_openshift_io"
	workkey                     = "key"
)

// OperatorStateGetter knows how to get the current operator state and provides operator client informer.
type OperatorStateGetter interface {
	GetOperatorState() (spec *operatorv1.OperatorSpec, status *operatorv1.OperatorStatus, staticPodStatus *operatorv1.StaticPodOperatorStatus, resourceVersion string, err error)
	Informer() cache.SharedIndexInformer
}

// operatorMetricUpdater knows how to update a single tracked metric.
type operatorMetricUpdater interface {
	Update(*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, *operatorv1.StaticPodOperatorStatus) error
}

type operatorMetricUpdateFn func(*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, *operatorv1.StaticPodOperatorStatus) ([]metricValue, error)

type Collector struct {
	operatorClient  OperatorStateGetter
	operatorMetrics []operatorMetricUpdater
	targetNamespace string

	queue          workqueue.RateLimitingInterface
	hasSynced      cache.InformerSynced
	collectorMutex sync.RWMutex
}

// metricValue represents a single metric value sample
type metricValue struct {
	value  float64
	labels []string
}

// operatorMetrics represents a single metric definition
type operatorMetric struct {
	prometheusDesc *prometheus.Desc
	valueType      prometheus.ValueType

	// values are the recently observed metric values provided by the updateFn
	values []metricValue

	// updateFn know how to gather the values for this metric
	updateFn operatorMetricUpdateFn

	// valueMutex protects from values changes
	valueMutex sync.RWMutex
}

// Update updates the values for the current metric.
func (m *operatorMetric) Update(spec *operatorv1.OperatorSpec, status *operatorv1.OperatorStatus, staticPodStatus *operatorv1.StaticPodOperatorStatus) error {
	m.valueMutex.Lock()
	defer m.valueMutex.Unlock()
	currentValues, err := m.updateFn(spec, status, staticPodStatus)
	if err != nil {
		return err
	}
	m.values = currentValues
	return nil
}

// NewOperatorStatusMetricsCollector returns a metrics collector that automatically collect prometheus metrics from given operator status.
func NewOperatorStatusMetricsCollector(client OperatorStateGetter, targetOperatorNamespace string) *Collector {
	collector := &Collector{
		operatorClient:  client,
		targetNamespace: targetOperatorNamespace,
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "OperatorStatusMetricsCollector"),
		hasSynced:       client.Informer().HasSynced,
	}

	// register default set of metrics we track
	addStatusConditionsMetrics(collector)
	addStaticPodStatusLatestRevisionMetrics(collector)
	addStaticPodNodesMetrics(collector)

	client.Informer().AddEventHandler(collector.eventHandler())

	// NOTE: Only call this once and this must be called after all metrics are registered otherwise prometheus will panic.
	prometheus.MustRegister(collector)

	return collector
}

func (c *Collector) register(name, description string, valueType prometheus.ValueType, labelNames []string, updateFn operatorMetricUpdateFn) {
	c.collectorMutex.Lock()
	defer c.collectorMutex.Unlock()

	c.operatorMetrics = append(c.operatorMetrics, &operatorMetric{
		prometheusDesc: prometheus.NewDesc(
			metricNameToQuery(c.targetNamespace, name),
			description,
			labelNames,
			nil,
		),
		valueType: valueType,
		updateFn:  updateFn,
	})
}

// metricNameToQuery will produce prometheus friendly metric query name.
func metricNameToQuery(namespace, name string) string {
	return strings.Join([]string{openshiftOperatorNamePrefix, strings.Replace(namespace, "-", "_", -1), name}, "_")
}

func (c *Collector) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	glog.Infof("Starting MetricsCollector for %s", c.targetNamespace)
	defer glog.Infof("Shutting down MetricsCollector for %s", c.targetNamespace)

	if !cache.WaitForCacheSync(stopCh, c.hasSynced) {
		utilruntime.HandleError(fmt.Errorf("caches did not sync"))
		return
	}

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *Collector) sync() error {
	operatorSpec, operatorStatus, staticPodOperatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil && errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		glog.Warningf("Unable to get operator status: %v", err)
		return err
	}
	for _, m := range c.operatorMetrics {
		if err := m.Update(operatorSpec, operatorStatus, staticPodOperatorStatus); err != nil {
			glog.Warningf("Unable to update metrics for operator: %v", err)
		}
	}
	return nil
}

// Describe implements Prometheus Collector interface
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.collectorMutex.RLock()
	defer c.collectorMutex.RUnlock()
	for _, m := range c.operatorMetrics {
		ch <- m.(*operatorMetric).prometheusDesc
	}
}

// Collect implements Prometheus Collector interface
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectorMutex.RLock()
	c.collectorMutex.RUnlock()
	for _, m := range c.operatorMetrics {
		metric := m.(*operatorMetric)
		if metric.values == nil {
			continue
		}
		for _, s := range metric.values {
			ch <- prometheus.MustNewConstMetric(metric.prometheusDesc, metric.valueType, s.value, s.labels...)
		}
	}
}

func (c *Collector) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Collector) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.sync()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}

// eventHandler queues the operator to check spec and status
func (c *Collector) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(workkey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(workkey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(workkey) },
	}
}

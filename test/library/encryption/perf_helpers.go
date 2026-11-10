package encryption

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/openshift/api/operator/v1"
	test "github.com/openshift/library-go/test/library"
)

func watchForMigrationControllerProgressingConditionAsync(t testing.TB, getOperatorCondFn GetOperatorConditionsFuncType, migrationStartedCh chan time.Time) {
	t.Helper()
	go watchForMigrationControllerProgressingCondition(t, getOperatorCondFn, migrationStartedCh)
}

// migrationProgressingPollInterval is intentionally tighter than waitPollInterval.
// Auth/OAS migrations with few objects can flip Progressing True→False in well under
// 15s; a coarse poll misses the window and leaves migration timing unobservable.
const migrationProgressingPollInterval = time.Second

func watchForMigrationControllerProgressingCondition(t testing.TB, getOperatorConditionsFn GetOperatorConditionsFuncType, migrationStartedCh chan time.Time) {
	t.Helper()

	t.Logf("Waiting up to %s for the condition %q with the reason %q to be set to true", waitPollTimeout.String(), "EncryptionMigrationControllerProgressing", "Migrating")
	err := wait.Poll(migrationProgressingPollInterval, waitPollTimeout, func() (bool, error) {
		conditions, err := getOperatorConditionsFn(t)
		if err != nil {
			if transientAPIError(err) {
				t.Logf("failed to get operator conditions, will retry: %v", err)
				return false, nil
			}
			return false, err
		}
		for _, cond := range conditions {
			if cond.Type == "EncryptionMigrationControllerProgressing" && cond.Status == operatorv1.ConditionTrue {
				t.Logf("EncryptionMigrationControllerProgressing condition observed at %v", cond.LastTransitionTime)
				migrationStartedCh <- cond.LastTransitionTime.Time
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Logf("failed waiting for the condition %q with the reason %q to be set to true, err was %v", "EncryptionMigrationControllerProgressing", "Migrating", err)
	}
}

func populateDatabase(t testing.TB, workers int, dbLoaderFun DBLoaderFuncType, assertDBPopulatedFunc func(t testing.TB, errorStore map[string]int, statStore map[string]int)) {
	t.Helper()
	start := time.Now()
	defer func() {
		end := time.Now()
		t.Logf("Populating etcd took %v", end.Sub(start))
	}()

	r := newRunner()

	// run executes loaderFunc for each worker
	r.run(t, workers, dbLoaderFun)

	assertDBPopulatedFunc(t, r.errorStore, r.statsStore)
}

type DBLoaderFuncType func(kubernetes.Interface, string, func(error) /*error collector*/, func(string) /*stats collector*/) error

type runner struct {
	errorStore map[string]int
	lock       *sync.Mutex

	statsStore map[string]int
	lockStats  *sync.Mutex
	wg         *sync.WaitGroup
}

func newRunner() *runner {
	r := &runner{}

	r.errorStore = map[string]int{}
	r.lock = &sync.Mutex{}
	r.statsStore = map[string]int{}
	r.lockStats = &sync.Mutex{}

	r.wg = &sync.WaitGroup{}

	return r
}

func (r *runner) run(t testing.TB, workers int, workFunc ...DBLoaderFuncType) {
	t.Logf("Executing provided load function for %d workers", workers)
	for i := 0; i < workers; i++ {
		wrapper := func(wg *sync.WaitGroup) {
			defer wg.Done()
			kubeClient, err := newKubeClient(300, 600)
			if err != nil {
				t.Errorf("Unable to create a kube client for a worker due to %v", err)
				r.collectError(err)
				return
			}
			_ = runWorkFunctions(kubeClient, "", r.collectError, r.collectStat, workFunc...)
		}
		r.wg.Add(1)
		go wrapper(r.wg)
	}
	r.wg.Wait()
	t.Log("All workers completed successfully")
}

func (r *runner) collectError(err error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	errCount, ok := r.errorStore[err.Error()]
	if !ok {
		r.errorStore[err.Error()] = 1
		return
	}
	errCount += 1
	r.errorStore[err.Error()] = errCount
}

func (r *runner) collectStat(stat string) {
	r.lockStats.Lock()
	defer r.lockStats.Unlock()
	statCount, ok := r.statsStore[stat]
	if !ok {
		r.statsStore[stat] = 1
		return
	}
	statCount += 1
	r.statsStore[stat] = statCount
}

func runWorkFunctions(kubeClient kubernetes.Interface, namespace string, errorCollector func(error), statsCollector func(string), workFunc ...DBLoaderFuncType) error {
	if len(namespace) == 0 {
		namespace = createNamespaceName()
	}
	for _, work := range workFunc {
		err := work(kubeClient, namespace, errorCollector, statsCollector)
		if err != nil {
			errorCollector(err)
			return err
		}
	}
	return nil
}

func DBLoaderRepeat(times int, genNamespaceName bool, workToRepeatFunc ...DBLoaderFuncType) DBLoaderFuncType {
	return DBLoaderRepeatParallel(times, 1, genNamespaceName, workToRepeatFunc...)
}

func DBLoaderRepeatParallel(times int, workers int, genNamespaceName bool, workToRepeatFunc ...DBLoaderFuncType) DBLoaderFuncType {
	return func(kubeClient kubernetes.Interface, namespace string, errorCollector func(error), statsCollector func(string)) error {
		if times < workers {
			panic("DBLoaderRepeat cannot be < workers")
		}
		wg := sync.WaitGroup{}
		workPerWorker := times / workers
		for w := 0; w < workers; w++ {
			work := func() {
				defer wg.Done()
				for i := 0; i < workPerWorker; i++ {
					if genNamespaceName {
						namespace = createNamespaceName()
					}
					if err := runWorkFunctions(kubeClient, namespace, errorCollector, statsCollector, workToRepeatFunc...); err != nil {
						errorCollector(err)
					}
				}
			}
			wg.Add(1)
			go work()
		}
		wg.Wait()
		return nil
	}
}

const apiWorkloadPayloadSize = 1024

func apiWorkloadPayload(seed int) []byte {
	payload := make([]byte, apiWorkloadPayloadSize)
	for i := range payload {
		payload[i] = byte(seed + i)
	}
	return payload
}

// APIWorkloadConfig configures a secret create/get/list latency workload.
type APIWorkloadConfig struct {
	Workers int
	Creates int
	Gets    int // requires Creates > 0
	Lists   int // requires Creates > 0
}

// APIWorkloadResult holds latency samples from one RunAPIWorkload call.
type APIWorkloadResult struct {
	Latencies map[string][]time.Duration
	Errors    map[string]int
	Duration  time.Duration
	Workers   int
}

func (r *APIWorkloadResult) Count(op string) int {
	return len(r.Latencies[op])
}

func (r *APIWorkloadResult) Percentile(op string, p float64) time.Duration {
	samples := r.Latencies[op]
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx > len(sorted)-1 {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func (r *APIWorkloadResult) Throughput() float64 {
	if r.Duration == 0 {
		return 0
	}
	var ops int
	for _, samples := range r.Latencies {
		ops += len(samples)
	}
	return float64(ops) / r.Duration.Seconds()
}

func (r *APIWorkloadResult) Summary() string {
	ops := make([]string, 0, len(r.Latencies))
	for op := range r.Latencies {
		ops = append(ops, op)
	}
	sort.Strings(ops)

	var b strings.Builder
	for _, op := range ops {
		fmt.Fprintf(&b, "%s: n=%d p50=%s p95=%s p99=%s\n", op,
			r.Count(op), r.Percentile(op, 50), r.Percentile(op, 95), r.Percentile(op, 99))
	}
	fmt.Fprintf(&b, "throughput: %.1f ops/s over %s with %d workers\n", r.Throughput(), r.Duration, r.Workers)
	return b.String()
}

// RunAPIWorkload runs a secret create/get/list workload and returns latency samples.
// Workload namespaces are deleted before return so baseline secrets do not inflate
// a following encryption migration.
func RunAPIWorkload(ctx context.Context, t testing.TB, config APIWorkloadConfig) *APIWorkloadResult {
	t.Helper()
	require.Greater(t, config.Workers, 0, "APIWorkloadConfig.Workers must be > 0")
	require.GreaterOrEqual(t, config.Creates, 0, "APIWorkloadConfig.Creates must be >= 0")
	require.GreaterOrEqual(t, config.Gets, 0, "APIWorkloadConfig.Gets must be >= 0")
	require.GreaterOrEqual(t, config.Lists, 0, "APIWorkloadConfig.Lists must be >= 0")
	require.Greater(t, config.Creates+config.Gets+config.Lists, 0,
		"APIWorkloadConfig requires at least one operation per worker")
	require.False(t, config.Gets > 0 && config.Creates == 0,
		"APIWorkloadConfig.Gets requires Creates > 0: gets read back the secrets the workload creates")
	require.False(t, config.Lists > 0 && config.Creates == 0,
		"APIWorkloadConfig.Lists requires Creates > 0: lists must read namespaces that contain secrets")

	result := &APIWorkloadResult{
		Latencies: map[string][]time.Duration{},
		Errors:    map[string]int{},
		Workers:   config.Workers,
	}
	var mu sync.Mutex
	record := func(op string, latency time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		result.Latencies[op] = append(result.Latencies[op], latency)
	}
	recordError := func(op string, err error) {
		mu.Lock()
		defer mu.Unlock()
		result.Errors[fmt.Sprintf("%s: %v", op, err)]++
	}

	var (
		namespaces []string
		nsMu       sync.Mutex
	)
	trackNamespace := func(namespace string) {
		nsMu.Lock()
		defer nsMu.Unlock()
		namespaces = append(namespaces, namespace)
	}

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < config.Workers; i++ {
		wg.Go(func() {
			kubeClient, err := newKubeClient(300, 600)
			if err != nil {
				recordError("client", err)
				return
			}
			runAPIWorkloadWorker(ctx, kubeClient, config, record, recordError, trackNamespace)
		})
	}
	wg.Wait()
	result.Duration = time.Since(start)

	cleanupAPIWorkloadNamespaces(ctx, t, namespaces)

	require.Empty(t, result.Errors, "API workload operations failed")
	t.Logf("API workload summary (workers=%d, duration=%s):\n%s", config.Workers, result.Duration, result.Summary())
	return result
}

func runAPIWorkloadWorker(ctx context.Context, kubeClient kubernetes.Interface, config APIWorkloadConfig, record func(string, time.Duration), recordError func(string, error), trackNamespace func(string)) {
	namespace := createNamespaceName()
	if _, err := kubeClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil && !errors.IsAlreadyExists(err) {
		recordError("create-namespace", err)
		return
	}
	trackNamespace(namespace)

	for i := 0; i < config.Creates; i++ {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("workload-secret-%d", i)},
			Data:       map[string][]byte{"payload": apiWorkloadPayload(i)},
		}
		start := time.Now()
		_, err := kubeClient.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
		record("create", time.Since(start))
		if err != nil && !errors.IsAlreadyExists(err) {
			recordError("create", err)
		}
	}

	for i := 0; i < config.Gets; i++ {
		name := fmt.Sprintf("workload-secret-%d", i%config.Creates)
		start := time.Now()
		_, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		record("get", time.Since(start))
		if err != nil {
			recordError("get", err)
		}
	}

	for i := 0; i < config.Lists; i++ {
		start := time.Now()
		_, err := kubeClient.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
		record("list", time.Since(start))
		if err != nil {
			recordError("list", err)
		}
	}
}

func cleanupAPIWorkloadNamespaces(ctx context.Context, t testing.TB, namespaces []string) {
	t.Helper()
	if len(namespaces) == 0 {
		return
	}
	kubeClient, err := newKubeClient(50, 100)
	if err != nil {
		t.Errorf("unable to create kube client for API workload cleanup: %v", err)
		return
	}
	var wg sync.WaitGroup
	for _, namespace := range namespaces {
		wg.Go(func() {
			if err := kubeClient.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
				t.Errorf("failed to delete API workload namespace %q: %v", namespace, err)
				return
			}
			err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
				_, err := kubeClient.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
				if errors.IsNotFound(err) {
					return true, nil
				}
				return false, nil
			})
			if err != nil {
				t.Errorf("timed out waiting for API workload namespace %q to be deleted: %v", namespace, err)
			}
		})
	}
	wg.Wait()
}

func createNamespaceName() string {
	return fmt.Sprintf("encryption-%s", rand.String(10))
}

func newKubeClient(qps float32, burst int) (kubernetes.Interface, error) {
	kubeConfig, err := test.NewClientConfigForTest()
	if err != nil {
		return nil, err
	}

	kubeConfig.QPS = qps
	kubeConfig.Burst = burst

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return kubeClient, nil
}

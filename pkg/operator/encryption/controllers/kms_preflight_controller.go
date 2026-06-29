package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"

	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

type kmsConfigHasher struct {
	provider   kmsProviderConfig
	coreClient corev1client.CoreV1Interface
	namespace  string
}

// newKMSConfigHasher creates a hasher for a KMS provider config and its referenced resources.
// namespace is the namespace where the referenced Secrets and ConfigMaps are stored (e.g., openshift-config).
func newKMSConfigHasher(provider kmsProviderConfig, coreClient corev1client.CoreV1Interface, namespace string) *kmsConfigHasher {
	return &kmsConfigHasher{provider: provider, coreClient: coreClient, namespace: namespace}
}

// hash computes a deterministic hash over the provider config and the specific data keys
// from its referenced Secret and ConfigMap. Uses FNV-32, JSON encoding, and base64 URL
// encoding, consistent with resourcehash.GetSecretHash and resourcehash.GetConfigMapHash.
func (h *kmsConfigHasher) hash(ctx context.Context) (string, error) {
	hasher := fnv.New32()

	if err := json.NewEncoder(hasher).Encode(h.provider.sourceConfig()); err != nil {
		return "", fmt.Errorf("failed to hash provider config: %w", err)
	}

	if err := h.hashReferencedSecret(ctx, hasher); err != nil {
		return "", err
	}
	if err := h.hashReferencedConfigMap(ctx, hasher); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

func (h *kmsConfigHasher) hashReferencedSecret(ctx context.Context, hasher hash.Hash) error {
	name, keys, err := h.provider.referencedSecretName()
	if err != nil {
		return fmt.Errorf("failed to get referenced secret name: %w", err)
	}
	if name == "" {
		return nil
	}

	secret, err := h.coreClient.Secrets(h.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get secret %s/%s: %w", h.namespace, name, err)
	}

	// Write each key name before its value to prevent collisions when bytes
	// shift between adjacent values (e.g. role-id="ab",secret-id="cd" vs
	// role-id="abc",secret-id="d" would otherwise both hash as "abcd").
	sort.Strings(keys)
	for _, k := range keys {
		v, ok := secret.Data[k]
		if !ok {
			return fmt.Errorf("key %q not found in secret %s/%s", k, h.namespace, name)
		}
		if _, err := hasher.Write([]byte(k)); err != nil {
			return fmt.Errorf("failed to hash key %q: %w", k, err)
		}
		if _, err := hasher.Write(v); err != nil {
			return fmt.Errorf("failed to hash key %q: %w", k, err)
		}
	}
	return nil
}

func (h *kmsConfigHasher) hashReferencedConfigMap(ctx context.Context, hasher hash.Hash) error {
	name, keys, err := h.provider.referencedConfigMapName()
	if err != nil {
		return fmt.Errorf("failed to get referenced configmap name: %w", err)
	}
	if name == "" {
		return nil
	}

	cm, err := h.coreClient.ConfigMaps(h.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get configmap %s/%s: %w", h.namespace, name, err)
	}

	sort.Strings(keys)
	for _, k := range keys {
		v, ok := cm.Data[k]
		if !ok {
			return fmt.Errorf("key %q not found in configmap %s/%s", k, h.namespace, name)
		}
		if _, err := hasher.Write([]byte(k)); err != nil {
			return fmt.Errorf("failed to hash key %q: %w", k, err)
		}
		if _, err := hasher.Write([]byte(v)); err != nil {
			return fmt.Errorf("failed to hash key %q: %w", k, err)
		}
	}
	return nil
}

// KMSPreflightDeployer abstracts the lifecycle of a preflight workload that
// validates KMS plugin configuration before an encryption key is created.
// All methods are idempotent.
//
// Deploy creates all resources the workload needs (ServiceAccount, Secret,
// RBAC, Pod). The controller only calls Deploy when Status reports no pod
// exists, so no running pod can be affected.
//
// Cleanup removes all resources created by Deploy.
type KMSPreflightDeployer interface {
	// Deploy creates the preflight workload with the given config hash
	// and encryption configuration. It is idempotent.
	Deploy(ctx context.Context, configHash string, encryptionConfiguration *corev1.Secret) error

	// Status returns the current pod status of the preflight workload.
	// It returns an apierrors.IsNotFound error when no preflight pod exists.
	Status(ctx context.Context) (corev1.PodStatus, error)

	// Cleanup removes all resources created by Deploy.
	Cleanup(ctx context.Context) error
}

type kmsPreflightController struct {
	controllerInstanceName string

	operatorClient  operatorv1helpers.OperatorClient
	apiServerClient configv1client.APIServerInterface
	coreClient      corev1client.CoreV1Interface

	deployer                 KMSPreflightDeployer
	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled
}

// NewKMSPreflightController validates KMS configuration before a key is created.
//
// Coordination with the key-controller:
//
// The key-controller writes a hash of the current KMS config to operator status
// as the EncryptionKMSPreflightRequired condition (hash in the message).
// This controller reads that hash, runs preflight checks, and on success sets
// the EncryptionKMSPreflightSucceeded condition (same hash in the message).
// The key-controller waits for the two hashes to match before creating a key.
//
// This is the same pattern used by the revision and installer controllers:
// the revision controller writes LatestAvailableRevision, the installer
// controller reads it and acts.
//
// Without this protocol the following race can occur:
//  1. Preflight passes for config A, hash A written to operator status.
//  2. Key-controller reads hash A, starts creating a key for config A.
//  3. Config changes to B.
//  4. Preflight controller syncs, sees config B, does not yet see the key
//     for A (key-controller is in the process of creating the key),
//     runs preflight for B, overwrites status with hash B.
//  5. The key created in step 2 was for config A but status now says B.
//
// Letting the key-controller own EncryptionKMSPreflightRequired and this
// controller own EncryptionKMSPreflightSucceeded solves this. If the config
// changes mid-flight the key-controller posts a new hash and the preflight
// controller sees the mismatch and waits.
//
// Example 1: config changes before key is created
//  1. User creates KMS config A.
//  2. Key-controller computes hash A, writes EncryptionKMSPreflightRequired=A.
//  3. Preflight controller sees required=A, starts checking A.
//  4. User changes config to A2 (minor variation, different hash).
//  5. Key-controller computes hash A2, writes EncryptionKMSPreflightRequired=A2.
//  6. Preflight controller sees required=A2, starts checking A2.
//  7. Key-controller does not create a key until succeeded=A2.
//
// Example 2: config changes after key is created
//  1. User creates KMS config A.
//  2. Key-controller computes hash A, writes EncryptionKMSPreflightRequired=A.
//  3. Preflight controller checks A, succeeds, writes EncryptionKMSPreflightSucceeded=A.
//  4. Key-controller sees required=A matches succeeded=A, creates key for A.
//  5. User changes config to A2 (or B).
//  6. Key-controller waits until the key for A completes the full cycle
//     (read, write, migrated) before creating a new key. No preflight done
//     at this stage.
//
// Preflight workload:
//
// A deployer interface abstracts the workload creation. Each operator provides
// its own implementation that knows how to install, get status, clean up the
// preflight workload, and wire the credentials needed to update pod status.
// The workload type matches the API server it validates (static pod for kas-o,
// Deployment for aggregated API servers).
//
// When an existing KMS plugin is already configured, the checker runs the new
// plugin alongside the existing one to catch co-existence issues (e.g., metric
// port collisions). When no plugin is configured yet, it runs the new plugin alone.
// The sync method reads existing encryption key secrets to determine whether
// a plugin is already configured.
//
// The pod uses readiness gates to post check results back to the controller.
// To set the readiness gate condition, the pod PATCHes its own status using
// credentials wired by the deployer.
// The controller reads these enhanced pod statuses to update its own operator
// status, which is propagated to end users.
//
// After a successful check the preflight pod is kept for a short period (e.g. 1h)
// so that its logs can be inspected, then cleaned up by a subsequent sync.
func NewKMSPreflightController(
	instanceName string,
	provider Provider,
	preconditionsFulfilledFn preconditionsFulfilled,
	deployer KMSPreflightDeployer,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	apiServerInformer configv1informers.APIServerInformer,
// coreClient reads referenced Secrets and ConfigMaps in openshift-config for hash
// computation. No informer is needed: the key-controller detects config changes and
// posts a new EncryptionKMSPreflightRequired condition, which triggers this controller
// via the operatorClient informer. The minute-based resync covers the rest.
	coreClient corev1client.CoreV1Interface,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &kmsPreflightController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "EncryptionKMSPreflight"),

		operatorClient:  operatorClient,
		apiServerClient: apiServerClient,
		coreClient:      coreClient,

		deployer:                 deployer,
		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
	}

	return factory.New().
		WithSync(c.sync).
		WithControllerInstanceName(c.controllerInstanceName).
		ResyncEvery(time.Minute).
		WithInformers(
			apiServerInformer.Informer(),
			operatorClient.Informer(),
		).ToController(
		c.controllerInstanceName,
		eventRecorder.WithComponentSuffix("encryption-kms-preflight-controller"),
	)
}

func (c *kmsPreflightController) sync(ctx context.Context, syncCtx factory.SyncContext) (err error) {
	var requiredHash string
	var podStatus *corev1.PodStatus
	var preflightErr error

	defer func() {
		if statusErr := c.updatePreflightStatus(ctx, requiredHash, podStatus, preflightErr); statusErr != nil {
			err = statusErr
		}
	}()

	if ready, err := shouldRunEncryptionController(c.operatorClient, c.preconditionsFulfilledFn, c.provider.ShouldRunEncryptionControllers); err != nil || !ready {
		return err
	}

	var requeue bool
	requiredHash, podStatus, requeue, preflightErr = c.runPreflightChecks(ctx)
	if requeue {
		syncCtx.Queue().AddAfter(syncCtx.QueueKey(), 30*time.Second)
	}
	return preflightErr
}

// updatePreflightStatus sets EncryptionKMSPreflightControllerDegraded,
// EncryptionKMSPreflightControllerProgressing, and
// EncryptionKMSPreflightSucceeded operator conditions based on the values
// returned by runPreflightChecks.
//
// Degraded scenarios:
//
//  1. runPreflightChecks returned a non-nil error (deploy failure, pod
//     crash, check failure, status error). Set True with reason Error.
//
//  2. Pod exists, no error was returned, but the pod has not reported its
//     config hash or result within the startup timeout (2m). Set True with
//     reason PodStuck. The message includes why the pod is stuck (e.g.
//     ImagePullBackOff, Pending phase).
//
//  3. Otherwise set False (no preflight needed, pod running within timeout,
//     check passed).
//
// Progressing scenarios:
//
//  1. Preflight is required (requiredHash is non-empty), no error was
//     returned, and the pod has not yet reported a successful result. Set
//     True with reason PreflightRunning. This covers initial deploy,
//     waiting for the pod to start, and waiting for the checker to finish.
//
//  2. Otherwise set False (no preflight needed, check succeeded, or check
//     failed — in the failure case the admin must update the config before
//     any further progress can be made).
//
// Succeeded scenarios:
//
//  1. Preflight is required and the pod has reported a successful result.
//     Set True with the config hash in the message to signal the key
//     controller that the KMS config is valid.
//
//  2. Otherwise set False. A transient precondition error may briefly flip
//     this to False even though the check previously passed; the consumer
//     (key controller) reads this condition promptly so the flip is
//     acceptable. This condition will be replaced by a direct API call.
func (c *kmsPreflightController) updatePreflightStatus(ctx context.Context, requiredHash string, podStatus *corev1.PodStatus, preflightErr error) error {
	degraded := applyoperatorv1.OperatorCondition().WithType("EncryptionKMSPreflightControllerDegraded")
	progressing := applyoperatorv1.OperatorCondition().WithType("EncryptionKMSPreflightControllerProgressing")

	var degradedStatus operatorv1.ConditionStatus
	var degradedReason, degradedMessage string

	switch {
	case preflightErr != nil:
		// Degraded scenario 1: runPreflightChecks returned an error.
		degradedStatus = operatorv1.ConditionTrue
		var pe *preflightError
		if errors.As(preflightErr, &pe) {
			degradedReason = pe.reason
		} else {
			degradedReason = "Error"
		}
		degradedMessage = preflightErr.Error()
	case podStatus != nil:
		// Degraded scenario 2: pod exists but is stuck past the startup timeout.
		// Degraded scenario 3: pod exists, no error, not stuck.
		if pe := podStuckError(*podStatus); pe != nil {
			degradedStatus = operatorv1.ConditionTrue
			degradedReason = pe.reason
			degradedMessage = pe.message
		} else {
			degradedStatus = operatorv1.ConditionFalse
			degradedReason = "AsExpected"
		}
	default:
		// Degraded scenario 3: no pod, no error — either no preflight
		// needed, or the pod was just deployed and has not appeared in
		// Status yet (Progressing will be True in that case).
		degradedStatus = operatorv1.ConditionFalse
		degradedReason = "AsExpected"
	}

	degraded.WithStatus(degradedStatus).WithReason(degradedReason).WithMessage(degradedMessage)

	// Progressing scenario 1: preflight required, no error, not yet succeeded.
	if requiredHash != "" && preflightErr == nil && !preflightSucceeded(podStatus) {
		progressing.WithStatus(operatorv1.ConditionTrue).
			WithReason("PreflightRunning").
			WithMessage("preflight check in progress")
	} else {
		// Progressing scenario 2: no preflight needed, succeeded, or failed.
		progressing.WithStatus(operatorv1.ConditionFalse).
			WithReason("AsExpected")
	}

	// Succeeded: signals the key controller that the KMS config is valid.
	// This must be included in every apply call because SSA removes
	// conditions that a field manager previously owned but omits from a
	// subsequent apply. The consumer (key controller) reads this condition
	// promptly so a brief flip to False on transient errors is acceptable.
	// TODO: replace this condition with a direct API call (see the TODO in
	// runPreflightChecks scenario 3e).
	succeeded := applyoperatorv1.OperatorCondition().WithType("EncryptionKMSPreflightSucceeded")
	if requiredHash != "" && preflightSucceeded(podStatus) {
		succeeded.WithStatus(operatorv1.ConditionTrue).
			WithReason("PreflightCheckPassed").
			WithMessage(requiredHash)
	} else {
		succeeded.WithStatus(operatorv1.ConditionFalse).
			WithReason("AsExpected")
	}

	status := applyoperatorv1.OperatorStatus().WithConditions(degraded, progressing, succeeded)
	return c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status)
}

// Pod readiness gate condition types set by the preflight checker running inside
// the pod. The checker PATCHes its own pod status with these conditions.
const (
	// PodConditionKMSPreflightConfigHash carries the config hash the pod was
	// deployed for. The controller compares this against the required hash to
	// detect stale pods from a previous config.
	PodConditionKMSPreflightConfigHash corev1.PodConditionType = "KMSPreflightConfigHash"

	// PodConditionKMSPreflightResult carries the outcome of the preflight check.
	// Status True means the check passed; False means it failed, with details
	// in the condition message.
	PodConditionKMSPreflightResult corev1.PodConditionType = "KMSPreflightResult"
)

const preflightPodRetention = 1 * time.Hour
const preflightPodStartupTimeout = 2 * time.Minute

// runPreflightChecks manages the preflight pod lifecycle across sync iterations.
// It returns the required config hash (empty when no preflight is needed), the
// current pod status (nil when no pod exists), whether to requeue, and any error.
// The caller uses these to set operator conditions via updatePreflightStatus.
//
// Scenarios:
//
//  1. No preflight required (condition absent, False, or hash mismatch in preflightRequired).
//     Cleanup any lingering resources (pod, SA, RBAC) from a previous run.
//
//  2. Preflight required, no pod exists (Status returns NotFound).
//     Call Deploy. On success, requeue and wait for the pod to report results.
//     If Deploy fails, report the error.
//
//  3. Preflight required, pod exists (Status returns a PodStatus).
//     Evaluate the pod state via readiness-gate conditions and phase:
//
//     a) Pod phase is Failed — the pod crashed before or after posting
//     conditions. Report degraded and keep the pod for inspection. The
//     admin fixes the config, which triggers a new hash and cleanup
//     via scenario (c).
//
//     b) No KMSPreflightConfigHash condition yet — the checker has not
//     started reporting. If the pod phase is Succeeded, it exited
//     without reporting; return an error immediately. Otherwise, if
//     within the startup timeout (2m), wait. If past the timeout,
//     report degraded with the reason the pod is stuck (e.g.
//     ImagePullBackOff, Pending).
//
//     c) KMSPreflightConfigHash does not match the required hash — stale
//     pod from a previous config. Clean up; next sync deploys fresh.
//
//     d) Hash matches, no KMSPreflightResult yet — check is running.
//     If the pod phase is Succeeded, it exited without reporting the
//     result; return an error immediately. Otherwise, if within the
//     startup timeout, wait. If past the timeout, report degraded.
//
//     e) Hash matches, KMSPreflightResult is True — check passed. Set the
//     EncryptionKMSPreflightSucceeded operator condition. Keep the pod
//     for retention (1h), then clean up.
//
//     f) Hash matches, KMSPreflightResult is False — check failed. Report
//     degraded with the failure message. Keep the pod for inspection.
//     The admin fixes the config, which triggers a new hash and cleanup
//     via scenario (c).
func (c *kmsPreflightController) runPreflightChecks(ctx context.Context) (requiredHash string, preflightPodStatus *corev1.PodStatus, requeue bool, err error) {
	requiredHash, err = c.preflightRequired(ctx)
	if err != nil {
		return "", nil, false, err
	}

	// Scenario 1: no preflight required, cleanup lingering resources.
	if requiredHash == "" {
		return "", nil, false, c.deployer.Cleanup(ctx)
	}

	// Check whether a preflight pod already exists.
	podStatus, err := c.deployer.Status(ctx)

	// Scenario 2: no pod exists, deploy a new one.
	if apierrors.IsNotFound(err) {
		return requiredHash, nil, true, c.deployer.Deploy(ctx, requiredHash, nil)
	}
	if err != nil {
		return requiredHash, nil, false, fmt.Errorf("failed to get preflight pod status: %w", err)
	}

	// Scenario 3a: pod crashed. Keep for inspection; the admin will update
	// the config which triggers a new hash and cleanup via scenario 3c.
	if podStatus.Phase == corev1.PodFailed {
		pe := podFailureError(podStatus)
		pe.message = fmt.Sprintf("preflight pod failed for hash %s: %s", requiredHash, pe.message)
		return requiredHash, &podStatus, false, pe
	}

	// Scenario 3b: pod has not reported its config hash yet.
	hashCondition := findPodCondition(podStatus.Conditions, PodConditionKMSPreflightConfigHash)
	if hashCondition == nil {
		if podStatus.Phase == corev1.PodSucceeded {
			return requiredHash, &podStatus, false, &preflightError{reason: "PodCompletedWithoutResult", message: fmt.Sprintf("preflight pod completed without reporting result for hash %s", requiredHash)}
		}
		return requiredHash, &podStatus, true, nil
	}

	// Scenario 3c: stale pod from a different config.
	if hashCondition.Message != requiredHash {
		return requiredHash, nil, true, c.deployer.Cleanup(ctx)
	}

	// Scenario 3d: hash matches, waiting for result.
	resultCondition := findPodCondition(podStatus.Conditions, PodConditionKMSPreflightResult)
	if resultCondition == nil {
		if podStatus.Phase == corev1.PodSucceeded {
			return requiredHash, &podStatus, false, &preflightError{reason: "PodCompletedWithoutResult", message: fmt.Sprintf("preflight pod completed without reporting result for hash %s", requiredHash)}
		}
		return requiredHash, &podStatus, true, nil
	}

	// Scenario 3e: check passed.
	// TODO: replace the EncryptionKMSPreflightSucceeded condition (set in
	// updatePreflightStatus) with a direct API call here.
	if resultCondition.Status == corev1.ConditionTrue {
		return requiredHash, &podStatus, false, c.cleanupAfterRetention(ctx, resultCondition.LastTransitionTime.Time)
	}

	// Scenario 3f: check failed. Keep pod for inspection; the admin will
	// update the config which triggers a new hash and cleanup via scenario 3c.
	return requiredHash, &podStatus, false, &preflightError{
		reason:  "PreflightCheckFailed",
		message: fmt.Sprintf("preflight check failed for hash %s: %s", requiredHash, resultCondition.Message),
	}
}


func (c *kmsPreflightController) cleanupAfterRetention(ctx context.Context, completedAt time.Time) error {
	age := time.Since(completedAt)
	if age < preflightPodRetention {
		klog.V(4).Infof("Preflight pod completed %s ago, keeping for inspection (retention %s)", age.Truncate(time.Second), preflightPodRetention)
		return nil
	}
	klog.V(2).Infof("Preflight pod retention period elapsed (%s), cleaning up", preflightPodRetention)
	return c.deployer.Cleanup(ctx)
}

type preflightError struct {
	reason  string
	message string
}

func (e *preflightError) Error() string { return e.message }

func podFailureError(podStatus corev1.PodStatus) *preflightError {
	for _, cs := range podStatus.ContainerStatuses {
		if cs.State.Terminated != nil && cs.State.Terminated.ExitCode != 0 {
			reason := cs.State.Terminated.Reason
			if reason == "" {
				reason = "Error"
			}
			msg := fmt.Sprintf("container %s exited with %d", cs.Name, cs.State.Terminated.ExitCode)
			if cs.State.Terminated.Message != "" {
				msg = fmt.Sprintf("%s: %s", msg, cs.State.Terminated.Message)
			}
			return &preflightError{reason: reason, message: msg}
		}
	}
	if podStatus.Message != "" {
		return &preflightError{reason: "Unknown", message: podStatus.Message}
	}
	return &preflightError{reason: "Unknown", message: "unknown"}
}

func preflightSucceeded(podStatus *corev1.PodStatus) bool {
	if podStatus == nil {
		return false
	}
	resultCondition := findPodCondition(podStatus.Conditions, PodConditionKMSPreflightResult)
	return resultCondition != nil && resultCondition.Status == corev1.ConditionTrue
}

func podStuckError(podStatus corev1.PodStatus) *preflightError {
	if podStatus.StartTime == nil || time.Since(podStatus.StartTime.Time) <= preflightPodStartupTimeout {
		return nil
	}

	reason, detail := podStuckReasonAndMessage(podStatus)

	hashCondition := findPodCondition(podStatus.Conditions, PodConditionKMSPreflightConfigHash)
	if hashCondition == nil {
		return &preflightError{
			reason:  reason,
			message: fmt.Sprintf("preflight pod has not reported config hash after %s: %s", preflightPodStartupTimeout, detail),
		}
	}

	resultCondition := findPodCondition(podStatus.Conditions, PodConditionKMSPreflightResult)
	if resultCondition == nil {
		return &preflightError{
			reason:  reason,
			message: fmt.Sprintf("preflight pod has not reported result after %s: %s", preflightPodStartupTimeout, detail),
		}
	}

	return nil
}

func podStuckReasonAndMessage(podStatus corev1.PodStatus) (string, string) {
	for _, cs := range podStatus.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			msg := fmt.Sprintf("container %s is waiting: %s", cs.Name, cs.State.Waiting.Reason)
			if cs.State.Waiting.Message != "" {
				msg = fmt.Sprintf("%s: %s", msg, cs.State.Waiting.Message)
			}
			return cs.State.Waiting.Reason, msg
		}
	}
	if podStatus.Reason != "" {
		return podStatus.Reason, podStatus.Reason
	}
	if podStatus.Message != "" {
		return "Unknown", podStatus.Message
	}
	return "Unknown", fmt.Sprintf("pod is in %s phase", podStatus.Phase)
}

func findPodCondition(conditions []corev1.PodCondition, condType corev1.PodConditionType) *corev1.PodCondition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}


// preflightRequired returns the config hash that needs preflight validation,
// or an empty string when no preflight is needed.
func (c *kmsPreflightController) preflightRequired(ctx context.Context) (string, error) {
	_, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return "", fmt.Errorf("failed to get operator state: %w", err)
	}
	requiredCondition := operatorv1helpers.FindOperatorCondition(operatorStatus.Conditions, "EncryptionKMSPreflightRequired")
	if requiredCondition == nil || requiredCondition.Status != operatorv1.ConditionTrue {
		return "", nil
	}
	apiServer, err := c.apiServerClient.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get apiserver config: %w", err)
	}

	providerCfg, err := newKMSProviderConfig(apiServer.Spec.Encryption.KMS)
	if err != nil {
		return "", fmt.Errorf("failed to create KMS provider config: %w", err)
	}
	currentHash, err := newKMSConfigHasher(providerCfg, c.coreClient, openshiftConfigNS).hash(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to compute KMS config hash: %w", err)
	}

	requiredHash := requiredCondition.Message
	// No requeue needed: the key-controller will post an updated condition when it
	// picks up the config change (via apiServerInformer), which triggers us through
	// operatorClient.Informer(). The minute-based resync is a backstop.
	if currentHash != requiredHash {
		klog.V(4).Infof("KMS config hash changed: required=%s, current=%s; waiting for the key-controller to post an updated condition", requiredHash, currentHash)
		return "", nil
	}

	return requiredHash, nil
}

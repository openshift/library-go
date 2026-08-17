# PR Split Plan for `workload-condition-overwrites`

## PR 1: Cleanup / Refactoring (no behavior change) — MERGED

https://github.com/openshift/library-go/pull/2197

- Replace inline error message loops with `errors.Join`
- Use `ptr.Deref` for replicas
- Fix `areCondidtionsEqual` typo
- Remove unnecessary `Template`/`Labels` from test fixtures

---

## PR 2: Rework of the progressing condition

Based on PR 1.

### New function in `pkg/apps/deployment/`
- `DeploymentProgressingCondition(deployment *appsv1.Deployment) → operatorv1.OperatorCondition`
  - Computes the Progressing condition from deployment status and replica counts
  - Uses exported helpers: `HasDeploymentProgressed`, `HasDeploymentTimedOutProgressing`

### Source changes in `pkg/operator/apiserver/controller/workload/`
- Call the new helper instead of computing the progressing condition inline
- Remove `workloadAtHighestGeneration` as a signal for `Progressing`
- Replace `v1helpers.IsUpdatingTooLong()` with deployment-native `ProgressDeadlineExceeded`
- Add `ProgressDeadlineExceeded` as a new Progressing=False reason
- Change wording "latest generation" → "latest revision" in PodsUpdating message

### Test scenarios added/updated
- "unavailable workload with progress deadline exceeded" (was "updated for too long")
- "unavailable workload progressing normally" (was "updated for a short time")
- "all pods updated but not all available yet"
- "available workload with progress deadline exceeded"
- "workload rollout with maxSurge"

---

## PR 3: Rework of the degraded condition

Based on PR 2.

### New function in `pkg/apps/deployment/`
- `DeploymentDegradedCondition(deployment, pods []*corev1.Pod) → operatorv1.OperatorCondition`
  - Computes the Degraded condition from deployment status and pod state
  - Internally uses unexported helpers: `hasFailingPods`, `findPodReadyCondition`

### Source changes in `pkg/operator/apiserver/controller/workload/`
- Call the new helper instead of computing the degraded condition inline
- When `workload == nil`, also set `WorkloadDegraded`
- Use `defer` to apply SyncError to `workloadDegradedCondition`
- When `ProgressDeadlineExceeded`, also report `DeploymentDegraded`
- Degraded only when pods are actually failing, not during normal rollouts
- Remove trailing period from "no pods available on any node" message

### Test infrastructure (carried with this PR)
- Add `podListErr` field to test struct and wire through `fakePodLister`

### Test scenarios added/updated
- "unavailable workload that previously progressed successfully"
- "partially available during active rollout, pods starting"
- "workload recovering from progress deadline exceeded"
- "partially available workload with failing pod"
- "partially available during scale-up, new pods failing"
- "zero available replicas, no pods exist"
- "pod list error"
- "terminating pod past deadline is not reported as failing"
- "pod with flapping Ready condition detected as failing"
- "pod with flapping Ready within combined deadline not flagged"
- "stably ready pod past combined deadline not flagged as flapping"

---

## PR 4: Changes related to version recording

Based on PR 2.

### Source changes
- Inline the version-recording guard: replace `workloadAtHighestGeneration && workloadHasAllPodsAvailable && workloadHasAllPodsUpdated` intermediate variables with direct field comparisons at the recording site
- This is required because `workloadAtHighestGeneration` was removed from progressing logic in PR 2, but the generation check is still needed here

### Test infrastructure (carried with this PR)
- Wire `versionRecorder` (`status.NewVersionGetter()`) and `targetOperandVersion` into test controller setup

### Test scenarios added
- "version recorded when at highest revision"
- "version not recorded when not at highest revision"
- "version not recorded when generation != observed generation"
- "version not recorded when available replicas < desired"
- "version not recorded when updated replicas < desired"

---

## Dependency order

```
PR 1 (cleanup, MERGED) → PR 2 (progressing) → PR 3 (degraded)
                                             → PR 4 (version)
```

PR 1 is merged. PR 2 builds on PR 1. PRs 3 and 4 both build on PR 2 and are independent of each other. `podListErr` test infra is carried with PR 3 (first needed there); `versionRecorder` and `targetOperandVersion` are carried with PR 4.

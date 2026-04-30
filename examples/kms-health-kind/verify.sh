#!/usr/bin/env bash
#
# Acceptance test for the KIND harness. Implements the 6 assertions
# from PLAN.md §9.
#
# Exit 0 = pass. On failure: dump monitor logs, fake-plugin container
# logs, and the status ConfigMap, then exit 1.

set -o errexit
set -o nounset
set -o pipefail

unset KIND_EXPERIMENTAL_PROVIDER

CLUSTER="${CLUSTER:-kms-health-claude}"
CTX="kind-${CLUSTER}"
NODE="${CLUSTER}-control-plane"
FAKE_POD="kms-fake-plugin-${NODE}"
MONITOR_NS="kms-health-test"
MONITOR_SELECTOR="app=kms-health-monitor-fake"
CM_NS="kms-health-test"
CM="kms-health-fake"

step() { echo "[verify] $*"; }

monitor_pod() {
    kubectl --context "${CTX}" -n "${MONITOR_NS}" get pod \
        -l "${MONITOR_SELECTOR}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

dump_diagnostics() {
    local mp
    mp="$(monitor_pod || true)"
    echo "" >&2
    echo "=== diagnostics ===" >&2
    echo "--- monitor pod describe (${mp}) ---" >&2
    kubectl --context "${CTX}" -n "${MONITOR_NS}" describe pod "${mp}" >&2 || true
    echo "--- monitor logs ---" >&2
    kubectl --context "${CTX}" -n "${MONITOR_NS}" logs "${mp}" >&2 || true
    echo "--- fake-plugin crictl logs ---" >&2
    local cid
    cid="$(docker exec "${NODE}" crictl ps -a --name fake-plugin -q 2>/dev/null | head -1 || true)"
    if [ -n "${cid}" ]; then
        docker exec "${NODE}" crictl logs "${cid}" >&2 || true
    fi
    echo "--- configmap ---" >&2
    kubectl --context "${CTX}" -n "${CM_NS}" get cm "${CM}" -o yaml >&2 || true
}

fail() {
    echo "" >&2
    echo "FAIL: $*" >&2
    dump_diagnostics
    exit 1
}

## Schema reminder: the writer keys data.<class> to a JSON-encoded
## classEntry. There is no flat "current state" key; the class with
## the maximum embedded .timestamp is the current observation.
##
##   data.ok        = `{"timestamp":...,"observerPod":...,"keyIDHash":...}`
##   data.not-ok    = `{"timestamp":...,"observerPod":...,"detail":...,"keyIDHash":...}`
##   data.rpc-error = `{"timestamp":...,"observerPod":...,"detail":...}`
##
## After a class transition the previous class's key is left in place
## (merge-patch semantics), so "current" is determined by max-timestamp,
## not by key existence.

# Print the class key whose embedded .timestamp is max. Empty when the
# CM or its data is missing/empty.
current_class() {
    kubectl --context "${CTX}" -n "${CM_NS}" get cm "${CM}" -o json 2>/dev/null \
      | jq -r '
          .data // {}
          | to_entries
          | map(.key as $k | .value | fromjson | {k: $k, ts: .timestamp})
          | (max_by(.ts) // {k: ""}).k
        '
}

# Print one field from data.<class>. Empty when class or field absent.
class_field() {
    local class="$1" field="$2"
    kubectl --context "${CTX}" -n "${CM_NS}" get cm "${CM}" -o json 2>/dev/null \
      | jq -r --arg c "$class" --arg f "$field" '
          .data[$c] // ""
          | if . == "" then "" else fromjson | .[$f] // "" end
        '
}

# wait_for PRED TIMEOUT_SECONDS MSG: evaluates PRED every second.
wait_for() {
    local pred="$1" timeout="$2" msg="$3"
    local deadline=$(($(date +%s) + timeout))
    while ! eval "$pred" >/dev/null 2>&1; do
        if [ "$(date +%s)" -gt "$deadline" ]; then
            fail "timeout (${timeout}s) waiting for: ${msg}"
        fi
        sleep 1
    done
}

# Assertion 1: Bootstrap.
step "1/6  monitor Deployment Available + fake-plugin container running"
kubectl --context "${CTX}" -n "${MONITOR_NS}" rollout status deployment/kms-health-monitor-fake \
    --timeout=120s \
    || fail "monitor Deployment not Available within 120s"
FAKE_CID="$(docker exec "${NODE}" crictl ps --name fake-plugin -q 2>/dev/null | head -1)"
if [ -z "${FAKE_CID}" ]; then
    fail "fake-plugin container not running on ${NODE}"
fi

# Assertion 2: Initial healthy.
step "2/6  ConfigMap shows current class = ok"
wait_for '[ "$(current_class)" = "ok" ]' 15 "current_class=ok"
t0="$(class_field ok timestamp)"
step "     t0=${t0}  keyIDHash=$(class_field ok keyIDHash | cut -c1-16)…  observerPod=$(class_field ok observerPod)"

# Assertion 3: Timestamp advances.
step "3/6  data.ok.timestamp advances after 2× probe-interval"
sleep 6    # ≥2× harness probe-interval (2s) + slack
t1="$(class_field ok timestamp)"
if [ "${t1}" = "${t0}" ]; then
    fail "data.ok.timestamp did not advance: t0=${t0} t1=${t1}"
fi
if ! [[ "${t1}" > "${t0}" ]]; then
    fail "data.ok.timestamp moved backward: t0=${t0} t1=${t1}"
fi
step "     t1=${t1} > t0 ok"

# Assertion 4: Flip to unhealthy.
step "4/6  flip-unhealthy → current class = not-ok"
docker exec "${NODE}" touch /tmp/kms-unhealthy
wait_for '[ "$(current_class)" = "not-ok" ]' 10 "current_class=not-ok"
t2="$(class_field not-ok timestamp)"
d2="$(class_field not-ok detail)"
if ! [[ "${t2}" > "${t1}" ]]; then
    fail "data.not-ok.timestamp not newer than last data.ok: t1=${t1} t2=${t2}"
fi
step "     t2=${t2}  detail=${d2}"

# Assertion 5: Restore healthy.
step "5/6  flip-healthy → current class = ok"
docker exec "${NODE}" rm -f /tmp/kms-unhealthy
wait_for '[ "$(current_class)" = "ok" ]' 10 "current_class=ok after flip"
t3="$(class_field ok timestamp)"
if ! [[ "${t3}" > "${t2}" ]]; then
    fail "recovery data.ok.timestamp not newer than data.not-ok: t2=${t2} t3=${t3}"
fi
step "     t3=${t3}  current_class=ok"

# Assertion 6: Plugin death.
# Staydown marker pattern: kubelet's restart speed varies (1s to 9s
# observed). Without help, the probe sometimes reconnects across the
# gap thanks to grpc.WaitForReady(true) and never reports rpc-error.
# Setting /tmp/kms-staydown before killing makes fake-plugin sleep on
# its next start, giving a deterministic outage window.
step "6/6  set staydown marker + kill fake-plugin → current class = rpc-error"
FAKE_CID="$(docker exec "${NODE}" crictl ps --name fake-plugin -q 2>/dev/null | head -1)"
if [ -z "${FAKE_CID}" ]; then
    fail "could not find fake-plugin container via crictl on ${NODE}"
fi
docker exec "${NODE}" touch /tmp/kms-staydown
step "     stopping container ${FAKE_CID}"
docker exec "${NODE}" crictl stop "${FAKE_CID}" >/dev/null
caught=0
for _ in $(seq 1 50); do
    if [ "$(current_class)" = "rpc-error" ]; then
        caught=1
        step "     caught: detail=$(class_field rpc-error detail)"
        break
    fi
    sleep 0.2
done
docker exec "${NODE}" rm -f /tmp/kms-staydown
if [ "${caught}" -ne 1 ]; then
    fail "never observed current_class=rpc-error after killing fake-plugin (window ~10s @ 200ms poll)"
fi
t4="$(class_field rpc-error timestamp)"
step "     t4=${t4} (rpc-error observation timestamp)"

echo ""
echo "✅ All 6 assertions passed on cluster ${CLUSTER}."

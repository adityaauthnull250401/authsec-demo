#!/usr/bin/env bash
#
# Discovery collector conformance suite.
#
# Stands up a throwaway cluster, installs the collector in dry-run, applies the
# case matrix, then runs the phases that need real cluster manipulation
# (fingerprint stability under scale/rollout/retag, safety under collector
# failure, resync). Prints a pass/fail report and exits non-zero on failure.
#
#   ./run.sh                     full suite on a throwaway kind cluster
#   ./run.sh --keep              leave the cluster up for inspection
#   ./run.sh --use-current       run against the current kubectl context
#   ./run.sh --agent-repo PATH   path to the discovery-agent checkout
#
# Requires: kubectl, helm, python3. kind and docker unless --use-current.
#
# Note on log handling: later phases restart the collector pod, which discards
# its logs. Every phase therefore appends to an accumulator file and all
# assertions read that, never the live pod. Getting this wrong silently drops
# most of the evidence and reports it as detection failures.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="dc-conformance"
NS_AGENT="authsec-system"
AGENT_REPO="${AGENT_REPO:-$HERE/../../../authnull/discovery-agent}"
KEEP=0
USE_CURRENT=0
IMG="authsec-discovery-agent:conformance"
LOGS="$HERE/.logs.jsonl"
NOTES=()

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[34m'; D=$'\033[2m'; N=$'\033[0m'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --use-current) USE_CURRENT=1; shift ;;
    --agent-repo) AGENT_REPO="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

step()  { echo; echo "${B}▸ $*${N}"; }
info()  { echo "  $*"; }
good()  { echo "  ${G}✓${N} $*"; }
bad()   { echo "  ${R}✗${N} $*"; }
note()  { NOTES+=("$1"); }
die()   { echo "${R}fatal: $*${N}" >&2; exit 2; }

need() { command -v "$1" >/dev/null || die "$1 not found on PATH"; }
need kubectl; need helm; need python3

[[ -d "$AGENT_REPO/charts/authsec-discovery-agent" ]] \
  || die "discovery-agent chart not found under $AGENT_REPO
       pass --agent-repo /path/to/discovery-agent"

: > "$LOGS"

# --- cluster ----------------------------------------------------------------
if [[ $USE_CURRENT -eq 0 ]]; then
  need kind; need docker
  step "Creating throwaway cluster '$CLUSTER'"
  # Own kubeconfig so we never touch the caller's ~/.kube/config.
  export KUBECONFIG="$HERE/.kubeconfig-$CLUSTER"
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
  kind create cluster --name "$CLUSTER" >/dev/null 2>&1 \
    || die "kind create failed (is docker running?)"
  kind get kubeconfig --name "$CLUSTER" > "$KUBECONFIG" 2>/dev/null
  good "cluster up, kubeconfig at $KUBECONFIG"

  step "Building and loading the collector image"
  ( cd "$AGENT_REPO" && docker build -q -t "$IMG" . ) >/dev/null || die "docker build failed"
  kind load docker-image "$IMG" --name "$CLUSTER" >/dev/null 2>&1 || die "kind load failed"
  good "$IMG loaded"
  PULL=Never
else
  step "Using current context: $(kubectl config current-context)"
  IMG="${CONFORMANCE_IMAGE:?set CONFORMANCE_IMAGE to a pullable collector image when using --use-current}"
  PULL=IfNotPresent
fi

cleanup() {
  if [[ $USE_CURRENT -eq 0 && $KEEP -eq 0 ]]; then
    echo; echo "${D}tearing down cluster '$CLUSTER'${N}"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
    rm -f "$HERE/.kubeconfig-$CLUSTER"
  elif [[ $KEEP -eq 1 ]]; then
    echo; echo "${Y}cluster kept.${N} export KUBECONFIG=$HERE/.kubeconfig-$CLUSTER"
  fi
}
trap cleanup EXIT

kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null 2>&1

# --- helpers ---------------------------------------------------------------
install_agent() {
  helm upgrade --install discovery-agent "$AGENT_REPO/charts/authsec-discovery-agent" \
    --namespace "$NS_AGENT" --create-namespace \
    --set image.repository="${IMG%:*}" --set image.tag="${IMG##*:}" \
    --set image.pullPolicy=$PULL \
    --set cluster.name="$CLUSTER" \
    --set controlPlane.url=https://conformance.invalid \
    --set dryRun=true --set logLevel=debug --set replicaCount=1 \
    "$@" >/dev/null 2>&1
}

agent_pod() {
  kubectl get pods -n "$NS_AGENT" --field-selector=status.phase=Running \
    -o name 2>/dev/null | head -1
}

wait_agent() {
  local i p
  for i in $(seq 1 60); do
    p="$(agent_pod)"
    if [[ -n "$p" ]] && \
       [[ "$(kubectl get "$p" -n "$NS_AGENT" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)" == "true" ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# Append the live pod's logs to the accumulator. Must be called before any
# action that replaces the pod, and before reading results.
capture() {
  local p; p="$(agent_pod)"
  [[ -n "$p" ]] && kubectl logs -n "$NS_AGENT" "$p" 2>/dev/null >> "$LOGS"
  return 0
}

# Count distinct fingerprints for workload/container across everything captured.
fp_count() {
  capture
  python3 - "$1" "$2" < "$LOGS" <<'PY'
import json, sys
w, c = sys.argv[1], sys.argv[2]
fps = set()
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        rec = json.loads(line)
    except Exception:
        continue
    if "sighting" not in rec:
        continue
    try:
        s = json.loads(rec["sighting"])
    except Exception:
        continue
    k = s.get("metadata", {}).get("kubernetes") or {}
    if k.get("workload_name") == w and k.get("container_name") == c:
        fps.add(s["fingerprint"])
print(len(fps))
PY
}

# Count sightings whose discovery channel matches, from the accumulator.
channel_count() {
  capture
  python3 - "$1" < "$LOGS" <<'PY'
import json, sys
want = sys.argv[1]
n = 0
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        rec = json.loads(line)
    except Exception:
        continue
    if "sighting" not in rec:
        continue
    try:
        s = json.loads(rec["sighting"])
    except Exception:
        continue
    if (s.get("metadata", {}).get("discovery") or {}).get("channel") == want:
        n += 1
print(n)
PY
}

step "Installing collector (dry-run, control plane deliberately unreachable)"
install_agent || die "helm install failed"
wait_agent || die "collector never became ready"
good "collector ready, webhook registered"

# --- phase 1: declarative case matrix --------------------------------------
step "Phase 1 — applying case matrix"
kubectl apply -f "$HERE/cases.yaml" >/dev/null || die "cases.yaml failed to apply"
# CronJob needs a schedule tick; controllers need time to create pods.
sleep 70
capture
good "$(kubectl get deploy,sts,ds,job,cronjob,pod -n dc-conformance --no-headers 2>/dev/null | wc -l | tr -d ' ') objects created"
good "$(channel_count admission) admission sightings captured"

# --- phase 2: fingerprint stability ----------------------------------------
# A fingerprint that changes when it should not creates a duplicate governed
# agent on every rollout. One that stays the same when it should not merges two
# distinct agents. Both are silent and unrecoverable, so they get direct tests.
step "Phase 2 — fingerprint stability under mutation"

BASE="$(fp_count c-a1-label app)"
if [[ "${BASE:-0}" -eq 0 ]]; then
  bad "c-a1-label produced no sighting; skipping stability phase"
  note "fingerprint stability phase skipped — baseline sighting missing"
else
  # 2a scale up: replicas are not agents
  kubectl scale deploy/c-a1-label -n dc-conformance --replicas=3 >/dev/null 2>&1
  kubectl rollout status deploy/c-a1-label -n dc-conformance --timeout=90s >/dev/null 2>&1
  sleep 5
  if [[ "$(fp_count c-a1-label app)" -eq 1 ]]; then
    good "scale 1→3 replicas: still ONE fingerprint"
  else
    bad "scale 1→3 produced $(fp_count c-a1-label app) fingerprints (want 1)"
    note "FAIL: replicas produce distinct fingerprints — one agent becomes N governed rows"
  fi

  # 2b rollout: pod-template-hash and pod names change, the agent does not
  kubectl patch deploy/c-a1-label -n dc-conformance --type=merge \
    -p '{"spec":{"template":{"metadata":{"annotations":{"conformance/rollout":"1"}}}}}' >/dev/null 2>&1
  kubectl rollout status deploy/c-a1-label -n dc-conformance --timeout=90s >/dev/null 2>&1
  sleep 5
  if [[ "$(fp_count c-a1-label app)" -eq 1 ]]; then
    good "rollout (new pod-template-hash): fingerprint unchanged"
  else
    bad "rollout produced $(fp_count c-a1-label app) fingerprints (want 1)"
    note "FAIL: a rollout creates a new governed agent — inventory grows on every deploy"
  fi

  # 2c image TAG bump: a version bump is the same agent
  kubectl set image deploy/c-a1-label app=alpine:3.19 -n dc-conformance >/dev/null 2>&1
  kubectl rollout status deploy/c-a1-label -n dc-conformance --timeout=90s >/dev/null 2>&1
  sleep 5
  if [[ "$(fp_count c-a1-label app)" -eq 1 ]]; then
    good "image tag 3.20→3.19: fingerprint unchanged"
  else
    bad "tag bump produced $(fp_count c-a1-label app) fingerprints (want 1)"
    note "FAIL: tag bumps fork the identity — every release duplicates every agent"
  fi

  # 2d image REPOSITORY change: a different program is a different agent
  kubectl set image deploy/c-a1-label app=busybox:1.36 -n dc-conformance >/dev/null 2>&1
  kubectl rollout status deploy/c-a1-label -n dc-conformance --timeout=90s >/dev/null 2>&1
  sleep 5
  if [[ "$(fp_count c-a1-label app)" -ge 2 ]]; then
    good "image repo alpine→busybox: NEW fingerprint (correct)"
  else
    bad "repo swap did not change the fingerprint"
    note "FAIL: swapping the image keeps the old identity — a different program inherits governance"
  fi
fi

# --- phase 3: never block a deployment -------------------------------------
# The single most important safety property. failurePolicy: Ignore must mean a
# dead collector cannot stop a pod from being created.
step "Phase 3 — safety: a dead collector must not block deployments"
capture
kubectl scale deploy -n "$NS_AGENT" --all --replicas=0 >/dev/null 2>&1
for i in $(seq 1 30); do [[ -z "$(agent_pod)" ]] && break; sleep 2; done
info "collector scaled to zero; webhook configuration still registered"
ERR="$(kubectl run c-g2-agent-down -n dc-conformance --image=alpine:3.20 \
        --restart=Never --command -- sleep infinity 2>&1)"
if kubectl get pod c-g2-agent-down -n dc-conformance >/dev/null 2>&1; then
  good "pod created with the collector DOWN (failurePolicy: Ignore honoured)"
else
  bad "pod creation FAILED while the collector was down"
  info "${D}${ERR}${N}"
  note "CRITICAL: a dead collector blocks pod creation — the collector is a hard dependency of every deploy. Check webhook.failurePolicy is Ignore. API server said: ${ERR}"
fi
kubectl scale deploy -n "$NS_AGENT" --all --replicas=1 >/dev/null 2>&1
wait_agent || die "collector did not come back"
good "collector restored"

# --- phase 4: resync discovers the installed base --------------------------
# Everything above was already running before this restart, so a resync sweep
# must find it. This is the only channel that sees workloads predating install.
step "Phase 4 — resync discovers already-running workloads"
capture
install_agent --set resync.enabled=true --set resync.initialDelay=5s --set resync.interval=10m
wait_agent || die "collector did not come back after enabling resync"
sleep 30
RESYNC_N="$(channel_count resync)"
if [[ "${RESYNC_N:-0}" -gt 0 ]]; then
  good "resync produced $RESYNC_N sightings of pre-existing workloads"
else
  bad "resync produced no sightings"
  note "resync found nothing — the installed base would be invisible on a real install"
fi

# --- phase 5: dry-run must not leak to the control plane --------------------
step "Phase 5 — dry-run must send nothing"
capture
SENT="$(grep -c 'sighting send failed\|control plane rejected' "$LOGS" 2>/dev/null || true)"
SENT="${SENT:-0}"
if [[ "$SENT" -eq 0 ]]; then
  good "no send attempts while dryRun=true"
else
  bad "$SENT send attempts despite dryRun=true"
  note "BUG: dryRun=true does not suppress the resync channel. DryRunReporting is checked only in webhook/handler.go, so resync enqueues straight to the reporter and POSTs. An operator previewing findings safely would still ship their inventory. Fix belongs in Reporter.Enqueue so no producer can bypass it."
fi

# --- verdict ---------------------------------------------------------------
step "Evaluating expectations"
ARGS=()
for n in "${NOTES[@]:-}"; do [[ -n "$n" ]] && ARGS+=(--note "$n"); done
python3 "$HERE/assert.py" \
  --expectations "$HERE/expectations.json" \
  --logs "$LOGS" \
  --json-out "$HERE/.last-run.json" \
  "${ARGS[@]}"
exit $?

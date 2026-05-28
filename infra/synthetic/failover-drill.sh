#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# failover-drill.sh — Single-region failover drill for Powehi
#
# Scales the target region to 0 replicas, waits 30s, asserts the peer region
# health endpoint returns HTTP 200, then scales back.  Prints RTO measurement.
#
# Usage:
#   REGION=eu-frankfurt \
#   KUBECONFIG=/path/to/kubeconfig \
#   PEER_BASE_URL=https://ap.powehi.example \
#   ./infra/synthetic/failover-drill.sh
#
# Required env vars:
#   REGION          — eu-frankfurt | ap-seoul (region under test / to be downed)
#   KUBECONFIG      — path to the kubeconfig for the target cluster
#   PEER_BASE_URL   — base URL of the peer region (must respond at /health)
#
# Optional env vars:
#   NAMESPACE       — Kubernetes namespace (default: powehi)
#   DEPLOYMENT      — Deployment name (default: powehi)
#   ORIGINAL_REPLICAS — replica count to restore (default: 2)
# ---------------------------------------------------------------------------
set -euo pipefail

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
: "${REGION:?REGION env var is required (eu-frankfurt|ap-seoul)}"
: "${KUBECONFIG:?KUBECONFIG env var is required}"
: "${PEER_BASE_URL:?PEER_BASE_URL env var is required}"

# Guard against credentials accidentally embedded in the URL (e.g. https://user:pass@host)
# which would be printed to stdout and potentially captured in logs.
if [[ "${PEER_BASE_URL}" == *"@"* ]]; then
  echo "[failover-drill] ERROR: PEER_BASE_URL contains '@' — do not embed credentials in the URL." >&2
  exit 1
fi

NAMESPACE="${NAMESPACE:-powehi}"
DEPLOYMENT="${DEPLOYMENT:-powehi}"
ORIGINAL_REPLICAS="${ORIGINAL_REPLICAS:-2}"

export KUBECONFIG

# ---------------------------------------------------------------------------
# Idempotent cleanup — always restore replicas even if assertions fail
# ---------------------------------------------------------------------------
_restore() {
  local exit_code=$?
  echo ""
  echo "[failover-drill] --- cleanup: restoring ${REGION} to ${ORIGINAL_REPLICAS} replicas ---"
  kubectl scale deployment "${DEPLOYMENT}" \
    --replicas="${ORIGINAL_REPLICAS}" \
    -n "${NAMESPACE}" \
    --kubeconfig="${KUBECONFIG}" \
    || echo "[failover-drill] WARNING: scale-back failed — manual intervention required"
  echo "[failover-drill] restore complete (exit_code=${exit_code})"
  exit "${exit_code}"
}
trap _restore EXIT

# ---------------------------------------------------------------------------
# Step 1: Scale target region to 0
# ---------------------------------------------------------------------------
echo "[failover-drill] === Phase 6 Failover Drill ==="
echo "[failover-drill] Target region : ${REGION}"
echo "[failover-drill] Peer URL      : ${PEER_BASE_URL}"
echo "[failover-drill] Namespace     : ${NAMESPACE}"
echo "[failover-drill] Deployment    : ${DEPLOYMENT}"
echo ""
echo "[failover-drill] Step 1: scaling ${DEPLOYMENT} in ${REGION} to 0 replicas..."

DRILL_START_EPOCH=$(date +%s)

kubectl scale deployment "${DEPLOYMENT}" \
  --replicas=0 \
  -n "${NAMESPACE}" \
  --kubeconfig="${KUBECONFIG}"

echo "[failover-drill] scale-to-zero issued. Waiting 30s for traffic to reroute..."

# ---------------------------------------------------------------------------
# Step 2: Wait 30 seconds
# ---------------------------------------------------------------------------
sleep 30

# ---------------------------------------------------------------------------
# Step 3: Assert peer region health endpoint returns HTTP 200
# ---------------------------------------------------------------------------
echo "[failover-drill] Step 3: probing peer region at ${PEER_BASE_URL}/health ..."

HTTP_STATUS=$(curl \
  --silent \
  --output /dev/null \
  --write-out "%{http_code}" \
  --max-time 10 \
  "${PEER_BASE_URL}/health")

PROBE_EPOCH=$(date +%s)
RTO_SECONDS=$(( PROBE_EPOCH - DRILL_START_EPOCH ))

echo "[failover-drill] Peer HTTP status: ${HTTP_STATUS}"
echo "[failover-drill] RTO measurement : ${RTO_SECONDS}s (from scale-to-zero to successful peer probe)"

if [ "${HTTP_STATUS}" != "200" ]; then
  echo "[failover-drill] FAIL: expected HTTP 200 from peer, got ${HTTP_STATUS}" >&2
  exit 1
fi

echo ""
echo "[failover-drill] PASS: peer region responded with HTTP 200."
echo "[failover-drill] RTO = ${RTO_SECONDS}s (target: <300s / 5 minutes)"

if [ "${RTO_SECONDS}" -gt 300 ]; then
  echo "[failover-drill] WARNING: RTO exceeded 5-minute target (prd.md §4A.7)" >&2
fi

# Step 5: Restore is handled by the trap (EXIT).

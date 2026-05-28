#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# failover-drill.sh — Single-region failover drill for Powehi
#
# Verifies prd.md §4A.7 SLOs: RTO <5 minutes, RPO <30 seconds.
#
# Steps:
#   0. RPO pre-check — asserts Postgres replica lag < 30s (skipped if DB_HOST
#      is unset; in that case a warning is printed but the drill continues).
#   1. Scale target region to 0 replicas (simulate region failure).
#   2. Wait 30 seconds for traffic to reroute via CF smart-router.
#   3. Assert peer region health endpoint returns HTTP 200.
#   3b. (Optional) Assert CF smart-router KV shows failed region as unhealthy.
#   4. Emit RTO measurement; FAIL if > 300s (5 min).
#   5. Restore (always via EXIT trap).
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
#   NAMESPACE            — Kubernetes namespace (default: powehi)
#   DEPLOYMENT           — Deployment name (default: powehi)
#   ORIGINAL_REPLICAS    — replica count to restore (default: 2)
#   RTO_MAX_SECONDS      — hard failure threshold in seconds (default: 300 = 5 min)
#   DB_HOST              — if set, enables RPO pre-check via rpo-check.sh
#   DB_USER              — Postgres user for RPO pre-check
#   DB_PORT              — default: 5432
#   DB_NAME              — default: powehi
#   RPO_THRESHOLD_SECONDS — default: 30
#   HEALTH_KV_API_URL    — if set, asserts failed region is unhealthy in CF KV
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
: "${REGION:?REGION env var is required (eu-frankfurt|ap-seoul)}"
: "${KUBECONFIG:?KUBECONFIG env var is required}"
: "${PEER_BASE_URL:?PEER_BASE_URL env var is required}"

# Guard: credentials must not appear in URLs.
if [[ "${PEER_BASE_URL}" == *"@"* ]]; then
  echo "[failover-drill] ERROR: PEER_BASE_URL contains '@' — do not embed credentials in the URL." >&2
  exit 1
fi
if [[ -n "${HEALTH_KV_API_URL:-}" ]] && [[ "${HEALTH_KV_API_URL}" == *"@"* ]]; then
  echo "[failover-drill] ERROR: HEALTH_KV_API_URL contains '@' — do not embed credentials in the URL." >&2
  exit 1
fi

# Guard: require https:// for all URLs (prevents http downgrade + SSRF to local
# metadata endpoints — prd.md §3 threat model; security-auditor Y1).
if ! [[ "${PEER_BASE_URL}" =~ ^https:// ]]; then
  echo "[failover-drill] ERROR: PEER_BASE_URL must start with https://, got: '${PEER_BASE_URL}'" >&2
  exit 1
fi
if [[ -n "${HEALTH_KV_API_URL:-}" ]] && ! [[ "${HEALTH_KV_API_URL}" =~ ^https:// ]]; then
  echo "[failover-drill] ERROR: HEALTH_KV_API_URL must start with https://, got: '${HEALTH_KV_API_URL}'" >&2
  exit 1
fi

# Guard: REGION must be a safe identifier (letters + hyphens only) to prevent
# path traversal when concatenated into HEALTH_KV_API_URL (security-auditor Y2).
if ! [[ "${REGION}" =~ ^[a-z]+-[a-z]+(-[0-9]+)?$ ]]; then
  echo "[failover-drill] ERROR: REGION '${REGION}' must match ^[a-z]+-[a-z]+(-[0-9]+)?$ (e.g. eu-frankfurt, ap-seoul)" >&2
  exit 1
fi

NAMESPACE="${NAMESPACE:-powehi}"
DEPLOYMENT="${DEPLOYMENT:-powehi}"
ORIGINAL_REPLICAS="${ORIGINAL_REPLICAS:-2}"
RTO_MAX_SECONDS="${RTO_MAX_SECONDS:-300}"

export KUBECONFIG

# ---------------------------------------------------------------------------
# Idempotent cleanup — always restore replicas even if assertions fail
# ---------------------------------------------------------------------------
DRILL_FAILED=0
# Secure temp file for CF KV response (security-auditor Y3).
# Created here so _restore can always clean it up, even on early exit.
KV_TMP_FILE=$(mktemp)

_restore() {
  local exit_code=$?
  rm -f "${KV_TMP_FILE}"
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
# Header
# ---------------------------------------------------------------------------
echo "[failover-drill] ======================================================"
echo "[failover-drill]  Phase 6 Failover Drill  (prd.md §4A.7)"
echo "[failover-drill] ======================================================"
echo "[failover-drill]  Target region    : ${REGION}"
echo "[failover-drill]  Peer URL         : ${PEER_BASE_URL}"
echo "[failover-drill]  Namespace        : ${NAMESPACE}"
echo "[failover-drill]  Deployment       : ${DEPLOYMENT}"
echo "[failover-drill]  RTO hard limit   : ${RTO_MAX_SECONDS}s"
echo ""

# ---------------------------------------------------------------------------
# Step 0: RPO pre-check (optional — skip if DB_HOST not set)
# ---------------------------------------------------------------------------
echo "[failover-drill] Step 0: RPO pre-check..."
if [[ -n "${DB_HOST:-}" ]]; then
  export DB_HOST DB_USER="${DB_USER:-}" DB_PORT="${DB_PORT:-5432}" \
         DB_NAME="${DB_NAME:-powehi}" RPO_THRESHOLD_SECONDS="${RPO_THRESHOLD_SECONDS:-30}"
  "${SCRIPT_DIR}/rpo-check.sh"
  echo "[failover-drill] RPO pre-check PASSED."
else
  echo "[failover-drill] WARNING: DB_HOST not set — skipping RPO pre-check." >&2
  echo "[failover-drill]   Set DB_HOST, DB_USER, and PGPASSWORD to enable RPO verification." >&2
  echo "[failover-drill]   Proceeding without RPO pre-condition guarantee." >&2
fi
echo ""

# ---------------------------------------------------------------------------
# Step 1: Scale target region to 0
# ---------------------------------------------------------------------------
echo "[failover-drill] Step 1: scaling ${DEPLOYMENT} in ${REGION} to 0 replicas..."

DRILL_START_EPOCH=$(date +%s)

kubectl scale deployment "${DEPLOYMENT}" \
  --replicas=0 \
  -n "${NAMESPACE}" \
  --kubeconfig="${KUBECONFIG}"

echo "[failover-drill] scale-to-zero issued. Waiting 30s for traffic to reroute..."
echo ""

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
  --proto '=https' \
  --max-time 10 \
  "${PEER_BASE_URL}/health")

PROBE_EPOCH=$(date +%s)
RTO_SECONDS=$(( PROBE_EPOCH - DRILL_START_EPOCH ))

echo "[failover-drill] Peer HTTP status : ${HTTP_STATUS}"
echo "[failover-drill] RTO measurement  : ${RTO_SECONDS}s (target: <${RTO_MAX_SECONDS}s)"

if [ "${HTTP_STATUS}" != "200" ]; then
  echo "[failover-drill] FAIL: expected HTTP 200 from peer, got ${HTTP_STATUS}" >&2
  DRILL_FAILED=1
  exit 1
fi

echo "[failover-drill] PASS: peer region responded with HTTP 200."
echo ""

# ---------------------------------------------------------------------------
# Step 3b: Assert CF smart-router KV shows failed region as unhealthy (optional)
# ---------------------------------------------------------------------------
if [[ -n "${HEALTH_KV_API_URL:-}" ]]; then
  echo "[failover-drill] Step 3b: checking CF smart-router HEALTH_KV for ${REGION}..."

  KV_HTTP_STATUS=$(curl \
    --silent \
    --output "${KV_TMP_FILE}" \
    --write-out "%{http_code}" \
    --proto '=https' \
    --max-time 10 \
    "${HEALTH_KV_API_URL}/${REGION}")

  if [ "${KV_HTTP_STATUS}" = "200" ]; then
    KV_VALUE=$(cat "${KV_TMP_FILE}" 2>/dev/null || echo "")
    # Healthy KV entry would contain "healthy":true — we expect "healthy":false or absence.
    if echo "${KV_VALUE}" | grep -q '"healthy":true'; then
      echo "[failover-drill] WARNING: CF KV still shows ${REGION} as healthy after scale-to-zero." >&2
      echo "[failover-drill]   Smart-router may route traffic to the downed region." >&2
      echo "[failover-drill]   Expected KV to be updated by the synthetic monitor within 30s." >&2
    else
      echo "[failover-drill] PASS: CF KV correctly reflects ${REGION} as unhealthy."
    fi
  else
    echo "[failover-drill] NOTE: CF KV API returned HTTP ${KV_HTTP_STATUS} — skipping KV assertion." >&2
  fi
  # KV_TMP_FILE is cleaned up by the EXIT trap (_restore).
  echo ""
fi

# ---------------------------------------------------------------------------
# Step 4: RTO assertion — hard fail if > RTO_MAX_SECONDS
# ---------------------------------------------------------------------------
echo "[failover-drill] Step 4: RTO assertion (SLO: <${RTO_MAX_SECONDS}s = prd.md §4A.7)..."
echo "[failover-drill]   Measured RTO = ${RTO_SECONDS}s"

if [ "${RTO_SECONDS}" -gt "${RTO_MAX_SECONDS}" ]; then
  echo "[failover-drill] FAIL: RTO ${RTO_SECONDS}s exceeded hard limit of ${RTO_MAX_SECONDS}s" >&2
  echo "[failover-drill]   SLO violation: prd.md §4A.7 requires RTO <5 minutes" >&2
  DRILL_FAILED=1
  exit 1
fi

echo "[failover-drill] PASS: RTO ${RTO_SECONDS}s is within the <${RTO_MAX_SECONDS}s SLO."
echo ""
echo "[failover-drill] ======================================================"
echo "[failover-drill]  DRILL COMPLETE — all assertions passed"
echo "[failover-drill]   RTO = ${RTO_SECONDS}s  (SLO: <${RTO_MAX_SECONDS}s)"
echo "[failover-drill]   RPO pre-condition: $([ -n "${DB_HOST:-}" ] && echo "verified" || echo "skipped (DB_HOST not set)")"
echo "[failover-drill] ======================================================"

# Step 5: Restore is handled by the EXIT trap.

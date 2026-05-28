#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# rpo-check.sh — Postgres streaming replication lag check for RPO verification
#
# Queries pg_stat_replication on the primary to verify that all standbys have
# replay_lag < RPO_THRESHOLD_SECONDS (default: 30s). Calling this before a
# failover drill confirms that the RPO pre-condition is satisfied: data written
# to the primary has been replicated within the RPO window, so a drill-induced
# failover will not lose more than threshold seconds of data.
#
# Usage:
#   DB_HOST=pg-primary.eu.internal \
#   DB_USER=powehi_monitor \
#   PGPASSWORD=secret \
#   ./infra/synthetic/rpo-check.sh
#
# Required env vars:
#   DB_HOST  — hostname of the Postgres primary
#   DB_USER  — Postgres user with pg_monitor or superuser privileges
#
# Optional env vars:
#   DB_PORT                — default: 5432
#   DB_NAME                — default: powehi
#   RPO_THRESHOLD_SECONDS  — default: 30
#
# Exit codes:
#   0 — all standbys within RPO threshold (PASS)
#   1 — one or more standbys exceed threshold (FAIL)
#   2 — psql error / connection failure
# ---------------------------------------------------------------------------
set -euo pipefail

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
: "${DB_HOST:?DB_HOST env var is required}"
: "${DB_USER:?DB_USER env var is required}"

DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-powehi}"
RPO_THRESHOLD_SECONDS="${RPO_THRESHOLD_SECONDS:-30}"

# Guard: credentials must not appear in DB_HOST (e.g. user:pass@host).
if [[ "${DB_HOST}" == *"@"* ]]; then
  echo "[rpo-check] ERROR: DB_HOST contains '@' — do not embed credentials in the hostname." >&2
  exit 2
fi

# Guard: RPO_THRESHOLD_SECONDS must be a plain positive integer before it is
# interpolated into a SQL literal. An unsanitised value could inject arbitrary
# SQL into the pg_stat_replication query (e.g. "1'; DROP TABLE ...--").
if ! [[ "${RPO_THRESHOLD_SECONDS}" =~ ^[0-9]+$ ]] || [ "${RPO_THRESHOLD_SECONDS}" -eq 0 ]; then
  echo "[rpo-check] ERROR: RPO_THRESHOLD_SECONDS must be a positive integer, got: '${RPO_THRESHOLD_SECONDS}'" >&2
  exit 2
fi

echo "[rpo-check] === Postgres RPO Pre-Check ==="
echo "[rpo-check]   Primary : ${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo "[rpo-check]   User    : ${DB_USER}"
echo "[rpo-check]   RPO SLO : replay_lag < ${RPO_THRESHOLD_SECONDS}s"
echo ""

PSQL_CMD=(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A)

# ---------------------------------------------------------------------------
# Count standbys whose replay_lag exceeds the threshold OR is NULL.
# A NULL replay_lag means the standby has stopped streaming — treat as lagged.
# ---------------------------------------------------------------------------
LAGGING_COUNT_RAW=$("${PSQL_CMD[@]}" -c "
  SELECT COUNT(*)
  FROM   pg_stat_replication
  WHERE  replay_lag > interval '${RPO_THRESHOLD_SECONDS} seconds'
     OR  replay_lag IS NULL;
" 2>&1) || {
  echo "[rpo-check] ERROR: psql command failed — check DB_HOST, DB_USER, and PGPASSWORD." >&2
  echo "[rpo-check] psql output: ${LAGGING_COUNT_RAW}" >&2
  exit 2
}

# Strip whitespace and validate numeric output.
LAGGING_COUNT="${LAGGING_COUNT_RAW//[[:space:]]/}"
if ! [[ "${LAGGING_COUNT}" =~ ^[0-9]+$ ]]; then
  echo "[rpo-check] ERROR: psql returned non-numeric output — unexpected schema or error." >&2
  echo "[rpo-check] Raw output: ${LAGGING_COUNT_RAW}" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Also verify at least one standby exists (a primary with zero standbys is a
# degenerate state: there is no replication and RPO is effectively infinite).
# ---------------------------------------------------------------------------
STANDBY_COUNT_RAW=$("${PSQL_CMD[@]}" -c "SELECT COUNT(*) FROM pg_stat_replication;" 2>&1) || true
STANDBY_COUNT="${STANDBY_COUNT_RAW//[[:space:]]/}"
if [[ "${STANDBY_COUNT}" =~ ^[0-9]+$ ]] && [ "${STANDBY_COUNT}" -eq 0 ]; then
  echo "[rpo-check] WARNING: pg_stat_replication is empty — no standbys connected." >&2
  echo "[rpo-check]   RPO cannot be verified without active streaming replication." >&2
  echo "[rpo-check]   Treating this as a FAIL to avoid silently running a data-loss drill." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
if [ "${LAGGING_COUNT}" -eq 0 ]; then
  echo "[rpo-check] PASS: all standbys have replay_lag < ${RPO_THRESHOLD_SECONDS}s"
  echo "[rpo-check] RPO pre-condition satisfied — safe to proceed with failover drill."
  exit 0
fi

echo "[rpo-check] FAIL: ${LAGGING_COUNT} standby(s) have replay_lag >= ${RPO_THRESHOLD_SECONDS}s" >&2
echo "[rpo-check] Running a failover drill now risks exceeding RPO <${RPO_THRESHOLD_SECONDS}s." >&2
echo ""
echo "[rpo-check] Replica lag summary (application_name omitted to avoid leaking hostnames):"
"${PSQL_CMD[@]}" -c "
  SELECT
    '[standby_' || LPAD(ROW_NUMBER() OVER (ORDER BY replay_lag DESC NULLS FIRST)::text, 2, '0') || ']' AS standby,
    state,
    write_lag,
    flush_lag,
    replay_lag,
    sync_state
  FROM   pg_stat_replication
  ORDER BY replay_lag DESC NULLS FIRST;
" 2>/dev/null || true

exit 1

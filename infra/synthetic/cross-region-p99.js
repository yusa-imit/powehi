/**
 * cross-region-p99.js — k6 cross-region latency synthetic monitor
 *
 * Validates that EU and AP-Seoul health endpoints respond within p99 <200ms.
 * Also enforces the zero-knowledge invariant: response body must contain
 * "status":"ok" and must NOT contain "content" or "plaintext" fields.
 *
 * Usage:
 *   EU_BASE_URL=https://eu.powehi.example \
 *   AP_SEOUL_BASE_URL=https://ap.powehi.example \
 *   k6 run infra/synthetic/cross-region-p99.js
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Trend } from "k6/metrics";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const EU_BASE_URL = __ENV.EU_BASE_URL;
const AP_SEOUL_BASE_URL = __ENV.AP_SEOUL_BASE_URL;

if (!EU_BASE_URL || !AP_SEOUL_BASE_URL) {
  throw new Error(
    "Required env vars: EU_BASE_URL and AP_SEOUL_BASE_URL must be set"
  );
}

// ---------------------------------------------------------------------------
// Custom metrics (tagged by region so thresholds can be per-region)
// ---------------------------------------------------------------------------
const zkViolations = new Counter("zk_guard_violations_total");

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------
export const options = {
  scenarios: {
    cross_region_health: {
      // Constant arrival rate: 6 iterations per 10 minutes (~every 100s).
      executor: "constant-arrival-rate",
      duration: "10m",
      rate: 6,
      timeUnit: "10m",
      preAllocatedVUs: 2,
      maxVUs: 4,
    },
  },
  thresholds: {
    // p99 < 200ms for EU requests
    "http_req_duration{region:eu}": ["p(99)<200"],
    // p99 < 200ms for AP-Seoul requests
    "http_req_duration{region:ap-seoul}": ["p(99)<200"],
    // Zero zero-knowledge violations allowed
    zk_guard_violations_total: ["count==0"],
  },
};

// ---------------------------------------------------------------------------
// Zero-knowledge guard — asserts no plaintext payload leakage in response
// ---------------------------------------------------------------------------
function assertZeroKnowledge(body, region) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (_) {
    zkViolations.add(1, { region });
    console.error(`[zk-guard][${region}] response body is not valid JSON`);
    return false;
  }

  // Must contain status:ok
  if (parsed.status !== "ok") {
    zkViolations.add(1, { region });
    console.error(
      `[zk-guard][${region}] expected status:ok, got: ${parsed.status}`
    );
    return false;
  }

  // Must NOT contain content or plaintext fields (zero-knowledge invariant)
  const forbidden = ["content", "plaintext"];
  for (const field of forbidden) {
    if (Object.prototype.hasOwnProperty.call(parsed, field)) {
      zkViolations.add(1, { region });
      console.error(
        `[zk-guard][${region}] forbidden field "${field}" found in response — zero-knowledge violation`
      );
      return false;
    }
  }

  return true;
}

// ---------------------------------------------------------------------------
// Default function — runs each iteration
// ---------------------------------------------------------------------------
export default function () {
  // EU health check
  const euRes = http.get(`${EU_BASE_URL}/health`, {
    tags: { region: "eu" },
    timeout: "5s",
  });

  check(euRes, {
    "[eu] status 200": (r) => r.status === 200,
    "[eu] zk invariant": (r) => assertZeroKnowledge(r.body, "eu"),
  });

  // AP-Seoul health check
  const apRes = http.get(`${AP_SEOUL_BASE_URL}/health`, {
    tags: { region: "ap-seoul" },
    timeout: "5s",
  });

  check(apRes, {
    "[ap-seoul] status 200": (r) => r.status === 200,
    "[ap-seoul] zk invariant": (r) => assertZeroKnowledge(r.body, "ap-seoul"),
  });
}

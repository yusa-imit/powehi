/**
 * cross-region-p99.js — k6 cross-region latency synthetic monitor
 *
 * Validates that EU and AP-Seoul endpoints respond within p99 <200ms for both
 * HTTP health checks and gRPC inter-region HealthCheck calls.  The gRPC path
 * exercises the same channel used by ForwardEnvelope — if gRPC HealthCheck
 * p99 < 200ms, the forwarding path meets the cross-region latency SLA
 * (prd.md §4A.6).
 *
 * Also enforces the zero-knowledge invariant: response bodies must NOT contain
 * "content" or "plaintext" fields.
 *
 * HTTP env vars (required):
 *   EU_BASE_URL=https://eu.powehi.example
 *   AP_SEOUL_BASE_URL=https://ap.powehi.example
 *
 * gRPC env vars (optional — gRPC tests skipped if absent):
 *   EU_GRPC_ADDR=eu.powehi.example:50051
 *   AP_SEOUL_GRPC_ADDR=ap.powehi.example:50051
 *   GRPC_PLAINTEXT=0     (set to 1 for non-TLS dev environments)
 *   PROTO_DIR=crates/infra/powehi-proto/proto  (path to .proto files, relative to cwd)
 *
 * Usage (from repo root):
 *   EU_BASE_URL=https://eu.powehi.example \
 *   AP_SEOUL_BASE_URL=https://ap.powehi.example \
 *   EU_GRPC_ADDR=eu.powehi.example:50051 \
 *   AP_SEOUL_GRPC_ADDR=ap.powehi.example:50051 \
 *   k6 run infra/synthetic/cross-region-p99.js
 */

import http from "k6/http";
import { check } from "k6";
import grpc from "k6/net/grpc";
import { Counter } from "k6/metrics";

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

const EU_GRPC_ADDR = __ENV.EU_GRPC_ADDR || "";
const AP_SEOUL_GRPC_ADDR = __ENV.AP_SEOUL_GRPC_ADDR || "";
const GRPC_ENABLED = EU_GRPC_ADDR !== "" && AP_SEOUL_GRPC_ADDR !== "";
const GRPC_PLAINTEXT = __ENV.GRPC_PLAINTEXT === "1";
// Path to the proto directory, relative to the k6 process working directory.
const PROTO_DIR =
  __ENV.PROTO_DIR || "crates/infra/powehi-proto/proto";

// R2 fix: GRPC_PLAINTEXT=1 is only allowed for local/dev addresses.
// Prevents accidentally probing production gRPC endpoints without mTLS.
if (GRPC_PLAINTEXT && GRPC_ENABLED) {
  const devPattern = /^(localhost|127\.0\.0\.1|.*\.local|.*\.internal)(:\d+)?$/;
  if (!devPattern.test(EU_GRPC_ADDR) || !devPattern.test(AP_SEOUL_GRPC_ADDR)) {
    throw new Error(
      "GRPC_PLAINTEXT=1 is only allowed for local/dev addresses " +
        "(localhost, 127.0.0.1, *.local, *.internal). " +
        "Production gRPC addresses require mTLS (prd.md §4A.6)."
    );
  }
}

// ---------------------------------------------------------------------------
// gRPC client (init phase — load() must be called before default())
// ---------------------------------------------------------------------------
const grpcClient = new grpc.Client();
grpcClient.load([PROTO_DIR], "region.proto");

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const zkViolations = new Counter("zk_guard_violations_total");
const grpcZkViolations = new Counter("grpc_zk_guard_violations_total");

// ---------------------------------------------------------------------------
// Thresholds — p99 <200ms for all paths (prd.md §4A.6)
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
    // HTTP health endpoints
    "http_req_duration{region:eu}": ["p(99)<200"],
    "http_req_duration{region:ap-seoul}": ["p(99)<200"],
    zk_guard_violations_total: ["count==0"],
    // gRPC HealthCheck (inter-region channel — same path as ForwardEnvelope)
    // These thresholds are registered unconditionally; they pass trivially
    // when no gRPC data points are emitted (i.e. GRPC_ENABLED=false).
    "grpc_req_duration{region:eu}": ["p(99)<200"],
    "grpc_req_duration{region:ap-seoul}": ["p(99)<200"],
    grpc_zk_guard_violations_total: ["count==0"],
  },
};

// ---------------------------------------------------------------------------
// Zero-knowledge guard — HTTP
//
// The /health endpoint returns the bare string "ok" (not JSON).
// This guard accepts either:
//   - The bare string "ok" (no forbidden fields possible)
//   - A JSON object with status:"ok" and no forbidden fields
// Any other response shape is treated as a ZK violation.
// ---------------------------------------------------------------------------
function assertZeroKnowledge(body, region) {
  // Fast path: bare "ok" response from the axum health handler.
  if (body === "ok") return true;

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (_) {
    zkViolations.add(1, { region });
    console.error(`[zk-guard][${region}] unexpected response format`);
    return false;
  }

  if (parsed.status !== "ok") {
    zkViolations.add(1, { region });
    console.error(`[zk-guard][${region}] unexpected status field value`);
    return false;
  }

  const forbidden = ["content", "plaintext"];
  for (const field of forbidden) {
    if (Object.prototype.hasOwnProperty.call(parsed, field)) {
      zkViolations.add(1, { region });
      console.error(
        `[zk-guard][${region}] forbidden field "${field}" found — zero-knowledge violation`
      );
      return false;
    }
  }

  return true;
}

// ---------------------------------------------------------------------------
// Zero-knowledge guard — gRPC HealthCheckResponse
//
// HealthCheckResponse contains only: status (int), region_id (string),
// latency_ms (uint64) — none of which are forbidden fields.  The guard still
// checks in case a future proto change inadvertently adds a content field.
// ---------------------------------------------------------------------------
function assertGrpcZeroKnowledge(response, region) {
  if (!response || !response.message) {
    grpcZkViolations.add(1, { region });
    console.error(`[grpc-zk-guard][${region}] null or empty gRPC response`);
    return false;
  }
  const forbidden = ["content", "plaintext"];
  const msg = response.message;
  for (const field of forbidden) {
    if (Object.prototype.hasOwnProperty.call(msg, field)) {
      grpcZkViolations.add(1, { region });
      console.error(
        `[grpc-zk-guard][${region}] forbidden field "${field}" in gRPC HealthCheckResponse`
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
  // ── HTTP health checks ──────────────────────────────────────────────────
  const euRes = http.get(`${EU_BASE_URL}/health`, {
    tags: { region: "eu" },
    timeout: "5s",
  });
  check(euRes, {
    "[eu] status 200": (r) => r.status === 200,
    "[eu] zk invariant": (r) => assertZeroKnowledge(r.body, "eu"),
  });

  const apRes = http.get(`${AP_SEOUL_BASE_URL}/health`, {
    tags: { region: "ap-seoul" },
    timeout: "5s",
  });
  check(apRes, {
    "[ap-seoul] status 200": (r) => r.status === 200,
    "[ap-seoul] zk invariant": (r) => assertZeroKnowledge(r.body, "ap-seoul"),
  });

  if (!GRPC_ENABLED) return;

  // ── gRPC HealthCheck — EU ───────────────────────────────────────────────
  // Exercises the inter-region gRPC channel (port 50051, mTLS in prod).
  // HealthCheck uses the same connection as ForwardEnvelope; a p99 <200ms
  // here validates the gRPC forwarding path latency SLA (prd.md §4A.6).
  // try/finally ensures close() runs even if invoke() throws (Y4 fix).
  try {
    grpcClient.connect(EU_GRPC_ADDR, {
      plaintext: GRPC_PLAINTEXT,
      timeout: "5s",
      tags: { region: "eu" },
    });
    const euGrpc = grpcClient.invoke(
      "region.RegionService/HealthCheck",
      { region_id: "synthetic-monitor" },
      { tags: { region: "eu" }, timeout: "5s" }
    );
    check(euGrpc, {
      "[eu-grpc] status OK": (r) => r !== null && r.status === grpc.StatusOK,
      "[eu-grpc] healthy": (r) =>
        r !== null &&
        r.message !== null &&
        r.message.status === "HEALTH_STATUS_HEALTHY",
      "[eu-grpc] region_id present": (r) =>
        r !== null &&
        typeof r.message.region_id === "string" &&
        r.message.region_id.length > 0,
      "[eu-grpc] zk invariant": (r) => assertGrpcZeroKnowledge(r, "eu"),
    });
  } finally {
    grpcClient.close();
  }

  // ── gRPC HealthCheck — AP-Seoul ─────────────────────────────────────────
  try {
    grpcClient.connect(AP_SEOUL_GRPC_ADDR, {
      plaintext: GRPC_PLAINTEXT,
      timeout: "5s",
      tags: { region: "ap-seoul" },
    });
    const apGrpc = grpcClient.invoke(
      "region.RegionService/HealthCheck",
      { region_id: "synthetic-monitor" },
      { tags: { region: "ap-seoul" }, timeout: "5s" }
    );
    check(apGrpc, {
      "[ap-seoul-grpc] status OK": (r) => r !== null && r.status === grpc.StatusOK,
      "[ap-seoul-grpc] healthy": (r) =>
        r !== null &&
        r.message !== null &&
        r.message.status === "HEALTH_STATUS_HEALTHY",
      "[ap-seoul-grpc] region_id present": (r) =>
        r !== null &&
        typeof r.message.region_id === "string" &&
        r.message.region_id.length > 0,
      "[ap-seoul-grpc] zk invariant": (r) => assertGrpcZeroKnowledge(r, "ap-seoul"),
    });
  } finally {
    grpcClient.close();
  }
}

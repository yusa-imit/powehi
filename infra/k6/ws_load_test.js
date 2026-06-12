// WS load test: ramp to 10 000 concurrent connections, sustain 10 min.
//
// Usage:
//   K6_BASE_URL=ws://staging.powehi.app \
//   K6_TOKENS_FILE=/tmp/k6_tokens.json \
//     k6 run infra/k6/ws_load_test.js
//
// Quick smoke run (50 VUs, 2 min):
//   K6_SMOKE=1 ... k6 run infra/k6/ws_load_test.js
//
// Token file format (JSON array of session-token UUIDs):
//   ["550e8400-e29b-41d4-a716-446655440000", ...]
//   Minimum length: max VU count.
//   Generate with: python3 infra/k6/tools/seed_load_test.py --count 10000
//
// Hardware requirements for the 10 k run:
//   k6 runner:  ≥ 4 vCPU, 16 GB RAM (single process limit ~5 k VUs);
//   for full 10 k use k6 distributed (k6 Operator) or k6 Cloud.
//   Target server: ≥ 4 vCPU, 8 GB RAM + Redis with ≥ 10 k open connections.
//
// Pass/fail criteria (prd.md Phase 5 DoD):
//   - WS connect success rate   ≥ 99 %
//   - p95 connection setup time < 500 ms  (goal: <200 ms per prd.md §60)
//   - p99 connection setup time < 1 000 ms
//   - Total ws_errors           < 1 % of peak VU count

import ws from 'k6/ws';
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import { Counter, Gauge, Rate, Trend } from 'k6/metrics';

const wsErrors       = new Counter('ws_errors');
const wsConnectRate  = new Rate('ws_connect_success');
const wsConnectMs    = new Trend('ws_connect_time_ms', true);
const wsActiveConns  = new Gauge('ws_active_connections');

// SharedArray is read once, shared across all VUs without copying.
const tokens = new SharedArray('session_tokens', function () {
  const path = __ENV.K6_TOKENS_FILE || '/tmp/k6_tokens.json';
  return JSON.parse(open(path));
});

const SMOKE = Boolean(__ENV.K6_SMOKE);

// Smoke mode: 50 VUs × 2 min (quick connectivity check).
// Load mode:  ramp to 10 k VUs, sustain 10 min, ramp down.
const smokeStages = [
  { duration: '30s', target: 50  },
  { duration: '60s', target: 50  },
  { duration: '30s', target: 0   },
];
const loadStages = [
  { duration: '2m',  target: 2_000  },
  { duration: '2m',  target: 5_000  },
  { duration: '2m',  target: 10_000 },
  { duration: '10m', target: 10_000 },
  { duration: '2m',  target: 0      },
];

export const options = {
  scenarios: {
    ws_connections: {
      executor:          'ramping-vus',
      startVUs:          0,
      stages:            SMOKE ? smokeStages : loadStages,
      gracefulRampDown:  '30s',
    },
  },
  thresholds: {
    ws_connect_success:  [{ threshold: 'rate>=0.99', abortOnFail: true }],
    ws_connect_time_ms:  ['p95<500', 'p99<1000'],
    ws_errors:           [`count<${SMOKE ? 5 : 100}`],
  },
};

const BASE_URL = __ENV.K6_BASE_URL || 'ws://localhost:3000';

export default function () {
  // Distribute tokens evenly across VUs; wrap around if tokens < peak VUs.
  const token  = tokens[(__VU - 1) % tokens.length];
  const url    = `${BASE_URL}/v1/ws`;
  const params = { headers: { Authorization: `Bearer ${token}` } };

  const res = ws.connect(url, params, function (socket) {
    socket.on('open', function () {
      wsActiveConns.add(1);

      // Hold connection for up to 15 min (longer than the longest stage).
      // k6 will tear down the VU when the scenario ends, closing the socket.
      socket.setTimeout(function () { socket.close(); }, 900_000);
    });

    // Periodic keepalive ping — mirrors what Powehi browser clients send.
    socket.setInterval(function () {
      socket.ping();
    }, 30_000);

    socket.on('pong', function () { /* no-op */ });

    socket.on('message', function (data) {
      // WS notifications (EnvelopeReceived, EpochAdvanced, …) are expected
      // in a real deployment.  Validate JSON shape without logging content.
      try {
        const msg = JSON.parse(data);
        if (!msg.type) {
          wsErrors.add(1);
        }
      } catch (_) {
        wsErrors.add(1);
      }
    });

    socket.on('error', function (e) {
      const msg = e.error ? e.error() : String(e);
      // 1000 = normal closure, 1001 = going away — both expected.
      if (!msg.includes('1000') && !msg.includes('1001')) {
        wsErrors.add(1);
      }
    });

    socket.on('close', function () {
      wsActiveConns.add(-1);
    });
  });

  // res.timings.waiting = elapsed time until the HTTP 101 headers arrived,
  // i.e. the WebSocket handshake latency (target: <200 ms per prd.md).
  wsConnectMs.add(res.timings.waiting);
  wsConnectRate.add(res.status === 101);

  check(res, { 'WS upgrade 101': (r) => r.status === 101 });
}

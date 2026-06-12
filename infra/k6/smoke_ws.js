// Smoke test: 5 VUs × 30 s — validates basic WS upgrade + keep-alive.
//
// Usage:
//   K6_BASE_URL=ws://localhost:3000 K6_TEST_TOKEN=<session-uuid> \
//     k6 run infra/k6/smoke_ws.js
//
// Prerequisites:
//   - A live Powehi server at K6_BASE_URL
//   - One pre-seeded session token in Redis:
//       SETEX session:<token> 86400 <device_uuid_bytes_16>
//   See infra/k6/tools/seed_load_test.py for automated seeding.

import ws from 'k6/ws';
import { check } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const wsErrors       = new Counter('ws_errors');
const wsConnectRate  = new Rate('ws_connect_success');
const wsConnectMs    = new Trend('ws_connect_time_ms', true);

export const options = {
  vus:      5,
  duration: '30s',
  thresholds: {
    ws_connect_success:  ['rate>=1.00'],
    ws_connect_time_ms:  ['p95<1000'],
    ws_errors:           ['count==0'],
  },
};

const BASE_URL = __ENV.K6_BASE_URL  || 'ws://localhost:3000';
const TOKEN    = __ENV.K6_TEST_TOKEN || '';

export default function () {
  if (!TOKEN) {
    console.error('K6_TEST_TOKEN is required');
    return;
  }

  const url    = `${BASE_URL}/v1/ws`;
  const params = { headers: { Authorization: `Bearer ${TOKEN}` } };

  const res = ws.connect(url, params, function (socket) {
    socket.on('open', function () {
      // Hold the connection for 25 s then close cleanly.
      socket.setTimeout(function () { socket.close(); }, 25_000);
    });

    socket.setInterval(function () {
      socket.ping();
    }, 10_000);

    socket.on('pong', function () { /* keepalive ack — no-op */ });

    socket.on('error', function (e) {
      const msg = e.error ? e.error() : String(e);
      // Normal closure is not an error.
      if (!msg.includes('1000')) {
        wsErrors.add(1);
        console.error(`ws error: ${msg}`);
      }
    });
  });

  // res.timings.waiting = time to receive the 101 Switching Protocols headers.
  wsConnectMs.add(res.timings.waiting);
  wsConnectRate.add(res.status === 101);

  check(res, { 'WS upgrade 101': (r) => r.status === 101 });
}

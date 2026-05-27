/**
 * k6 load test — 10,000 concurrent WebSocket connections
 *
 * Target: POST /v1/ws (authenticated WebSocket upgrade)
 *
 * Run:
 *   k6 run --env TARGET_HOST=localhost:8080 --env WS_TOKEN=<bearer> load-tests/ws-10k.js
 *
 * Expected results (Phase 5 DoD):
 *   - 10,000 concurrent connections sustained for 60 s
 *   - ws_connecting p95 < 500 ms
 *   - ws_msgs_received rate > 0 (server is pushing notifications)
 *   - error_rate < 1 %
 */

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const wsConnectErrors = new Counter('ws_connect_errors');
const wsMsgsReceived = new Counter('ws_msgs_received');
const wsInvalidJson = new Counter('ws_invalid_json');
const wsConnectDuration = new Trend('ws_connect_duration_ms');
const errorRate = new Rate('error_rate');

export const options = {
  stages: [
    { duration: '30s', target: 2000 },  // ramp to 2 k
    { duration: '30s', target: 5000 },  // ramp to 5 k
    { duration: '30s', target: 10000 }, // ramp to 10 k
    { duration: '60s', target: 10000 }, // sustain 10 k for 60 s
    { duration: '30s', target: 0 },     // ramp down
  ],
  thresholds: {
    // Phase 5 DoD gate
    ws_connecting: ['p(95)<500'],
    ws_connect_duration_ms: ['p(95)<500'],
    error_rate: ['rate<0.01'],
  },
};

const TARGET = __ENV.TARGET_HOST || 'localhost:8080';
const TOKEN = __ENV.WS_TOKEN || 'test-token';

export default function () {
  const url = `ws://${TARGET}/v1/ws`;
  const start = Date.now();

  const params = {
    headers: {
      Authorization: `Bearer ${TOKEN}`,
    },
  };

  const res = ws.connect(url, params, (socket) => {
    wsConnectDuration.add(Date.now() - start);

    socket.on('open', () => {
      // No data to send — this client only listens for push notifications.
    });

    socket.on('message', (raw) => {
      wsMsgsReceived.add(1);
      try {
        const msg = JSON.parse(raw);
        // Verify notification carries no ciphertext / plaintext content
        check(msg, {
          'no content field': (m) => !('content' in m),
          'no ciphertext field': (m) => !('ciphertext' in m),
          'has type field': (m) => typeof m.type === 'string',
        });
      } catch {
        wsInvalidJson.add(1);
        errorRate.add(1);
      }
    });

    socket.on('error', (e) => {
      // k6 surfaces GoingAway as a normal close; ignore it.
      if (e.error() !== 'GoingAway') {
        wsConnectErrors.add(1);
        errorRate.add(1);
      }
    });

    socket.on('close', () => {
      errorRate.add(0);
    });

    // Hold the connection open for 25 s then close gracefully, leaving room
    // for the 30 s sustain stage without every VU timing out mid-stage.
    socket.setTimeout(() => {
      socket.close();
    }, 25000);
  });

  const connected = check(res, {
    'HTTP 101 Switching Protocols': (r) => r && r.status === 101,
  });

  if (!connected) {
    wsConnectErrors.add(1);
    errorRate.add(1);
  }

  // Small jitter to avoid thundering-herd reconnects during the ramp.
  sleep(Math.random() * 0.5);
}

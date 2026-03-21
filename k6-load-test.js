import http from 'k6/http';
import grpc from 'k6/net/grpc';
import { check, group, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const http1Rate = new Rate('http1_requests');
const http2Rate = new Rate('http2_requests');
const grpcRate = new Rate('grpc_requests');

export const options = {
  // Test phases: ramp up → sustained → ramp down
  stages: [
    { duration: '2m', target: 100 },   // 0 → 100 VUs over 2m
    { duration: '5m', target: 500 },   // 100 → 500 VUs over 5m (main load)
    { duration: '3m', target: 100 },   // 500 → 100 VUs over 3m
    { duration: '1m', target: 0 },     // 100 → 0 VUs over 1m
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500', 'p(99)<1000'],  // 95th percentile < 500ms
    'http_req_failed': ['rate<0.1'],                     // Error rate < 10%
    'errors': ['rate<0.05'],                             // Custom error rate < 5%
  },
  ext: {
    loadimpact: {
      projectID: 0,
      name: 'API-Sentinel Real Traffic Test',
    },
  },
};

// Configuration
const BASE_URL = __ENV.TARGET_URL || 'http://staging-api.local';
const GRPC_ENDPOINT = __ENV.GRPC_URL || 'staging-api.local:50051';
const PROTOCOL_MIX = {
  http1: 0.4,   // 40% HTTP/1.1
  http2: 0.35,  // 35% HTTP/2
  grpc: 0.15,   // 15% gRPC
  websocket: 0.1, // 10% WebSocket
};

/**
 * HTTP/1.1 Test Endpoints
 */
function testHTTP1() {
  const res = http.get(`${BASE_URL}/api/v1/users`, {
    headers: {
      'Connection': 'close',
    },
    tags: { protocol: 'HTTP/1' },
  });

  const success = check(res, {
    'HTTP/1.1 status 200': (r) => r.status === 200,
    'HTTP/1.1 response time < 500ms': (r) => r.timings.duration < 500,
  });

  http1Rate.add(!success);
  errorRate.add(!success);
  sleep(0.5);
}

/**
 * HTTP/2 Test Endpoints
 */
function testHTTP2() {
  const res = http.get(`${BASE_URL}/api/v2/products`, {
    headers: {
      'Accept': 'application/json',
    },
    tags: { protocol: 'HTTP/2' },
  });

  const success = check(res, {
    'HTTP/2 status 200': (r) => r.status === 200,
    'HTTP/2 response time < 500ms': (r) => r.timings.duration < 500,
  });

  http2Rate.add(!success);
  errorRate.add(!success);
  sleep(0.5);
}

/**
 * gRPC Test Endpoints
 */
function testGRPC() {
  const client = new grpc.Client();
  client.load([], 'service.proto');
  client.connect(GRPC_ENDPOINT, {
    plaintext: true,
  });

  const payload = {
    id: Math.floor(Math.random() * 10000),
  };

  try {
    const res = client.invoke('service.GetItem', payload, {});
    const success = res.status === 0;
    grpcRate.add(!success);
    errorRate.add(!success);
  } catch (e) {
    errorRate.add(1);
  } finally {
    client.close();
  }

  sleep(0.5);
}

/**
 * Mixed Protocol Endpoints (realistic API patterns)
 */
function testMixedTraffic() {
  // REST API calls
  const restEndpoints = [
    '/api/users',
    '/api/users/123',
    '/api/posts/456',
    '/api/comments',
    '/api/search?q=test',
  ];

  const endpoint = restEndpoints[Math.floor(Math.random() * restEndpoints.length)];
  const method = Math.random() < 0.8 ? 'GET' : 'POST';

  const params = method === 'POST' ? {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      title: 'Load test post',
      content: 'Real traffic simulation',
      timestamp: new Date().toISOString(),
    }),
  } : { method: 'GET' };

  const res = http.request(method, `${BASE_URL}${endpoint}`, undefined, params);

  const success = check(res, {
    'Request successful': (r) => r.status >= 200 && r.status < 400,
    'Response time < 1s': (r) => r.timings.duration < 1000,
  });

  errorRate.add(!success);
  sleep(Math.random() * 2); // Random delay 0-2 seconds
}

/**
 * Concurrent connection test (connection tracking)
 */
function testConcurrentConnections() {
  const batch = http.batch([
    ['GET', `${BASE_URL}/api/v1/health`],
    ['GET', `${BASE_URL}/api/v2/status`],
    ['GET', `${BASE_URL}/api/v3/info`],
    ['GET', `${BASE_URL}/api/v4/metrics`],
  ]);

  batch.forEach((response) => {
    check(response, {
      'Concurrent request status OK': (r) => r.status === 200,
    });
  });

  sleep(1);
}

/**
 * Anomaly detection patterns (high entropy, deep paths)
 */
function testAnomalyPatterns() {
  const patterns = [
    `/api/users/${Math.random().toString(36).substring(7)}/settings`,
    `/api/data/${Math.random().toString(36).substring(7)}/files/download`,
    `/api/query?filter=${Math.random().toString(36).substring(7)}&sort=asc`,
    `/api/admin/${Math.random().toString(36).substring(7)}/config`,
  ];

  const pattern = patterns[Math.floor(Math.random() * patterns.length)];
  const res = http.get(`${BASE_URL}${pattern}`);

  check(res, {
    'Anomaly pattern detected': (r) => r.status !== 404,
  });

  sleep(0.5);
}

/**
 * Main test function
 */
export default function () {
  group('Real Traffic Simulation', () => {
    const rand = Math.random();

    if (rand < PROTOCOL_MIX.http1) {
      testHTTP1();
    } else if (rand < PROTOCOL_MIX.http1 + PROTOCOL_MIX.http2) {
      testHTTP2();
    } else if (rand < PROTOCOL_MIX.http1 + PROTOCOL_MIX.http2 + PROTOCOL_MIX.grpc) {
      // testGRPC(); // Uncomment if gRPC endpoint available
      testMixedTraffic();
    } else {
      testMixedTraffic();
    }

    // Periodically test concurrent connections and anomaly patterns
    if (Math.random() < 0.1) {
      testConcurrentConnections();
    }
    if (Math.random() < 0.05) {
      testAnomalyPatterns();
    }
  });
}

/**
 * Setup phase - verify connectivity
 */
export function setup() {
  const res = http.get(`${BASE_URL}/health`);
  if (res.status !== 200) {
    throw new Error(`Cannot reach target: ${BASE_URL}, status: ${res.status}`);
  }
  console.log(`✓ Target reachable at ${BASE_URL}`);
}

/**
 * Teardown phase - summary
 */
export function teardown() {
  console.log('✓ Load test complete');
}

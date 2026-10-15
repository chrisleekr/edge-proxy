// Steady traffic through the mock LB while load-full.sh restarts or kills
// edges: rolling restarts must serve no 5xx, and losing one
// of three edges must hold the target rate.
import http from 'k6/http';
import { check } from 'k6';
import { thresholdReport, viewer } from '../lib.js';

const RATE = Number(__ENV.RATE || 300);
const DURATION = __ENV.DURATION || '90s';
const MAX_ERRORS = __ENV.MAX_ERRORS || '0';

export const options = {
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  scenarios: { lb: { executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DURATION, preAllocatedVUs: 100, maxVUs: 1000 } },
  thresholds: {
    http_req_failed: [`rate<=${MAX_ERRORS}`],
    dropped_iterations: [`count<${RATE}`], // under one second of traffic
  },
};

let n = 0;
export default function () {
  check(http.get('http://lb:8000/api/items', { headers: viewer(__VU * 100000 + n++) }), { 'no 5xx': (r) => r.status < 500 });
}

export function handleSummary(data) {
  return { stdout: `\n${__ENV.LABEL || 'Through the LB'}\n` + thresholdReport(data) };
}

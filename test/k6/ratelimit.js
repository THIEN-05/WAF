import http from 'k6/http';
import { check } from 'k6';

// Configure a low per-site limit for POST /login in the loaded edge snapshot.
// Run with: k6 run -e BASE_URL=http://127.0.0.1:8080 -e SITE_HOST=site.test test/k6/ratelimit.js
export const options = {
  vus: Number(__ENV.VUS || 20),
  duration: __ENV.DURATION || '30s',
  thresholds: {
    checks: ['rate>0.5'],
  },
};

const baseURL = __ENV.BASE_URL || 'http://127.0.0.1:8080';
const siteHost = __ENV.SITE_HOST || 'site.test';

export default function () {
  const response = http.post(`${baseURL}/login`, null, {
    headers: { Host: siteHost },
  });
  check(response, { 'rate limit returns 429': (r) => r.status === 429 });
}

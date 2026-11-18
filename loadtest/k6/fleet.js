// Synthetic clients for the fingerprint scenarios: a fleet of many IPs that
// share one browser fingerprint but claim stale browsers, and a cohort of real
// users on the same fingerprint with current ones. Every address is from a
// documentation range or this test's own 20.0.0.0/8, and the JA4 is made up.
import http from 'k6/http';
import { edges, pick } from './lib.js';

// TLS 1.3, h2, 15 ciphers, 16 extensions: a shape browsers share, with made-up hashes.
const JA4 = 't13d1516h2_0123456789ab_ba9876543210';

const ok = http.expectedStatuses(200, 429);

// fleetAddress cycles through 762 addresses of the three IPv4 documentation
// ranges, then 4238 of 2001:db8::/32, so an address repeats every 5000 requests.
const v4 = ['192.0.2', '198.51.100', '203.0.113'];
function fleetAddress(n) {
  const i = n % 5000;
  if (i < 3 * 254) return `${v4[i % 3]}.${1 + Math.floor(i / 3)}:443`;
  const j = i - 3 * 254;
  return `[2001:db8:${(j >> 8).toString(16)}:${(j & 255).toString(16)}::1]:443`;
}

const hints = (brand, v) => `"Chromium";v="${v}", "${brand}";v="${v}", "Not.A/Brand";v="99"`;
const chrome = (v) => ({ ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`, ch: hints('Google Chrome', v) });
const edge = (v) => ({ ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36 Edg/${v}.0.0.0`, ch: hints('Microsoft Edge', v) });
// Firefox never sends Sec-CH-UA; the fleet sends a Chrome-style one anyway.
const firefox = (os, v) => ({ ua: `Mozilla/5.0 (${os}; rv:${v}.0) Gecko/20100101 Firefox/${v}.0`, ch: hints('Google Chrome', 119) });
const stale = [chrome(118), chrome(119), chrome(120), edge(118), edge(119), edge(120),
  firefox('Windows NT 10.0; Win64; x64', 120), firefox('Windows NT 10.0; Win64; x64', 121), firefox('X11; Linux x86_64', 120), firefox('Macintosh; Intel Mac OS X 10.15', 121)];

// browserHeaders are what a browser sends over HTTPS on HTTP/2, as the CDN
// forwards them. Without the proto header the edge ignores the fingerprint.
const browserHeaders = (address, b) => ({
  Host: 'api.example.com',
  'CloudFront-Viewer-Address': address,
  'CloudFront-Forwarded-Proto': 'https',
  'CloudFront-Viewer-Http-Version': '2.0',
  'CloudFront-Viewer-JA4-Fingerprint': JA4,
  'User-Agent': b.ua,
  'Sec-CH-UA': b.ch,
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Sec-Fetch-Dest': 'document',
  'Accept-Language': 'en-US,en;q=0.9',
});

// fleetRequest is the n-th request of the fleet: a new address, one of 10
// stale browsers and a new query string, so no cache answers it.
export const fleetRequest = (n) => http.get(`${pick(edges)}/pages/p${n % 50}?cb=${n}`, { headers: browserHeaders(fleetAddress(n), stale[n % stale.length]), responseCallback: ok });

// cohortRequest is the n-th request of 300 real users on the same fingerprint, on a current Chrome.
export const cohortRequest = (n) => http.get(`${pick(edges)}/pages/home`, { headers: browserHeaders(`20.100.${(n % 300) >> 8}.${n % 300 % 256}:443`, chrome(138)), responseCallback: ok });

// Example values by field, shown as placeholders so an empty box says what
// to type.
export const valueExample: Record<string, string> = {
  'http.request.full_uri': 'https://api.example.com/v1/orders?page=2',
  'http.request.uri': '/v1/orders?page=2',
  'http.request.uri.path': '/v1/orders',
  'http.request.uri.query': 'page=2',
  'http.host': 'api.example.com',
  'http.request.method': 'POST',
  'http.cookie': 'session=abc',
  'http.referer': 'https://www.example.com/',
  'http.user_agent': 'curl/8.7.1',
  'http.x_forwarded_for': '203.0.113.7',
  'ip.src': '203.0.113.7',
  'ip.src.country': 'AU',
  'ip.src.asnum': '13335',
  'edge.locale': 'en-AU',
  'tls.client.ja4': 't13d1516h2_8daaf6152771_02713d6af862',
  'tls.client.ja3': '773906b0efdefa24a7f2b8eb6985bf37',
  'client.signals': 'ua_tool',
  'client.ip_lists': 'aws',
};

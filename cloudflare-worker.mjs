import { Container, getContainer } from '@cloudflare/containers';

const STATIC_ASSET_CSP = `default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self' data:; form-action 'self' mailto:; frame-ancestors 'none'; frame-src 'none'; img-src 'self' data:; manifest-src 'self'; media-src 'self'; object-src 'none'; script-src 'self' 'sha256-/eg+SNmROvaNNnUAEmESL/LHQRGvDLnzid7QTOagOXU=' 'sha256-1Ac6+32bz5Lti7IBxlR5UBwV/yERPIl0BiC5fpK74mc=' 'sha256-20LjVSRvWp12Wts3BjS+1+c4HhRC01n3OhZNaOqT1B4=' 'sha256-27hvD/nMLGvKeAu7Ea7c5+extDLRlqoEeYc51+WppME=' 'sha256-2NJABd4whHRS0Ovb0CJktoOJYejXgqGIKjeAu+pMXo8=' 'sha256-3AjDm1nb2aD6HZuaDpXR9S3VoSswbitNzYbll4WVS6Q=' 'sha256-3FEBG3l2Kvd4jGI+v4RPdcMyHCEthZuDD79aK2gmfkw=' 'sha256-3R81JWZvCZHN77B5u5gcja6Pu0PSft2FyrviEzvIK1o=' 'sha256-5S2JTVZHTy74ntadOzOSyrHmGzB6MvMIeOkvysks88w=' 'sha256-6iMjPrAV08RivCXhbwnsdbn9D/G9PQzRhgmb06vjwmU=' 'sha256-6ml7+x3xjdlUnrLVcvuL7LBLN9cGrTn+zk6C1CamMZI=' 'sha256-75KNWDXzqq3f5Ean/nlEraroYktWTOcQnrMfX2QDhIQ=' 'sha256-9mGzwR/j4noY0D2+8CkOa92YJOs3JW1go4BEoc+b38E=' 'sha256-9sjd4TLjYlLjEqCPOgXhVMY+B0fgJ1YKVRRcMf95mmo=' 'sha256-9ut4UPLsXtmfnFV7yZTLqm9DPJb7kK8M0q0zntHLPFI=' 'sha256-AM5yeHpgJoVlEpYXeymc/RSvohbo3P3QinIW7WSk2Nk=' 'sha256-HnSR7X+3sywDHZSQwQ0JG1NRcXnuOdGsFs5RP8IN46M=' 'sha256-ISjZ2qpiAYtEEKvLqqEYw9mvGjzDoePPqHmVN7XECB4=' 'sha256-IY6LsqExpnv2KuxEGAgOavFAj2M/V21doKnh9zSQfYA=' 'sha256-IYUZHzo+W4bePYgtTBi3DuIYIvU7TcM0L9YQxPUcsuk=' 'sha256-J5Xm+7HZ5UIiemV7qXb/jmRRlBoMrHnKgSLgJfVDWk4=' 'sha256-N0fiNv/PSuYHi/fUkxyr+bHk67hj87wul0zoThL+O64=' 'sha256-Nflb/kikg79eV9PEf3yhCI13GYruQM+Zi4I964poGu0=' 'sha256-Pl+N552UNxmmZj+oiMK+7Lu6UERm6aMBomexZfBWXlM=' 'sha256-QE1bEyshWZIsdRtTRCKCLPQHTzFdKCD88+1BV6xcC+s=' 'sha256-STwR1AlzmY6sN6T+C1CD/ABx3dxQX1fMAHmu39EbGSs=' 'sha256-TKS/MP+WAJb1wegsd6J/zV9yoGH17GswOh3tLQldcWg=' 'sha256-U1tjTe8NMjb695b00hzuCWnbDdSrroJwkb4uTDsUE/4=' 'sha256-WvstBcur5UGWavj/atsYH7tIHgZ2wQw0ozRT8IRyLIU=' 'sha256-XbGFBTqpAwdgG5m5S+JOrLqBPXA/n+QW2iY6088KzPM=' 'sha256-YoGoZXboVLcGuIb+Ekb2+cUoMqq2IjlD3gqTBujJaUE=' 'sha256-ZDfdtxkSPRsiTxb3cQs2HNelWKrxoISwOWFX9w1Tso4=' 'sha256-Zl+QBWg7jRlOl93iLzaLaaqz2D5nEQpavRM3JcV2Tns=' 'sha256-a2ZOopbRyrEQ2aoSnW6sD9aEYa99gb5G8HuNUwc3Tbk=' 'sha256-frxsQNZ+y+pNimf4ZIia/qdFA/eDz17Xpt+YE3NTV04=' 'sha256-hbbcZmlA8F7rfyDJhV4jUIdsVRLvoFA8M8120+EMlhw=' 'sha256-iKjqoKZNdyDdpHQ/inIygP4HqNLl6SpTpaucNIAdLuo=' 'sha256-jgguVM9voItK0VDAYLzeVqeFdZFz3k4BDKoCv0+GoCU=' 'sha256-l6/flC0VYwFeGgmwbH/u5Li97iPz8pTt0zHgKaOC544=' 'sha256-mojGLA4EcYj6GSQO345x42YipB+dEkdhdGLndYQXQug=' 'sha256-nAMUp1A8zU7EUgsDp9gXalycO8fSjq2XULZ2pjvorjE=' 'sha256-o1YC1SWmQw2zHksfOfLfYMQFJThb596fDNyA3DGSslI=' 'sha256-ppMu95egoisLTUuqVsMsdCWQkunqrur1IrcUq/qhS0I=' 'sha256-qczV/h9DuO1HPIsIKLGbOxHGGcQbifGEFneYW5TS9cY=' 'sha256-rW0quz2LgQyVVAOpZtFSxdo32BT8OWKg17aG6Zg7tnA=' 'sha256-rhblUxmA3qT9zW/WZqUrrp6TixVjNWZRDQbiR6eDSLw=' 'sha256-tNjXkw6mW8i0FH2s7rDsqIII+qIVyp0JNrQUOFc5zgU=' 'sha256-vyD0tDLKSgU2naTnaXTz2+x9ZDwIx28ZDvB62usV+EQ=' 'sha256-wrNIHZ0JUuVZCyBp72cokgqxl2QyfG9zbAh58XsJjDo=' 'sha256-xJ4ojrTkxBvfJqGdemPxn26gajMnMipZhwaTD+lrs6g=' 'sha256-xO0q/VvQs3PxpgmXz8qqwK4/3v8jhPTogX2wrlqUepM=' 'sha256-xY+27ij860ERoRai+yPd/z7FTY+CK/W55IaSnDVx85c=' 'sha256-xw1hGaDf8uLlV6VC8doZ/Ef5gpq8Rkqy+xDRDuC5aMA=' 'sha256-y+3VeUhIMwG8+x09E/zfyCJtu3CuV6aArdsZNMbnySQ=' 'sha256-yMUde8KRWoYMVQW1DxyFbR2cWUvbZnp5z8lLy8TMDOQ=' 'sha256-yR4mRMR29YGHOgcEvZud8Atbq1GOYilG/3GzxnmJxkA=' 'sha256-zD0fs8SOoHI5WPvNF6cBtnCAhXaiQGS8NqrnzCl4bNA=' 'sha256-zE3bWqFZ4gG47q0WZ2jAF/O18Dhq69ve5SwGGvaveZs='; script-src-attr 'none'; style-src 'self' 'sha256-+iEQIv8RHqJQeKC4VeBvfVSn6tAZUg+s0UR9EtyAgVo=' 'sha256-/BECnrnyoa7L7AI7aF9w9O/YuQgdaICJ8aDkqV9GYyA=' 'sha256-8ADYNY7huMHQZhqVTxT4yAQ2aWK2GendPRdWZOt5JYM=' 'sha256-Bmnw9BwCpzdUjUf+xROJi6uBn2kBbmx3S3gP34FaaDw=' 'sha256-HCS+uQlSPBoLE3yHOYxdokmp+VUB1wZJ7OVDDBBwdkA=' 'sha256-JzEMc2b4qDmLyqWuQ7OLk7Td9eGGFIL6CTW2VkKcVds=' 'sha256-KV1BUqvXbMRixJQ1nJMZSoBxW8nuBvCGW1B4/Ws8pWk=' 'sha256-L4u425WQgylo/SszyV6ItYRkNYHF00+n5uJJ/jDAQVA=' 'sha256-M/+g5/2AWfdHdwa7Ua/WpVi1g3uSQQzUR0fEeMpSiIs=' 'sha256-OsOoawF+IJfSu+d7+evkRrzozl+azbrH7y58guMlfo8=' 'sha256-OyRFupB1cej1us5rmw3wyo/ioDxrdka5feL5nlFBTrU=' 'sha256-RL043fRuIRZYNiQcwX20lV4etHB7pnBBQJV5omMYRPw=' 'sha256-Rl8kXk+wH9RApl1LyQMkQUrveReyico6FREGdxeHz+g=' 'sha256-U6QGcIZ1jcitIz3IDE+yI40vcf2kY+QByk/DkplZH5c=' 'sha256-VbvoV1CpUtqGk4owrU7s++1rAvOeUHVPmoygvAq4LWE=' 'sha256-jIxef98va+T4i6SFk2teue5Zx1ePjaeqkqDxv0JoENo=' 'sha256-nGhadWYpwtPzAGJrVlS5GvBCkOpnpzwvbpjtj7W0/kQ=' 'sha256-r4BatnmBZTgAJXYMOgQfCnXSDPKeK9e522IIcL1RMvk=' 'sha256-tXocnDKr6eHTgLx3PqAy7Gvw+msSKJm+7DdZ8YUZfIY=' 'sha256-v/k1CTXflaLmlr7OiW8+BvN9R3+1cj33bzY0GlL7nbQ=' 'sha256-ve/ZlwjD7dxuOvqv21IsKOaUt9Q1iYLeOQ2bY9htb00=' 'sha256-yyu6DQJZ/DXFc+tYKIyF2JWYicaJVKBEWz+WYX+H/Hk='; style-src-attr 'unsafe-inline'; upgrade-insecure-requests; worker-src 'none'`;

const RECOVERY_PRIVATE_ENV_NAMES = Object.freeze(new Set([
  'DIRAC_CENTRAL_VERCEL2_ACTIONS_ENABLED',
  'DIRAC_VERCEL2_ACTIONS_ENABLED',
  'DIRAC_CENTRAL_VERCEL2_ONLY_ACTIONS',
  'DIRAC_VERCEL2_ONLY_ACTIONS',
  'DIRAC_RECOVERY_WORKER_ALLOWED_CALLER',
  'DIRAC_RECOVERY_WORKER_MAX_BODY_BYTES',
  'DIRAC_RECOVERY_WORKER_CLOCK_SKEW_SECONDS',
  'DIRAC_RECOVERY_WORKER_X25519_PRIVATE_KEY',
  'DIRAC_RECOVERY_WORKER_MLKEM1024_PRIVATE_KEY',
  'DIRAC_LOST_PASSKEY_ARGON2_MEMORY_KIB',
  'DIRAC_LOST_PASSKEY_ARGON2_TIME_COST',
  'DIRAC_LOST_PASSKEY_ARGON2_PARALLELISM',
  'DIRAC_LOST_PASSKEY_LINK_OPEN_ARGON2_MEMORY_KIB',
  'DIRAC_LOST_PASSKEY_LINK_OPEN_ARGON2_TIME_COST',
  'DIRAC_LOST_PASSKEY_LINK_OPEN_ARGON2_PARALLELISM',
  'DIRAC_LOST_PASSKEY_ROOT_SECRET',
  'DIRAC_LOST_PASSKEY_ROOT_SECRET_VERSION',
  'DIRAC_LOST_PASSKEY_DB_PEPPER',
  'DIRAC_LOST_PASSKEY_MAX_RUNNING',
  'DIRAC_LOST_PASSKEY_QUEUE_MAX',
  'DIRAC_LOST_PASSKEY_PROCESSING_LOCK_TTL_SECONDS',
  'DIRAC_LOST_PASSKEY_QUEUE_DISABLED',
  'DIRAC_LOST_PASSKEY_QUEUE_LOCK_TTL_SECONDS',
  'DIRAC_LOST_PASSKEY_QUEUE_MAX_WAIT_SECONDS',
  'DIRAC_LOST_PASSKEY_QUEUE_POLL_MS',
  'DIRAC_RECOVERY_SERVER1_URL',
  'DIRAC_RECOVERY_SERVER1_ORIGIN',
  'DIRAC_RECOVERY_SERVER1_SERVER_ID',
  'DIRAC_RECOVERY_HPKE_PRIVATE_KEY',
  'DIRAC_RECOVERY_HPKE_KEY_ID',
  'DIRAC_RECOVERY_HPKE_PEPPER',
  'DIRAC_RECOVERY_HPKE_PEPPER_KEY_ID',
  'DIRAC_RECOVERY_HPKE_ARGON2_MEMORY_KIB',
  'DIRAC_RECOVERY_HPKE_ARGON2_TIME_COST',
  'DIRAC_RECOVERY_MLKEM1024_PRIVATE_KEY_PEM',
  'DIRAC_RECOVERY_MLKEM1024_PRIVATE_KEY_DER_B64',
  'DIRAC_RECOVERY_MLDSA87_PRIVATE_KEY_PEM',
  'DIRAC_RECOVERY_MLDSA87_PRIVATE_KEY_DER_B64',
  'DIRAC_LOST_PASSKEY_ED25519_PRIVATE_KEY',
  'DIRAC_LOST_PASSKEY_ED25519_PRIVATE_KEY_PEM'
]));

const EDGE_LABELS = Object.freeze(new Set([
  'api', 'auth', 'dashboard', 'panel', 'order', 'pesanan', 'security',
  'parfum', 'shop', 'secure', 'recovery', 'www', 'project', 'domain',
  'topup', 'pt', 'cs', 'website'
]));

const DIRECT_ROLE_BY_LABEL = Object.freeze({
  auth: 'auth',
  dashboard: 'dashboard',
  panel: 'dashboard',
  order: 'pesanan',
  pesanan: 'pesanan',
  security: 'security',
  parfum: 'parfum',
  shop: 'parfum',
  www: 'www'
});

const ACTION_ALIASES = Object.freeze({
  'domain-login': 'domain_login',
  'domain-register': 'domain_register',
  'domain-logout': 'domain_logout',
  'domain-health': 'domain_health',
  'hostinger-check': 'hostinger_check',
  'check-domain': 'domain_check',
  'create-order': 'domain_checkout',
  'get-orders': 'domain_orders',
  'dashboard-summary': 'domain_dashboard_me',
  dashboard_summary: 'domain_dashboard_me',
  'customer-summary': 'customer_security_overview',
  customer_summary: 'customer_security_overview',
  customer_security_recovery_codes_verify: 'customer_security_recovery_code_verify',
  'customer-security-status': 'customer_security_status',
  'customer-security-overview': 'customer_security_overview',
  'midtrans-webhook': 'midtrans_webhook',
  'midtrans-health': 'midtrans_health'
});

const AUTH_ACTIONS = Object.freeze(new Set([
  'domain_login', 'domain_register', 'domain_logout', 'domain_me', 'domain_dashboard_me', 'domain_mfa_status',
  'dirac_mfa_passkey_start', 'dirac_mfa_passkey_verify', 'domain_mfa_passkey_start',
  'domain_mfa_passkey_verify', 'dirac_mfa_passkey_status', 'domain_mfa_passkey_status',
  'dirac_passkey_status', 'domain_passkey_status', 'customer_session_handoff_issue',
  'customer_security_recovery_codes_generate', 'customer_security_recovery_code_verify',
  'customer_security_recovery_hpke_submit', 'midtrans_webhook', 'security_report'
]));

const DASHBOARD_ACTIONS = Object.freeze(new Set([
  'domain_dashboard_me', 'dashboard', 'my_orders', 'customer_orders', 'pesanan_saya',
  'my_invoices', 'customer_invoices', 'invoices', 'invoice_saya', 'my_bills',
  'my_shipments', 'customer_shipments', 'pengiriman_saya', 'my_domains', 'customer_domains',
  'my_projects', 'customer_projects', 'my_tickets', 'customer_tickets', 'tiket_bantuan',
  'my_notifications', 'customer_notifications', 'notifications', 'notifikasi',
  'dirac_session_handoff_prepare', 'customer_session_handoff_consume'
]));

const SECURITY_ACTIONS = Object.freeze(new Set([
  'customer_security_status', 'customer_security_overview', 'customer_security_guard_status',
  'customer_security_revoke_session', 'customer_security_revoke_other_sessions',
  'customer_security_account_request', 'customer_security_recovery_codes_status',
  'customer_security_recovery_codes_generate', 'customer_security_recovery_code_verify',
  'dirac_mfa_passkey_start', 'dirac_mfa_passkey_verify',
  'customer_security_features_bundle', 'customer_security_features_bundle_v2',
  'customer_security_features_bundle_v3', 'customer_security_trusted_devices',
  'customer_security_login_history', 'customer_security_score', 'customer_security_notifications',
  'customer_security_request_tracker', 'customer_security_trust_current_device',
  'customer_security_untrust_device', 'customer_security_prune_login_history',
  'admin_security_overview', 'admin_security_events', 'admin_security_blocks',
  'admin_security_unblock_user', 'security_report'
]));

const PARFUM_ACTIONS = Object.freeze(new Set([
  'public_products', 'products_public', 'catalog_products', 'product_catalog', 'public_catalog',
  'parfum_products', 'perfume_products', 'parfum_catalog', 'katalog_parfum', 'katalog_produk', 'lihat_produk'
]));

const PESANAN_ACTIONS = Object.freeze(new Set([
  'domain_checkout', 'domain_orders', 'checkout_order', 'create_payment', 'midtrans_health',
  'midtrans_webhook', 'my_orders', 'customer_orders', 'pesanan_saya', 'my_invoices',
  'customer_invoices', 'invoices', 'invoice_saya', 'my_bills', 'my_shipments',
  'customer_shipments', 'pengiriman_saya'
]));

const WWW_ACTIONS = Object.freeze(new Set(['hostinger_check', 'domain_check']));

function cleanHostname(value) {
  const host = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host || host.length > 253 || /[\s\x00-\x1f\x7f\\/@:#]/.test(host)) return '';
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host)) return '';
  return host;
}

function baseDomainFromHostname(hostname) {
  const host = cleanHostname(hostname);
  if (!host) return '';
  const labels = host.split('.');
  if (labels.length > 2 && EDGE_LABELS.has(labels[0])) labels.shift();
  return cleanHostname(labels.join('.'));
}

function requestBaseDomain(request) {
  try { return baseDomainFromHostname(new URL(request.url).hostname); } catch (_) { return ''; }
}

function exactSource(request, baseDomain) {
  for (const name of ['referer', 'origin']) {
    const raw = String(request.headers.get(name) || '').trim();
    if (!raw || raw.length > 2048) continue;
    try {
      const url = new URL(raw);
      if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash) continue;
      const host = cleanHostname(url.hostname);
      if (!host || (host !== baseDomain && !host.endsWith('.' + baseDomain))) continue;
      const label = host === baseDomain ? '' : host.slice(0, -(baseDomain.length + 1));
      if (label.includes('.')) continue;
      return Object.freeze({ host, label, pathname: url.pathname || '/' });
    } catch (_) {}
  }
  return Object.freeze({ host: '', label: '', pathname: '' });
}

function normalizedAction(url) {
  const raw = String(url.searchParams.get('action') || '').trim().toLowerCase();
  return ACTION_ALIASES[raw] || raw;
}

function roleFromDirectTarget(url, baseDomain) {
  const host = cleanHostname(url.hostname);
  if (!host || !baseDomain || host === baseDomain) return '';
  if (!host.endsWith('.' + baseDomain)) return '';
  const label = host.slice(0, -(baseDomain.length + 1));
  if (!label || label.includes('.') || label === 'api' || label === 'secure' || label === 'recovery') return '';
  return DIRECT_ROLE_BY_LABEL[label] || '';
}

function roleForCentralRequest(request, url, baseDomain) {
  const direct = roleFromDirectTarget(url, baseDomain);
  if (direct) return direct;

  const source = exactSource(request, baseDomain);
  const action = normalizedAction(url);
  const fromPanel = source.label === 'panel' || source.label === 'dashboard';
  const fromOrder = source.label === 'order' || source.label === 'pesanan';
  const fromSecurity = source.label === 'security';
  const fromParfum = source.label === 'shop' || source.label === 'parfum' || (source.label === '' && source.pathname === '/parfum.html');

  if (action === 'domain_health') {
    if (fromPanel) return 'dashboard';
    if (fromOrder) return 'pesanan';
    if (fromSecurity) return 'security';
    if (fromParfum) return 'parfum';
    return 'auth';
  }
  if (action === 'domain_dashboard_me') return fromPanel ? 'dashboard' : 'auth';
  if (action === 'checkout_order') return fromParfum ? 'auth' : 'pesanan';
  if (action === 'my_orders' || action === 'create_payment') {
    if (fromOrder) return 'auth';
    if (fromPanel) return 'dashboard';
    return 'pesanan';
  }
  if (DASHBOARD_ACTIONS.has(action)) return fromOrder && PESANAN_ACTIONS.has(action) ? 'pesanan' : 'dashboard';
  if (SECURITY_ACTIONS.has(action)) return fromSecurity ? 'security' : (AUTH_ACTIONS.has(action) ? 'auth' : 'security');
  if (PARFUM_ACTIONS.has(action)) return 'parfum';
  if (PESANAN_ACTIONS.has(action)) return 'pesanan';
  if (WWW_ACTIONS.has(action)) return 'www';
  if (AUTH_ACTIONS.has(action)) return 'auth';
  return 'auth';
}

function containerEnvironment(env, baseDomain, role, recovery) {
  const out = Object.create(null);
  for (const [name, value] of Object.entries(env || {})) {
    if (typeof value !== 'string') continue;
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue;
    if (/^VERCEL(?:_|$)/.test(name)) continue;
    if (!recovery && RECOVERY_PRIVATE_ENV_NAMES.has(name)) continue;
    out[name] = value;
  }
  out.NODE_ENV = 'production';
  out.DIRAC_TRUSTED_PROXY_MODE = 'standard';
  out.DIRAC_TRUSTED_PROXY_IPS = '127.0.0.1,::1';
  out.DIRAC_BASE_DOMAIN = baseDomain;
  out.DIRAC_APP_ROLE = role;
  out.DIRAC_S2S_SERVER_ID = role;

  if (recovery) {
    delete out.DIRAC_RECOVERY_WORKER_URL;
    delete out.DIRAC_RECOVERY_WORKER_EXPECTED_HOST;
    delete out.DIRAC_RECOVERY_WORKER_CALLER;
    delete out.DIRAC_RECOVERY_HPKE_ALLOWED_CALLER;

    const server1Origin = 'https://auth.' + baseDomain;
    out.DIRAC_CENTRAL_DEPLOYMENT_ROLE = 'vercel2';
    out.DIRAC_CENTRAL_VERCEL2_ACTIONS_ENABLED = 'true';
    out.DIRAC_CENTRAL_VERCEL2_ONLY_ACTIONS = [
      'dirac_recovery_worker_generate',
      'lost_passkey_recovery_link_open',
      'customer_security_recovery_hpke_verify'
    ].join(',');
    out.DIRAC_RECOVERY_WORKER_ALLOWED_CALLER = 'auth';
    out.DIRAC_RECOVERY_SERVER1_ORIGIN = server1Origin;
    out.DIRAC_RECOVERY_SERVER1_URL = server1Origin + '/api/health';
    out.DIRAC_RECOVERY_SERVER1_SERVER_ID = 'auth';
  } else {
    out.DIRAC_RECOVERY_WORKER_CALLER = 'auth';
  }

  return out;
}

function edgeRequest(request) {
  const url = new URL(request.url);
  const headers = new Headers(request.headers);

  for (const name of [
    'forwarded',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-real-ip',
    'x-client-ip',
    'x-vercel-forwarded-for',
    'x-vercel-ip-city',
    'x-vercel-ip-country-region',
    'x-vercel-ip-country'
  ]) headers.delete(name);

  const connectingIp = String(request.headers.get('cf-connecting-ip') || '').trim();
  if (connectingIp && connectingIp.length <= 64 && /^[0-9a-f:.]+$/i.test(connectingIp)) {
    headers.set('x-forwarded-for', connectingIp);
  }
  headers.set('x-forwarded-host', url.host);
  headers.set('x-forwarded-proto', 'https');

  return new Request(request, { headers, redirect: 'manual' });
}

class DiracContainerBase extends Container {
  defaultPort = 8080;
  requiredPorts = [8080];
  sleepAfter = '2h';
  pingEndpoint = 'localhost/__dirac_cf_ready';
  enableInternet = true;
}

export class DiracBackendContainer extends DiracContainerBase {
  entrypoint = ['node', 'cloudflare-server.js', 'main'];
}

export class DiracRecoveryContainer extends DiracContainerBase {
  entrypoint = ['node', 'cloudflare-server.js', 'recovery'];
}

function json(status, code) {
  return new Response(JSON.stringify({ ok: false, code }), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff'
    }
  });
}

async function startedContainer(binding, instanceName, envVars) {
  const container = getContainer(binding, instanceName);
  await container.startAndWaitForPorts({ startOptions: { envVars } });
  return container;
}


function withStaticAssetCsp(response) {
  const headers = new Headers(response.headers);
  headers.set('Content-Security-Policy', STATIC_ASSET_CSP);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

async function mainFetch(request, env) {
  const url = new URL(request.url);
  if (url.pathname === '/api/alamat-indonesia.js') {
    if (request.method !== 'GET' && request.method !== 'HEAD') return json(405, 'DIRAC_ASSET_METHOD_NOT_ALLOWED');
    if (!env.ASSETS || typeof env.ASSETS.fetch !== 'function') return json(404, 'DIRAC_ASSET_NOT_FOUND');
    const assetUrl = new URL(request.url);
    assetUrl.pathname = '/alamat-indonesia.js';
    assetUrl.search = '';
    return withStaticAssetCsp(await env.ASSETS.fetch(new Request(assetUrl.toString(), request)));
  }
  const allowed = new Set(['/api/health', '/api/ptdin', '/api/keamanan', '/api/support']);
  if (url.pathname.startsWith('/api/')) {
    if (!allowed.has(url.pathname)) return json(404, 'DIRAC_API_ROUTE_NOT_FOUND');
    const baseDomain = requestBaseDomain(request);
    if (!baseDomain) return json(400, 'DIRAC_BASE_DOMAIN_INVALID');
    let role = url.pathname === '/api/support' ? 'auth' : roleForCentralRequest(request, url, baseDomain);
    if (url.pathname === '/api/keamanan' && normalizedAction(url) !== 'domain_dashboard_me') role = 'security';
    try {
      const envVars = containerEnvironment(env, baseDomain, role, false);
      const container = await startedContainer(env.DIRAC_BACKEND, role + ':' + baseDomain, envVars);
      return await container.fetch(edgeRequest(request));
    } catch (_) {
      return json(503, 'DIRAC_BACKEND_CONTAINER_UNAVAILABLE');
    }
  }
  if (env.ASSETS && typeof env.ASSETS.fetch === 'function') return withStaticAssetCsp(await env.ASSETS.fetch(request));
  return json(404, 'DIRAC_ROUTE_NOT_FOUND');
}

async function recoveryFetch(request, env) {
  const url = new URL(request.url);
  if (url.pathname !== '/api/health') return json(404, 'DIRAC_RECOVERY_ROUTE_NOT_FOUND');
  const baseDomain = requestBaseDomain(request);
  if (!baseDomain) return json(400, 'DIRAC_BASE_DOMAIN_INVALID');
  try {
    const envVars = containerEnvironment(env, baseDomain, 'recovery', true);
    const container = await startedContainer(env.DIRAC_RECOVERY, 'recovery:' + baseDomain, envVars);
    return await container.fetch(edgeRequest(request));
  } catch (_) {
    return json(503, 'DIRAC_RECOVERY_CONTAINER_UNAVAILABLE');
  }
}

export default {
  async fetch(request, env) {
    if (env && env.DIRAC_RECOVERY) return recoveryFetch(request, env);
    if (env && env.DIRAC_BACKEND) return mainFetch(request, env);
    return json(503, 'DIRAC_CLOUDFLARE_BINDING_MISSING');
  }
};

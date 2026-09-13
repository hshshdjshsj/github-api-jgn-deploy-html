import { Container, getContainer } from '@cloudflare/containers';

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

async function mainFetch(request, env) {
  const url = new URL(request.url);
  if (url.pathname === '/api/alamat-indonesia.js') {
    if (request.method !== 'GET' && request.method !== 'HEAD') return json(405, 'DIRAC_ASSET_METHOD_NOT_ALLOWED');
    if (!env.ASSETS || typeof env.ASSETS.fetch !== 'function') return json(404, 'DIRAC_ASSET_NOT_FOUND');
    const assetUrl = new URL(request.url);
    assetUrl.pathname = '/alamat-indonesia.js';
    assetUrl.search = '';
    return env.ASSETS.fetch(new Request(assetUrl.toString(), request));
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
  if (env.ASSETS && typeof env.ASSETS.fetch === 'function') return env.ASSETS.fetch(request);
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

import crypto from 'node:crypto';
import https from 'node:https';
import { promises as dns } from 'node:dns';
import net from 'node:net';

const MAX_BODY_BYTES = 16 * 1024;
const MAX_MESSAGE_CHARS = 2000;
const MAX_MESSAGE_BYTES = 8 * 1024;
const MAX_CONVERSATION_MESSAGES = 1000;
const ADMIN_AUTH_RECHECK_MS = 5 * 60 * 1000;
const CUSTOMER_COOKIE = '__Host-dirac_support_guest';
const ADMIN_COOKIE = '__Host-dirac_support_admin';
const MFA_COOKIE = '__Host-dirac_support_mfa';
const CSRF_COOKIE = '__Host-dirac_support_csrf_seed';
const ACTIVE_CHAT_STATES = ['new', 'queued', 'active', 'waiting_customer', 'waiting_admin'];
const SERVICE_STATES = new Set(['operational', 'degraded', 'partial_outage', 'major_outage', 'maintenance', 'unknown']);
const INCIDENT_STAGES = new Set(['detected', 'investigating', 'identified', 'fixing', 'monitoring', 'resolved']);
const PUBLIC_GET_ACTIONS = new Set(['status_bootstrap', 'chat_public_config', 'admin_public_config']);
const CUSTOMER_GET_ACTIONS = new Set(['chat_bootstrap']);
const ADMIN_GET_ACTIONS = new Set(['admin_bootstrap', 'admin_queue', 'admin_thread', 'admin_status_snapshot']);
const MUTATION_ACTIONS = new Set([
  'chat_start', 'chat_send', 'chat_close', 'customer_access_refresh',
  'admin_login', 'admin_mfa_verify', 'admin_logout', 'admin_send',
  'admin_conversation_update', 'admin_component_update', 'admin_incident_create',
  'admin_incident_advance', 'admin_maintenance_create', 'admin_monitor_config_update'
]);

class PublicError extends Error {
  constructor(status, code, message, details) {
    super(message || code);
    this.status = Number(status || 500);
    this.code = String(code || 'REQUEST_FAILED');
    this.details = details || null;
  }
}

function env(name) { return String(process.env[name] || '').trim(); }
function envTrue(name, fallback) {
  const value = env(name);
  if (!value) return Boolean(fallback);
  return /^(1|true|yes|on|enabled)$/i.test(value);
}
function isProduction() { return env('NODE_ENV') === 'production'; }
function nowIso() { return new Date().toISOString(); }
function uuid() { return crypto.randomUUID(); }
function b64u(value) { return Buffer.from(value).toString('base64url'); }
function hash(value) { return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex'); }
function hmac(secret, value, encoding = 'base64url') { return crypto.createHmac('sha256', secret).update(String(value || ''), 'utf8').digest(encoding); }
function timingEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function config() {
  const supabaseUrl = env('DIRAC_SUPPORT_SUPABASE_URL').replace(/\/+$/, '');
  const publishableKey = env('DIRAC_SUPPORT_SUPABASE_PUBLISHABLE_KEY') || env('DIRAC_SUPPORT_SUPABASE_ANON_KEY');
  const secretKey = env('DIRAC_SUPPORT_SUPABASE_SECRET_KEY') || env('DIRAC_SUPPORT_SUPABASE_SERVICE_ROLE_KEY');
  const cookieSecret = env('DIRAC_SUPPORT_COOKIE_SECRET');
  const csrfSecret = env('DIRAC_SUPPORT_CSRF_SECRET');
  const ipSecret = env('DIRAC_SUPPORT_IP_HMAC_SECRET');
  const mfaEnrollmentSecret = env('DIRAC_SUPPORT_MFA_ENROLLMENT_SECRET');
  const turnstileSiteKey = env('DIRAC_SUPPORT_TURNSTILE_SITE_KEY'); const turnstileSecretKey = env('DIRAC_SUPPORT_TURNSTILE_SECRET_KEY');
  const turnstileRequired = envTrue('DIRAC_SUPPORT_REQUIRE_TURNSTILE', isProduction());
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(supabaseUrl)) throw new PublicError(503, 'SUPPORT_CONFIG_INVALID', 'Konfigurasi database support belum valid.');
  const publishableRole = decodeJwt(publishableKey).role; const secretRole = decodeJwt(secretKey).role;
  const publishableValid = /^sb_publishable_[A-Za-z0-9_-]{10,}$/.test(publishableKey) || publishableRole === 'anon';
  const secretValid = /^sb_secret_[A-Za-z0-9_-]{10,}$/.test(secretKey) || secretRole === 'service_role';
  if (!publishableValid || !secretValid || timingEqual(publishableKey, secretKey)) throw new PublicError(503, 'SUPPORT_KEYS_INVALID', 'Kelas kunci Supabase support tidak valid atau tertukar.');
  const securitySecrets = [cookieSecret, csrfSecret, ipSecret, mfaEnrollmentSecret];
  if (isProduction() && (securitySecrets.some((value) => Buffer.byteLength(value, 'utf8') < 32) || new Set(securitySecrets).size !== securitySecrets.length)) {
    throw new PublicError(503, 'SUPPORT_SECRETS_WEAK', 'Secret keamanan support wajib kuat dan berbeda satu sama lain.');
  }
  if (turnstileRequired && (!turnstileSiteKey || !turnstileSecretKey)) throw new PublicError(503, 'TURNSTILE_CONFIG_MISSING', 'Verifikasi anti-bot support belum dikonfigurasi lengkap.');
  return {
    supabaseUrl,
    publishableKey,
    secretKey,
    cookieSecret: cookieSecret || 'development-cookie-secret-change-before-production',
    csrfSecret: csrfSecret || 'development-csrf-secret-change-before-production',
    ipSecret: ipSecret || 'development-ip-secret-change-before-production',
    mfaEnrollmentSecret: mfaEnrollmentSecret || 'development-mfa-enrollment-secret-change-before-production',
    turnstileSiteKey,
    turnstileSecretKey,
    turnstileRequired,
    // Realtime admin authorization is deliberately AAL2-only in SQL, so the
    // HTTP capability must never be weaker than the channel capability.
    adminMfaRequired: true
  };
}

function allowedOrigins() {
  const values = env('DIRAC_SUPPORT_ALLOWED_ORIGINS').split(',').map((value) => value.trim()).filter(Boolean);
  if (!isProduction()) values.push('http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5173', 'http://127.0.0.1:5173');
  return new Set(values.map((value) => {
    try { return new URL(value).origin; } catch (_) { return ''; }
  }).filter(Boolean));
}

function requestOrigin(req) { return String(req.headers && req.headers.origin || '').trim(); }
function originAllowed(req) {
  const origin = requestOrigin(req);
  if (!origin) return false;
  return allowedOrigins().has(origin);
}

function setHeader(res, name, value) {
  if (!res.headersSent) res.setHeader(name, value);
}

function appendCookie(res, value) {
  const current = res.getHeader('Set-Cookie');
  const next = Array.isArray(current) ? current.concat(value) : current ? [current, value] : [value];
  res.setHeader('Set-Cookie', next);
}

function securityHeaders(req, res, action) {
  const origin = requestOrigin(req);
  if (origin && allowedOrigins().has(origin)) {
    setHeader(res, 'Access-Control-Allow-Origin', origin);
    setHeader(res, 'Access-Control-Allow-Credentials', 'true');
  }
  setHeader(res, 'Vary', 'Origin');
  setHeader(res, 'Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  setHeader(res, 'Access-Control-Allow-Headers', 'Content-Type, Accept, X-Dirac-CSRF, Idempotency-Key, If-None-Match');
  setHeader(res, 'Access-Control-Expose-Headers', 'ETag, Retry-After');
  setHeader(res, 'Access-Control-Max-Age', '600');
  setHeader(res, 'X-Content-Type-Options', 'nosniff');
  setHeader(res, 'X-Frame-Options', 'DENY');
  setHeader(res, 'Referrer-Policy', 'no-referrer');
  setHeader(res, 'Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()');
  setHeader(res, 'Cross-Origin-Opener-Policy', 'same-origin');
  // The supported split deployment keeps the static frontend and this API on
  // HTTPS sibling subdomains. CORS still restricts access to the exact origin
  // allowlist; CORP additionally prevents use from unrelated sites.
  setHeader(res, 'Cross-Origin-Resource-Policy', 'same-site');
  if (isProduction()) setHeader(res, 'Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  if (action !== 'status_bootstrap') setHeader(res, 'Cache-Control', 'no-store, private, max-age=0');
}

function json(res, status, payload) {
  if (res.headersSent) return;
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

function parseCookies(req) {
  const out = Object.create(null);
  String(req.headers && req.headers.cookie || '').split(';').forEach((part) => {
    const index = part.indexOf('=');
    if (index < 1) return;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key && !Object.prototype.hasOwnProperty.call(out, key)) out[key] = value;
  });
  return out;
}

function runtimeCookieName(productionName) {
  return isProduction() ? productionName : productionName.replace(/^__Host-/, '');
}

function cookieString(name, value, options) {
  const parts = [runtimeCookieName(name) + '=' + value, 'Path=/', 'HttpOnly', 'SameSite=' + (options.sameSite || 'Strict'), 'Max-Age=' + Math.max(0, Math.floor(options.maxAge || 0)), 'Priority=High'];
  if (isProduction()) parts.push('Secure');
  return parts.join('; ');
}

function clearCookie(res, name, sameSite) { appendCookie(res, cookieString(name, '', { maxAge: 0, sameSite: sameSite || 'Strict' })); }

function sessionKey() { return crypto.createHash('sha256').update(config().cookieSecret, 'utf8').digest(); }
function seal(name, payload) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey(), nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(name, 'utf8'));
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return b64u(Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]));
}
function unseal(name, value) {
  try {
    const packed = Buffer.from(String(value || ''), 'base64url');
    if (packed.length < 29 || packed.length > 7000) return null;
    const nonce = packed.subarray(0, 12); const tag = packed.subarray(12, 28); const ciphertext = packed.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey(), nonce, { authTagLength: 16 });
    decipher.setAAD(Buffer.from(name, 'utf8')); decipher.setAuthTag(tag);
    const payload = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
    if (!payload || payload.v !== 1 || Number(payload.exp || 0) <= Date.now()) return null;
    return payload;
  } catch (_) { return null; }
}

function readSession(req, name) {
  const cookies = parseCookies(req);
  return unseal(name, cookies[runtimeCookieName(name)]);
}
function writeSession(res, name, payload, maxAge, sameSite) {
  appendCookie(res, cookieString(name, seal(name, payload), { maxAge, sameSite }));
}

function csrfBundle(req, res) {
  const cookies = parseCookies(req); const cookieName = runtimeCookieName(CSRF_COOKIE);
  let seed = String(cookies[cookieName] || '');
  if (!/^[A-Za-z0-9_-]{32,96}$/.test(seed)) {
    seed = b64u(crypto.randomBytes(32));
    appendCookie(res, cookieString(CSRF_COOKIE, seed, { maxAge: 8 * 60 * 60, sameSite: 'Strict' }));
  }
  const exp = Date.now() + 2 * 60 * 60 * 1000;
  // Origin is enforced independently on every mutation. Browsers commonly
  // omit Origin on the GET that issues this token and include it on POST.
  return String(exp) + '.' + hmac(config().csrfSecret, seed + '|' + exp);
}

function verifyCsrf(req) {
  if (!originAllowed(req)) throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin permintaan tidak diizinkan.');
  const fetchSite = String(req.headers && req.headers['sec-fetch-site'] || '').toLowerCase();
  if (fetchSite && !['same-origin', 'same-site', 'none'].includes(fetchSite)) throw new PublicError(403, 'FETCH_SITE_REJECTED', 'Konteks browser tidak diizinkan.');
  const token = String(req.headers && req.headers['x-dirac-csrf'] || '');
  const match = /^(\d{13})\.([A-Za-z0-9_-]{43})$/.exec(token);
  if (!match || Number(match[1]) <= Date.now()) throw new PublicError(403, 'CSRF_INVALID', 'Token keamanan halaman tidak valid atau kedaluwarsa.');
  const cookies = parseCookies(req); const seed = String(cookies[runtimeCookieName(CSRF_COOKIE)] || '');
  const expected = hmac(config().csrfSecret, seed + '|' + match[1]);
  if (!seed || !timingEqual(expected, match[2])) throw new PublicError(403, 'CSRF_INVALID', 'Token keamanan halaman tidak valid.');
}

function verifyAuthenticatedReadOrigin(req) {
  const origin = requestOrigin(req);
  const fetchSite = String(req.headers && req.headers['sec-fetch-site'] || '').toLowerCase();
  if (origin && !allowedOrigins().has(origin)) throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin permintaan tidak diizinkan.');
  if (fetchSite && !['same-origin', 'same-site', 'none'].includes(fetchSite)) throw new PublicError(403, 'FETCH_SITE_REJECTED', 'Pembacaan sesi hanya diizinkan dari situs aplikasi yang sama.');
  if (fetchSite === 'same-site' && !origin) throw new PublicError(403, 'REQUEST_CONTEXT_REQUIRED', 'Origin wajib tersedia untuk pembacaan sesi lintas subdomain.');
  if (!origin && !fetchSite) throw new PublicError(403, 'REQUEST_CONTEXT_REQUIRED', 'Konteks origin permintaan tidak tersedia.');
}

async function readJson(req) {
  const type = String(req.headers && req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') throw new PublicError(415, 'CONTENT_TYPE_INVALID', 'Content-Type wajib application/json.');
  const declared = Number(req.headers && req.headers['content-length'] || 0);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw new PublicError(413, 'BODY_TOO_LARGE', 'Ukuran request melebihi batas.');
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    const raw = JSON.stringify(req.body);
    if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) throw new PublicError(413, 'BODY_TOO_LARGE', 'Ukuran request melebihi batas.');
    return req.body;
  }
  if (typeof req.body === 'string' || Buffer.isBuffer(req.body)) {
    const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : req.body;
    if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) throw new PublicError(413, 'BODY_TOO_LARGE', 'Ukuran request melebihi batas.');
    try { return JSON.parse(raw || '{}'); } catch (_) { throw new PublicError(400, 'JSON_INVALID', 'JSON request tidak valid.'); }
  }
  const chunks = []; let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw new PublicError(413, 'BODY_TOO_LARGE', 'Ukuran request melebihi batas.');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (_) { throw new PublicError(400, 'JSON_INVALID', 'JSON request tidak valid.'); }
}

function exactKeys(body, allowed) {
  if (!body || Object.getPrototypeOf(body) !== Object.prototype) throw new PublicError(400, 'BODY_INVALID', 'Bentuk request tidak valid.');
  const unknown = Object.keys(body).filter((key) => !allowed.includes(key));
  if (unknown.length) throw new PublicError(400, 'FIELDS_UNKNOWN', 'Request memuat field yang tidak diizinkan.');
}

function text(value, min, max, label) {
  const normalized = String(value || '').normalize('NFC').trim();
  if (normalized.length < min || normalized.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(normalized)) throw new PublicError(400, 'TEXT_INVALID', (label || 'Teks') + ' tidak valid.');
  return normalized;
}

function messageText(value) {
  const normalized = text(value, 1, MAX_MESSAGE_CHARS, 'Pesan');
  if (Buffer.byteLength(normalized, 'utf8') > MAX_MESSAGE_BYTES) throw new PublicError(400, 'MESSAGE_TOO_LARGE', 'Ukuran pesan melebihi batas 8 KB.');
  return normalized;
}

function email(value, required) {
  const clean = String(value || '').trim().toLowerCase();
  if (!clean && !required) return '';
  if (clean.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) throw new PublicError(400, 'EMAIL_INVALID', 'Alamat email tidak valid.');
  return clean;
}

function id(value, label) {
  const clean = String(value || '').trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(clean)) throw new PublicError(400, 'ID_INVALID', (label || 'ID') + ' tidak valid.');
  return clean;
}

function idempotencyKey(req, fallback, label) {
  const header = String(req.headers && req.headers['idempotency-key'] || '').trim();
  const candidate = header || fallback;
  return id(candidate, label || 'Idempotency key');
}

function queryValue(req, name) {
  const direct = req.query && req.query[name];
  if (Array.isArray(direct)) return String(direct[0] || '');
  if (direct !== undefined) return String(direct || '');
  try { return new URL(req.url, 'https://local.invalid').searchParams.get(name) || ''; } catch (_) { return ''; }
}

function clientIp(req) {
  // Vercel creates x-vercel-forwarded-for at its trusted edge. Never fall
  // back to the client-spoofable x-forwarded-for header in production.
  const platform = String(req.headers && req.headers['x-vercel-forwarded-for'] || '').split(',')[0].trim();
  const remote = String(req.socket && req.socket.remoteAddress || '').trim();
  const candidate = (isProduction() ? platform : platform || remote).replace(/^::ffff:/, '');
  return net.isIP(candidate) ? candidate : 'untrusted-client-ip';
}
function clientKey(req, suffix) { return hmac(config().ipSecret, clientIp(req) + '|' + String(suffix || ''), 'hex'); }

function verifyQueryShape(req, action) {
  const allowedByAction = {
    chat_bootstrap: ['after_sequence'],
    admin_queue: ['filter', 'limit'],
    admin_thread: ['conversation_id', 'after_sequence', 'limit']
  };
  const allowed = new Set(['action'].concat(allowedByAction[action] || []));
  const seen = new Set();
  try {
    const parsed = new URL(req.url || '/', 'https://local.invalid');
    parsed.searchParams.forEach((_value, name) => {
      if (!allowed.has(name)) throw new PublicError(400, 'QUERY_FIELD_UNKNOWN', 'Parameter URL tidak diizinkan.');
      if (seen.has(name)) throw new PublicError(400, 'QUERY_FIELD_DUPLICATE', 'Parameter URL tidak boleh berulang.');
      seen.add(name);
    });
    const canonicalSearch = parsed.searchParams.size ? '?' + parsed.searchParams.toString() : '';
    if (parsed.search !== canonicalSearch) throw new PublicError(400, 'QUERY_NON_CANONICAL', 'Format parameter URL tidak kanonis.');
  } catch (_) {
    if (_ instanceof PublicError) throw _;
    throw new PublicError(400, 'QUERY_INVALID', 'Parameter URL tidak valid.');
  }
  for (const name of Object.keys(req.query && typeof req.query === 'object' ? req.query : {})) {
    if (!allowed.has(name)) throw new PublicError(400, 'QUERY_FIELD_UNKNOWN', 'Parameter URL tidak diizinkan.');
    if (Array.isArray(req.query[name]) && req.query[name].length > 1) throw new PublicError(400, 'QUERY_FIELD_DUPLICATE', 'Parameter URL tidak boleh berulang.');
  }
}

async function fetchJson(url, options, timeoutMs) {
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs || 8000);
  try {
    const response = await fetch(url, Object.assign({}, options, { signal: controller.signal, redirect: 'error' }));
    const maxBytes = 2 * 1024 * 1024;
    const declared = Number(response.headers.get('content-length') || 0);
    if (Number.isFinite(declared) && declared > maxBytes) {
      if (response.body) await response.body.cancel().catch(() => {});
      throw new PublicError(502, 'UPSTREAM_RESPONSE_TOO_LARGE', 'Respons upstream terlalu besar.');
    }
    const chunks = []; let total = 0;
    if (response.body && typeof response.body.getReader === 'function') {
      const reader = response.body.getReader();
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        const chunk = Buffer.from(part.value);
        total += chunk.length;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          throw new PublicError(502, 'UPSTREAM_RESPONSE_TOO_LARGE', 'Respons upstream terlalu besar.');
        }
        chunks.push(chunk);
      }
    }
    const raw = Buffer.concat(chunks, total).toString('utf8');
    let data = null; try { data = raw ? JSON.parse(raw) : null; } catch (_) { data = raw; }
    return { ok: response.ok, status: response.status, data, headers: response.headers };
  } catch (error) {
    if (error instanceof PublicError) throw error;
    throw new PublicError(502, error && error.name === 'AbortError' ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_UNAVAILABLE', 'Layanan data support belum dapat dihubungi.');
  } finally { clearTimeout(timer); }
}

async function supabase(path, options) {
  const cfg = config(); const settings = options || {}; const key = settings.token ? cfg.publishableKey : cfg.secretKey;
  const headers = Object.assign({ apikey: key, Accept: 'application/json' }, settings.headers || {});
  // Modern sb_secret_/sb_publishable_ keys belong only in apikey. JWT bearer
  // auth is reserved for a user access token or a legacy service_role JWT.
  if (settings.token) headers.Authorization = 'Bearer ' + settings.token;
  else if (decodeJwt(cfg.secretKey).role === 'service_role') headers.Authorization = 'Bearer ' + cfg.secretKey;
  if (settings.body !== undefined) headers['Content-Type'] = 'application/json';
  const result = await fetchJson(cfg.supabaseUrl + path, { method: settings.method || 'GET', headers, body: settings.body === undefined ? undefined : JSON.stringify(settings.body) }, settings.timeoutMs || 8000);
  if (!result.ok && !settings.allowError) {
    const code = result.data && typeof result.data === 'object' && (result.data.code || result.data.error_code);
    throw new PublicError(result.status >= 400 && result.status < 600 ? result.status : 502, String(code || 'DATABASE_REQUEST_FAILED').slice(0, 90), 'Operasi database support belum dapat diproses.');
  }
  return result;
}

async function rpc(name, body) {
  const result = await supabase('/rest/v1/rpc/' + encodeURIComponent(name), { method: 'POST', body, headers: { Prefer: 'return=representation' } });
  return result.data;
}

async function auth(path, options) {
  const cfg = config(); const settings = options || {};
  const headers = { apikey: cfg.publishableKey, Accept: 'application/json', 'Content-Type': 'application/json' };
  if (settings.token) headers.Authorization = 'Bearer ' + settings.token;
  return fetchJson(cfg.supabaseUrl + '/auth/v1' + path, { method: settings.method || 'POST', headers, body: JSON.stringify(settings.body || {}) }, 9000);
}

function decodeJwt(token) {
  try { return JSON.parse(Buffer.from(String(token || '').split('.')[1], 'base64url').toString('utf8')); } catch (_) { return {}; }
}

async function refreshAuth(refreshToken) {
  const result = await auth('/token?grant_type=refresh_token', { body: { refresh_token: refreshToken } });
  if (!result.ok || !result.data || !result.data.access_token || !result.data.refresh_token || !result.data.user) throw new PublicError(401, 'SESSION_REFRESH_FAILED', 'Sesi sudah berakhir. Silakan masuk kembali.');
  return result.data;
}

async function refreshCustomerAuth(res, session) {
  try {
    const refreshed = await refreshAuth(session && session.refreshToken);
    if (!refreshed.user || String(refreshed.user.id || '') !== String(session && session.uid || '')) throw new PublicError(401, 'CUSTOMER_SESSION_MISMATCH', 'Sesi chat tidak cocok.');
    return refreshed;
  } catch (error) {
    clearCookie(res, CUSTOMER_COOKIE, 'Lax');
    throw error;
  }
}

async function staffByUser(userId) {
  const result = await supabase('/rest/v1/support_staff?select=user_id,email,display_name,role,is_active,mfa_required,session_version&user_id=eq.' + encodeURIComponent(userId) + '&limit=2', {});
  const rows = Array.isArray(result.data) ? result.data : [];
  if (rows.length !== 1 || rows[0].is_active !== true) throw new PublicError(403, 'STAFF_NOT_ALLOWED', 'Akun ini tidak memiliki akses staff aktif.');
  return rows[0];
}

function publicAdmin(staff) {
  return { id: staff.user_id, userId: staff.user_id, email: staff.email, displayName: staff.display_name || staff.email, role: staff.role };
}

async function requireAdmin(req, res, forceAuthCheck) {
  let session = readSession(req, ADMIN_COOKIE);
  if (!session || session.kind !== 'admin' || !session.uid || !session.refreshToken || !session.sessionId) throw new PublicError(401, 'ADMIN_SESSION_REQUIRED', 'Sesi admin tidak ditemukan atau sudah berakhir.');
  const staff = await staffByUser(session.uid);
  if (!Number.isSafeInteger(Number(session.sessionVersion)) || Number(session.sessionVersion) !== Number(staff.session_version)) throw new PublicError(401, 'ADMIN_SESSION_REVOKED', 'Sesi admin telah dicabut. Silakan masuk kembali.');
  const mustMfa = config().adminMfaRequired || staff.mfa_required === true;
  if (mustMfa && (session.aal !== 'aal2' || Number(session.mfaAt || 0) < Date.now() - 12 * 60 * 60 * 1000)) throw new PublicError(401, 'ADMIN_MFA_EXPIRED', 'Verifikasi MFA admin sudah berakhir. Silakan masuk kembali.');
  let authSession = null;
  if (forceAuthCheck || Number(session.authCheckedAt || 0) < Date.now() - ADMIN_AUTH_RECHECK_MS) {
    authSession = await refreshAuth(session.refreshToken);
    const claims = decodeJwt(authSession.access_token);
    if (String(authSession.user.id || '') !== String(session.uid)
       || String(claims.sub || '') !== String(session.uid)
       || String(claims.session_id || '') !== String(session.sessionId)
       || claims.aal !== 'aal2') {
      throw new PublicError(401, 'ADMIN_AUTH_SESSION_INVALID', 'Sesi Supabase Auth admin tidak lagi valid. Silakan masuk kembali.');
    }
    session = Object.assign({}, session, {
      refreshToken: authSession.refresh_token,
      aal: 'aal2',
      authCheckedAt: Date.now()
    });
    const remainingSeconds = Math.max(1, Math.ceil((Number(session.exp) - Date.now()) / 1000));
    writeSession(res, ADMIN_COOKIE, session, Math.min(12 * 60 * 60, remainingSeconds), 'Strict');
  }
  return { session, staff, authSession };
}

function requireStaffRole(staff, allowed, operation) {
  if (!staff || !allowed.includes(String(staff.role || ''))) throw new PublicError(403, 'STAFF_CAPABILITY_REQUIRED', 'Peran staff tidak diizinkan untuk ' + (operation || 'operasi ini') + '.');
}

function canManageStatus(staff) { return Boolean(staff && ['lead', 'admin'].includes(String(staff.role || ''))); }

async function takeRateLimit(scope, key, limit, windowSeconds, blockSeconds) {
  const data = await rpc('support_take_rate_limit', { p_scope: scope, p_key_hash: key, p_limit: limit, p_window_seconds: windowSeconds, p_block_seconds: blockSeconds });
  const value = Array.isArray(data) ? data[0] : data;
  if (!value || value.allowed !== true) {
    const retry = Math.max(1, Number(value && (value.retry_after || value.retry_after_seconds) || blockSeconds || windowSeconds));
    const error = new PublicError(429, 'RATE_LIMITED', 'Terlalu banyak permintaan. Coba kembali beberapa saat lagi.'); error.retryAfter = retry; throw error;
  }
  return value;
}

async function rateLimit(req, scope, limit, windowSeconds, blockSeconds, suffix) {
  return takeRateLimit(scope, clientKey(req, scope + '|' + String(suffix || '')), limit, windowSeconds, blockSeconds);
}

async function accountRateLimit(scope, accountId, limit, windowSeconds, blockSeconds) {
  const key = hmac(config().ipSecret, scope + '|account|' + String(accountId || ''), 'hex');
  return takeRateLimit(scope, key, limit, windowSeconds, blockSeconds);
}

async function recordAdminAuth(req, actorUserId, action, emailValue, outcome, code) {
  try {
    const normalizedEmail = String(emailValue || '').trim().toLowerCase();
    const targetId = normalizedEmail ? hmac(config().ipSecret, 'admin-auth-email|' + normalizedEmail, 'hex') : null;
    await rpc('support_auth_audit', {
      p_actor_user_id: actorUserId || null,
      p_action: action,
      p_target_id: targetId,
      p_metadata: {
        outcome: String(outcome || '').slice(0, 32),
        code: String(code || '').slice(0, 80),
        ip_hash: clientKey(req, 'admin-auth-audit'),
        request_id: String(req && req.diracRequestId || '')
      }
    });
  } catch (error) {
    try { console.error('[dirac-auth-audit]', JSON.stringify({ requestId: String(req && req.diracRequestId || ''), action, code: String(error && (error.code || error.name) || 'AUDIT_FAILED').slice(0, 80) })); } catch (_) {}
  }
}

async function verifyTurnstile(req, token) {
  const cfg = config();
  if (!cfg.turnstileRequired) return true;
  if (!cfg.turnstileSiteKey || !cfg.turnstileSecretKey) throw new PublicError(503, 'TURNSTILE_CONFIG_MISSING', 'Verifikasi anti-bot belum dikonfigurasi.');
  const body = new URLSearchParams({ secret: cfg.turnstileSecretKey, response: String(token || ''), remoteip: clientIp(req) });
  const result = await fetchJson('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() }, 5000);
  if (!result.ok || !result.data || result.data.success !== true) throw new PublicError(400, 'TURNSTILE_FAILED', 'Verifikasi keamanan gagal. Silakan ulangi.');
  return true;
}

function statusRealtime(token) {
  const cfg = config(); return { url: cfg.supabaseUrl, key: cfg.publishableKey, token: token || '', topic: 'support:status:public' };
}
function chatRealtime(conversationId, accessToken) {
  const cfg = config(); return { url: cfg.supabaseUrl, key: cfg.publishableKey, token: accessToken, topic: 'support:chat:' + conversationId };
}
function adminRealtime(accessToken) {
  const cfg = config(); return { url: cfg.supabaseUrl, key: cfg.publishableKey, token: accessToken, topic: 'support:admin' };
}

function normalizeSnapshot(raw) {
  const data = raw && typeof raw === 'object' ? raw : {};
  const services = Array.isArray(data.services) ? data.services : [];
  return {
    generatedAt: data.generatedAt || data.generated_at || nowIso(),
    revision: String(data.revision || '0'),
    overall: data.overall || 'unknown',
    services,
    incidents: Array.isArray(data.incidents) ? data.incidents : [],
    maintenance: Array.isArray(data.maintenance) ? data.maintenance : [],
    incidentHistory: Array.isArray(data.incidentHistory) ? data.incidentHistory : Array.isArray(data.incident_history) ? data.incident_history : []
  };
}

async function statusSnapshot(admin) {
  return normalizeSnapshot(await rpc('support_status_snapshot', { p_admin: Boolean(admin) }));
}

async function actionStatusBootstrap(req, res) {
  const snapshot = await statusSnapshot(false); const etag = '"support-' + snapshot.revision.replace(/[^0-9A-Za-z_.:-]/g, '') + '"';
  setHeader(res, 'ETag', etag);
  setHeader(res, 'Cache-Control', 'public, max-age=0, must-revalidate');
  setHeader(res, 'Vercel-CDN-Cache-Control', 'public, max-age=5, stale-while-revalidate=30');
  if (String(req.headers && req.headers['if-none-match'] || '') === etag) { res.statusCode = 304; return res.end(); }
  return json(res, 200, Object.assign({ ok: true, code: 'STATUS_SNAPSHOT_OK', realtime: statusRealtime('') }, snapshot));
}

async function actionChatPublicConfig(req, res) {
  const session = readSession(req, CUSTOMER_COOKIE); const cfg = config();
  return json(res, 200, { ok: true, code: 'CHAT_CONFIG_OK', csrfToken: csrfBundle(req, res), hasSession: Boolean(session && session.kind === 'customer'), turnstileRequired: cfg.turnstileRequired, turnstileSiteKey: cfg.turnstileRequired ? cfg.turnstileSiteKey : '' });
}

async function actionAdminPublicConfig(req, res) {
  const cfg = config(); const session = readSession(req, ADMIN_COOKIE);
  return json(res, 200, { ok: true, code: 'ADMIN_CONFIG_OK', csrfToken: csrfBundle(req, res), hasSession: Boolean(session && session.kind === 'admin'), mfaRequired: cfg.adminMfaRequired, turnstileRequired: cfg.turnstileRequired, turnstileSiteKey: cfg.turnstileRequired ? cfg.turnstileSiteKey : '' });
}

async function findActiveConversation(userId) {
  const path = '/rest/v1/support_chat_sessions?select=id,public_code,customer_name,customer_email,category,subject,status,priority,assigned_to,created_at,updated_at,last_message_at,revision&customer_user_id=eq.' + encodeURIComponent(userId) + '&status=in.(' + ACTIVE_CHAT_STATES.join(',') + ')&expires_at=gt.' + encodeURIComponent(nowIso()) + '&order=last_message_at.desc.nullslast&limit=1';
  const result = await supabase(path, {}); return Array.isArray(result.data) && result.data[0] ? result.data[0] : null;
}

async function messagesForConversation(conversationId, after, limit) {
  const initial = !(after > 0);
  let path = '/rest/v1/support_chat_messages?select=id,conversation_id,sequence,sender_kind,body,created_at,redacted_at&conversation_id=eq.' + encodeURIComponent(conversationId) + '&order=sequence.' + (initial ? 'desc' : 'asc') + '&limit=' + Math.min(100, Math.max(1, limit || 50));
  if (after > 0) path += '&sequence=gt.' + encodeURIComponent(after);
  const result = await supabase(path, {});
  const rows = Array.isArray(result.data) ? result.data.slice() : [];
  if (initial) rows.reverse();
  return rows.map((row) => row && row.redacted_at ? Object.assign({}, row, {
    body: 'Pesan telah disunting oleh petugas sesuai kebijakan keamanan.'
  }) : row);
}

async function actionChatBootstrap(req, res) {
  const session = readSession(req, CUSTOMER_COOKIE);
  if (!session || session.kind !== 'customer' || !session.uid || !session.refreshToken) throw new PublicError(401, 'CUSTOMER_SESSION_REQUIRED', 'Sesi chat belum tersedia.');
  await accountRateLimit('chat_bootstrap_account', session.uid, 60, 60, 60);
  const refreshed = await refreshCustomerAuth(res, session);
  const next = Object.assign({}, session, { refreshToken: refreshed.refresh_token, exp: Date.now() + 180 * 24 * 60 * 60 * 1000 });
  writeSession(res, CUSTOMER_COOKIE, next, 180 * 24 * 60 * 60, 'Lax');
  const conversation = await findActiveConversation(session.uid);
  const after = Math.max(0, Number(queryValue(req, 'after_sequence') || 0));
  const messages = conversation ? await messagesForConversation(conversation.id, after, 50) : [];
  return json(res, 200, { ok: true, code: 'CHAT_BOOTSTRAP_OK', csrfToken: csrfBundle(req, res), conversation, messages, realtime: conversation ? chatRealtime(conversation.id, refreshed.access_token) : null });
}

async function anonymousAuth(turnstileToken) {
  const token = text(turnstileToken, config().turnstileRequired ? 10 : 0, 4096, 'Token Turnstile');
  const body = { data: { source: 'dirac_support' } };
  if (token) body.gotrue_meta_security = { captcha_token: token };
  const result = await auth('/signup', { body });
  if (!result.ok || !result.data || !result.data.access_token || !result.data.refresh_token || !result.data.user || !result.data.user.id) throw new PublicError(503, 'ANONYMOUS_AUTH_FAILED', 'Sesi anonim belum dapat dibuat. Pastikan Anonymous Sign-ins aktif.');
  return result.data;
}

async function actionChatStart(req, res, body) {
  exactKeys(body, ['name', 'email', 'category', 'subject', 'message', 'website', 'consent', 'turnstileToken']);
  if (String(body.website || '').trim()) throw new PublicError(400, 'AUTOMATION_REJECTED', 'Permintaan tidak valid.');
  if (body.consent !== true) throw new PublicError(400, 'CONSENT_REQUIRED', 'Persetujuan pemrosesan percakapan wajib diberikan.');
  await rateLimit(req, 'chat_start', 3, 600, 900, 'burst'); await rateLimit(req, 'chat_start_daily', 10, 86400, 3600, 'daily');
  await takeRateLimit('chat_start_global', hmac(config().ipSecret, 'chat|global|start', 'hex'), 5000, 86400, 3600);
  const name = text(body.name, 2, 80, 'Nama'); const customerEmail = email(body.email, false);
  const category = String(body.category || 'other'); if (!['technical', 'account', 'billing', 'domain', 'other'].includes(category)) throw new PublicError(400, 'CATEGORY_INVALID', 'Kategori chat tidak valid.');
  const subject = text(body.subject, 3, 120, 'Judul'); const initialMessage = messageText(body.message);
  const clientMessageId = idempotencyKey(req, '', 'Idempotency key chat');
  let session = readSession(req, CUSTOMER_COOKIE); let authSession;
  if (session && session.kind === 'customer' && session.uid && session.refreshToken) {
    // Existing sessions do not call Supabase /signup, so validate Turnstile here.
    await verifyTurnstile(req, body.turnstileToken);
    authSession = await refreshCustomerAuth(res, session);
  } else {
    // For a new anonymous user Supabase Auth validates this token. A Turnstile
    // token is single-use, so it must not be consumed by siteverify first.
    authSession = await anonymousAuth(body.turnstileToken);
  }
  const userId = String(authSession.user.id); const existing = await findActiveConversation(userId);
  let result;
  if (existing) {
    result = { conversation: existing, messages: await messagesForConversation(existing.id, 0, 50) };
  } else {
    result = await rpc('support_chat_open', { p_customer_user_id: userId, p_customer_name: name, p_customer_email: customerEmail || null, p_category: category, p_subject: subject, p_body: initialMessage, p_client_message_id: clientMessageId });
    if (Array.isArray(result)) result = result[0];
  }
  if (!result || !result.conversation) throw new PublicError(500, 'CHAT_OPEN_FAILED', 'Percakapan belum dapat dibuka.');
  session = { v: 1, kind: 'customer', uid: userId, refreshToken: authSession.refresh_token, iat: Date.now(), exp: Date.now() + 180 * 24 * 60 * 60 * 1000 };
  writeSession(res, CUSTOMER_COOKIE, session, 180 * 24 * 60 * 60, 'Lax');
  const messages = Array.isArray(result.messages) ? result.messages : result.message ? [result.message] : await messagesForConversation(result.conversation.id, 0, 50);
  return json(res, 201, { ok: true, code: 'CHAT_OPENED', csrfToken: csrfBundle(req, res), conversation: result.conversation, messages, realtime: chatRealtime(result.conversation.id, authSession.access_token) });
}

async function requireCustomer(req, res, conversationId) {
  const session = readSession(req, CUSTOMER_COOKIE);
  if (!session || session.kind !== 'customer' || !session.uid || !session.refreshToken) throw new PublicError(401, 'CUSTOMER_SESSION_REQUIRED', 'Sesi chat tidak ditemukan.');
  const refreshed = await refreshCustomerAuth(res, session);
  const next = Object.assign({}, session, { refreshToken: refreshed.refresh_token, exp: Date.now() + 180 * 24 * 60 * 60 * 1000 });
  writeSession(res, CUSTOMER_COOKIE, next, 180 * 24 * 60 * 60, 'Lax');
  const path = '/rest/v1/support_chat_sessions?select=id,customer_user_id,status,expires_at,message_count,revision&id=eq.' + encodeURIComponent(conversationId) + '&customer_user_id=eq.' + encodeURIComponent(session.uid) + '&limit=2';
  const result = await supabase(path, {}); const rows = Array.isArray(result.data) ? result.data : [];
  if (rows.length !== 1) throw new PublicError(404, 'CONVERSATION_NOT_FOUND', 'Percakapan tidak ditemukan.');
  if (rows[0].status === 'blocked') throw new PublicError(403, 'CONVERSATION_BLOCKED', 'Percakapan diblokir oleh sistem keamanan.');
  if (!rows[0].expires_at || Date.parse(rows[0].expires_at) <= Date.now()) throw new PublicError(409, 'CONVERSATION_EXPIRED', 'Masa simpan percakapan telah berakhir. Silakan buka percakapan baru.');
  return { session, conversation: rows[0] };
}

async function actionChatSend(req, res, body) {
  exactKeys(body, ['conversationId', 'clientMessageId', 'body']); const conversationId = id(body.conversationId, 'Conversation ID'); const clientMessageId = id(body.clientMessageId, 'Client message ID'); if (idempotencyKey(req, clientMessageId, 'Idempotency key') !== clientMessageId) throw new PublicError(400, 'IDEMPOTENCY_MISMATCH', 'Idempotency key tidak cocok.');
  const preliminary = readSession(req, CUSTOMER_COOKIE); if (!preliminary || preliminary.kind !== 'customer' || !preliminary.uid) throw new PublicError(401, 'CUSTOMER_SESSION_REQUIRED', 'Sesi chat tidak ditemukan.');
  await rateLimit(req, 'chat_message_burst', 20, 10, 20, 'aggregate'); await rateLimit(req, 'chat_message_ip_daily', 1000, 86400, 3600, 'aggregate'); await accountRateLimit('chat_message_minute', preliminary.uid, 30, 60, 60); await accountRateLimit('chat_message_daily', preliminary.uid, 300, 86400, 3600); await takeRateLimit('chat_message_global', hmac(config().ipSecret, 'chat|global|message', 'hex'), 20000, 86400, 3600);
  const owner = await requireCustomer(req, res, conversationId); if (!ACTIVE_CHAT_STATES.includes(owner.conversation.status)) throw new PublicError(409, 'CONVERSATION_CLOSED', 'Percakapan sudah ditutup.');
  if (Number(owner.conversation.message_count || 0) >= MAX_CONVERSATION_MESSAGES) throw new PublicError(409, 'CONVERSATION_MESSAGE_LIMIT_REACHED', 'Batas pesan percakapan ini telah tercapai. Silakan buka tiket lanjutan.');
  let result = await rpc('support_chat_send', { p_conversation_id: conversationId, p_sender_kind: 'customer', p_sender_user_id: owner.session.uid, p_client_message_id: clientMessageId, p_body: messageText(body.body) });
  if (Array.isArray(result)) result = result[0];
  if (!result || !result.message) throw new PublicError(500, 'MESSAGE_SEND_FAILED', 'Pesan belum dapat disimpan.');
  return json(res, 200, { ok: true, code: 'MESSAGE_SENT', message: result.message, conversation: result.conversation || null });
}

async function actionChatClose(req, res, body) {
  exactKeys(body, ['conversationId']); const conversationId = id(body.conversationId, 'Conversation ID');
  const preliminary = readSession(req, CUSTOMER_COOKIE); if (!preliminary || preliminary.kind !== 'customer' || !preliminary.uid) throw new PublicError(401, 'CUSTOMER_SESSION_REQUIRED', 'Sesi chat tidak ditemukan.');
  await accountRateLimit('chat_close', preliminary.uid, 10, 600, 600);
  const owner = await requireCustomer(req, res, conversationId);
  let result = await rpc('support_chat_close', { p_conversation_id: conversationId, p_customer_user_id: owner.session.uid }); if (Array.isArray(result)) result = result[0];
  return json(res, 200, { ok: true, code: 'CHAT_CLOSED', conversation: result && result.conversation || result || null });
}

async function actionCustomerRefresh(req, res) {
  const session = readSession(req, CUSTOMER_COOKIE); if (!session || session.kind !== 'customer' || !session.refreshToken) throw new PublicError(401, 'CUSTOMER_SESSION_REQUIRED', 'Sesi chat sudah berakhir.');
  await accountRateLimit('customer_refresh', session.uid, 20, 600, 600);
  const refreshed = await refreshCustomerAuth(res, session); const conversation = await findActiveConversation(session.uid);
  const next = Object.assign({}, session, { refreshToken: refreshed.refresh_token, exp: Date.now() + 180 * 24 * 60 * 60 * 1000 }); writeSession(res, CUSTOMER_COOKIE, next, 180 * 24 * 60 * 60, 'Lax');
  return json(res, 200, { ok: true, code: 'CUSTOMER_ACCESS_REFRESHED', realtime: conversation ? chatRealtime(conversation.id, refreshed.access_token) : null });
}

async function issueAdminSession(res, authSession, staff, mfaAt) {
  const claims = decodeJwt(authSession.access_token); const sessionId = id(claims.session_id, 'Auth session ID');
  if (claims.aal !== 'aal2'
     || String(claims.sub || '') !== String(staff.user_id)
     || authSession.user && String(authSession.user.id || '') !== String(staff.user_id)) {
    throw new PublicError(403, 'MFA_ASSURANCE_INVALID', 'Identitas atau tingkat jaminan sesi admin tidak valid.');
  }
  const session = { v: 1, kind: 'admin', uid: staff.user_id, email: staff.email, role: staff.role, sessionVersion: Number(staff.session_version), sessionId, refreshToken: authSession.refresh_token, aal: 'aal2', mfaAt: mfaAt || Date.now(), authCheckedAt: Date.now(), iat: Date.now(), exp: Date.now() + 12 * 60 * 60 * 1000 };
  writeSession(res, ADMIN_COOKIE, session, 12 * 60 * 60, 'Strict'); clearCookie(res, MFA_COOKIE, 'Strict');
  return session;
}

async function actionAdminLogin(req, res, body) {
  exactKeys(body, ['email', 'password', 'turnstileToken', 'enrollmentSecret']); const adminEmail = email(body.email, true); const password = String(body.password || ''); const token = text(body.turnstileToken, config().turnstileRequired ? 10 : 0, 4096, 'Token Turnstile');
  if (password.length < 8 || password.length > 256) throw new PublicError(400, 'CREDENTIALS_INVALID', 'Email atau password belum sesuai.');
  await rateLimit(req, 'admin_login_ip', 5, 900, 1800, 'ip'); await accountRateLimit('admin_login_account', adminEmail, 5, 900, 1800);
  req.diracAuthAuditEligible = true;
  const loginBody = { email: adminEmail, password }; if (token) loginBody.gotrue_meta_security = { captcha_token: token };
  const login = await auth('/token?grant_type=password', { body: loginBody });
  if (!login.ok || !login.data || !login.data.access_token || !login.data.refresh_token || !login.data.user) throw new PublicError(401, 'CREDENTIALS_INVALID', 'Email atau password belum sesuai.');
  const staff = await staffByUser(login.data.user.id); if (String(staff.email).toLowerCase() !== adminEmail) throw new PublicError(403, 'STAFF_IDENTITY_MISMATCH', 'Identitas staff tidak cocok.');
  const claims = decodeJwt(login.data.access_token); const mustMfa = config().adminMfaRequired || staff.mfa_required === true;
  if (!mustMfa || claims.aal === 'aal2') {
    await issueAdminSession(res, login.data, staff, Date.now());
    req.diracAuthOutcome = 'success'; await recordAdminAuth(req, staff.user_id, 'admin.auth.session_issued', adminEmail, 'success', 'ADMIN_LOGIN_OK');
    const queue = await adminQueue(staff, 'active', 50); const snapshot = await statusSnapshot(canManageStatus(staff));
    return json(res, 200, { ok: true, code: 'ADMIN_LOGIN_OK', admin: publicAdmin(staff), queue, status: snapshot, realtime: adminRealtime(login.data.access_token) });
  }
  const factors = Array.isArray(login.data.user.factors) ? login.data.user.factors : [];
  let factor = factors.find((item) => item && item.status === 'verified' && item.factor_type === 'totp'); let enrollmentPayload = null;
  if (!factor) {
    // A separate out-of-band secret prevents a stolen initial password from
    // binding an attacker's authenticator before the legitimate first login.
    if (!timingEqual(config().mfaEnrollmentSecret, String(body.enrollmentSecret || ''))) throw new PublicError(403, 'MFA_ENROLLMENT_AUTH_REQUIRED', 'Secret bootstrap enrollment TOTP tidak valid.');
    for (const stale of factors.filter((item) => item && item.status !== 'verified' && item.factor_type === 'totp').slice(0, 5)) {
      try { await auth('/factors/' + encodeURIComponent(stale.id), { method: 'DELETE', token: login.data.access_token, body: {} }); } catch (_) {}
    }
    const enrolled = await auth('/factors', { token: login.data.access_token, body: { factor_type: 'totp', friendly_name: 'Dirac Support Console' } });
    const totp = enrolled.data && enrolled.data.totp; const factorId = enrolled.data && enrolled.data.id;
    const qrCode = String(totp && totp.qr_code || ''); const secret = String(totp && totp.secret || '');
    if (!enrolled.ok || !factorId || !/^data:image\/svg\+xml[,;]/i.test(qrCode) || qrCode.length > 20000 || !/^[A-Z2-7]{16,128}$/i.test(secret)) throw new PublicError(502, 'MFA_ENROLLMENT_FAILED', 'Faktor TOTP belum dapat dibuat.');
    factor = { id: factorId, factor_type: 'totp', status: 'unverified' };
    enrollmentPayload = { qrCode, secret };
  }
  const challenge = await auth('/factors/' + encodeURIComponent(factor.id) + '/challenge', { token: login.data.access_token, body: {} });
  if (!challenge.ok || !challenge.data || !challenge.data.id) throw new PublicError(502, 'MFA_CHALLENGE_FAILED', 'Challenge MFA belum dapat dibuat.');
  const temp = { v: 1, kind: 'admin_mfa', uid: staff.user_id, accessToken: login.data.access_token, refreshToken: login.data.refresh_token, factorId: factor.id, challengeId: challenge.data.id, exp: Date.now() + 5 * 60 * 1000 };
  writeSession(res, MFA_COOKIE, temp, 5 * 60, 'Strict');
  req.diracAuthOutcome = 'success'; await recordAdminAuth(req, staff.user_id, 'admin.auth.mfa_required', adminEmail, 'challenge_issued', enrollmentPayload ? 'MFA_ENROLLMENT_STARTED' : 'MFA_CHALLENGE_STARTED');
  return json(res, 200, { ok: true, code: 'ADMIN_MFA_REQUIRED', mfaRequired: true, mfaEnrollment: enrollmentPayload });
}

async function actionAdminMfaVerify(req, res, body) {
  exactKeys(body, ['code']); const code = String(body.code || '').trim(); if (!/^\d{6}$/.test(code)) throw new PublicError(400, 'MFA_CODE_INVALID', 'Kode TOTP wajib enam digit.');
  const temp = readSession(req, MFA_COOKIE); if (!temp || temp.kind !== 'admin_mfa') throw new PublicError(401, 'MFA_CHALLENGE_EXPIRED', 'Challenge MFA sudah berakhir. Silakan login ulang.');
  await rateLimit(req, 'admin_mfa_ip', 8, 900, 1800, 'verify'); await accountRateLimit('admin_mfa_account', temp.uid, 5, 900, 1800);
  req.diracAuthAuditEligible = true;
  const verified = await auth('/factors/' + encodeURIComponent(temp.factorId) + '/verify', { token: temp.accessToken, body: { challenge_id: temp.challengeId, code } });
  if (!verified.ok || !verified.data || !verified.data.access_token || !verified.data.refresh_token) throw new PublicError(401, 'MFA_CODE_REJECTED', 'Kode autentikator tidak valid.');
  const claims = decodeJwt(verified.data.access_token); if (claims.aal !== 'aal2' || String(claims.sub || '') !== String(temp.uid)) throw new PublicError(403, 'MFA_ASSURANCE_INVALID', 'Tingkat jaminan MFA belum terpenuhi.');
  const staff = await staffByUser(temp.uid); await issueAdminSession(res, verified.data, staff, Date.now());
  req.diracAuthOutcome = 'success'; await recordAdminAuth(req, staff.user_id, 'admin.auth.session_issued', staff.email, 'success', 'ADMIN_MFA_OK');
  const queue = await adminQueue(staff, 'active', 50); const snapshot = await statusSnapshot(canManageStatus(staff));
  return json(res, 200, { ok: true, code: 'ADMIN_MFA_OK', admin: publicAdmin(staff), queue, status: snapshot, realtime: adminRealtime(verified.data.access_token) });
}

async function adminQueue(staff, filter, limit) {
  const cleanFilter = ['active', 'new', 'mine', 'closed'].includes(filter) ? filter : 'active';
  let data = await rpc('support_admin_queue', { p_admin_user_id: staff.user_id, p_filter: cleanFilter, p_limit: Math.min(50, Math.max(1, limit || 50)) });
  if (data && Array.isArray(data.queue)) data = data.queue;
  return Array.isArray(data) ? data : [];
}

async function actionAdminBootstrap(req, res) {
  const owner = await requireAdmin(req, res, true); await accountRateLimit('admin_bootstrap', owner.staff.user_id, 30, 60, 60); const refreshed = owner.authSession;
  const queue = await adminQueue(owner.staff, 'active', 50); const snapshot = await statusSnapshot(canManageStatus(owner.staff));
  return json(res, 200, { ok: true, code: 'ADMIN_BOOTSTRAP_OK', csrfToken: csrfBundle(req, res), admin: publicAdmin(owner.staff), queue, status: snapshot, realtime: adminRealtime(refreshed.access_token) });
}

async function actionAdminQueue(req, res) {
  const owner = await requireAdmin(req, res, false); await accountRateLimit('admin_read', owner.staff.user_id, 240, 60, 60); const queue = await adminQueue(owner.staff, queryValue(req, 'filter'), Number(queryValue(req, 'limit') || 50));
  return json(res, 200, { ok: true, code: 'ADMIN_QUEUE_OK', queue });
}

async function actionAdminThread(req, res) {
  const owner = await requireAdmin(req, res, false); await accountRateLimit('admin_read', owner.staff.user_id, 240, 60, 60); const conversationId = id(queryValue(req, 'conversation_id'), 'Conversation ID'); const after = Math.max(0, Number(queryValue(req, 'after_sequence') || 0)); const limit = Math.min(100, Math.max(1, Number(queryValue(req, 'limit') || 100)));
  let data = await rpc('support_admin_thread', { p_admin_user_id: owner.staff.user_id, p_conversation_id: conversationId, p_after_sequence: after, p_limit: limit }); if (Array.isArray(data)) data = data[0];
  if (!data || !data.conversation) throw new PublicError(404, 'CONVERSATION_NOT_FOUND', 'Percakapan tidak ditemukan.');
  return json(res, 200, { ok: true, code: 'ADMIN_THREAD_OK', conversation: data.conversation, messages: data.messages || [] });
}

async function actionAdminSend(req, res, body) {
  exactKeys(body, ['conversationId', 'clientMessageId', 'body']); const owner = await requireAdmin(req, res, true); const conversationId = id(body.conversationId, 'Conversation ID'); const clientMessageId = id(body.clientMessageId, 'Client message ID'); if (idempotencyKey(req, clientMessageId, 'Idempotency key') !== clientMessageId) throw new PublicError(400, 'IDEMPOTENCY_MISMATCH', 'Idempotency key tidak cocok.');
  if (String(owner.staff.role || '') === 'agent') {
    const assignment = await supabase('/rest/v1/support_chat_sessions?select=id,assigned_to&id=eq.' + encodeURIComponent(conversationId) + '&limit=2', {});
    const rows = Array.isArray(assignment.data) ? assignment.data : [];
    if (rows.length !== 1) throw new PublicError(404, 'CONVERSATION_NOT_FOUND', 'Percakapan tidak ditemukan.');
    if (String(rows[0].assigned_to || '') !== String(owner.staff.user_id)) throw new PublicError(403, 'CONVERSATION_ASSIGNMENT_REQUIRED', 'Percakapan wajib diklaim sebelum dibalas.');
  }
  await accountRateLimit('admin_message', owner.staff.user_id, 120, 60, 60);
  let data = await rpc('support_chat_send', { p_conversation_id: conversationId, p_sender_kind: 'admin', p_sender_user_id: owner.staff.user_id, p_client_message_id: clientMessageId, p_body: messageText(body.body) }); if (Array.isArray(data)) data = data[0];
  if (!data || !data.message) throw new PublicError(500, 'MESSAGE_SEND_FAILED', 'Balasan belum dapat disimpan.');
  return json(res, 200, { ok: true, code: 'ADMIN_MESSAGE_SENT', message: data.message, conversation: data.conversation || null });
}

async function actionAdminConversationUpdate(req, res, body) {
  exactKeys(body, ['conversationId', 'operation']); const owner = await requireAdmin(req, res, true); const conversationId = id(body.conversationId, 'Conversation ID'); const operation = String(body.operation || ''); if (!['claim', 'waiting_customer', 'close', 'block'].includes(operation)) throw new PublicError(400, 'OPERATION_INVALID', 'Operasi percakapan tidak valid.');
  if (operation === 'block') requireStaffRole(owner.staff, ['lead', 'admin'], 'memblokir percakapan');
  await accountRateLimit('admin_chat_mutation', owner.staff.user_id, 120, 60, 60);
  let data = await rpc('support_admin_conversation_update', { p_admin_user_id: owner.staff.user_id, p_conversation_id: conversationId, p_operation: operation }); if (Array.isArray(data)) data = data[0];
  if (!data || !data.conversation) throw new PublicError(500, 'CONVERSATION_UPDATE_FAILED', 'Percakapan belum dapat diperbarui.');
  return json(res, 200, { ok: true, code: 'CONVERSATION_UPDATED', conversation: data.conversation });
}

async function actionAdminStatusSnapshot(req, res) {
  const owner = await requireAdmin(req, res, true); requireStaffRole(owner.staff, ['lead', 'admin'], 'membaca konfigurasi status'); await accountRateLimit('admin_read', owner.staff.user_id, 240, 60, 60); const snapshot = await statusSnapshot(true); return json(res, 200, Object.assign({ ok: true, code: 'ADMIN_STATUS_OK' }, snapshot));
}

async function actionAdminComponentUpdate(req, res, body) {
  exactKeys(body, ['componentId', 'status']); const owner = await requireAdmin(req, res, true); const componentId = id(body.componentId, 'Component ID'); const status = String(body.status || ''); if (!SERVICE_STATES.has(status)) throw new PublicError(400, 'SERVICE_STATUS_INVALID', 'Status komponen tidak valid.');
  requireStaffRole(owner.staff, ['lead', 'admin'], 'mengubah status layanan');
  await accountRateLimit('admin_status_mutation', owner.staff.user_id, 60, 60, 60);
  const data = await rpc('support_status_component_set', { p_admin_user_id: owner.staff.user_id, p_component_id: componentId, p_status: status });
  return json(res, 200, { ok: true, code: 'COMPONENT_STATUS_UPDATED', component: data && data.component || data });
}

async function actionAdminMonitorConfigUpdate(req, res, body) {
  exactKeys(body, ['componentId', 'enabled', 'url', 'timeoutMs', 'expectedMin', 'expectedMax']);
  const owner = await requireAdmin(req, res, true);
  requireStaffRole(owner.staff, ['lead', 'admin'], 'mengelola target pemantauan');
  const componentId = id(body.componentId, 'Component ID');
  if (typeof body.enabled !== 'boolean') throw new PublicError(400, 'MONITOR_ENABLED_INVALID', 'Status aktif target monitor tidak valid.');
  const timeoutMs = Number(body.timeoutMs); const expectedMin = Number(body.expectedMin); const expectedMax = Number(body.expectedMax);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 5000 ||
      !Number.isInteger(expectedMin) || !Number.isInteger(expectedMax) ||
      expectedMin < 100 || expectedMax > 599 || expectedMin > expectedMax) {
    throw new PublicError(400, 'MONITOR_RANGE_INVALID', 'Timeout atau rentang status HTTP target tidak valid.');
  }
  await accountRateLimit('admin_monitor_mutation', owner.staff.user_id, 30, 60, 120);
  const url = normalizeMonitorUrl(body.url);
  if (body.enabled && !url) throw new PublicError(400, 'MONITOR_URL_REQUIRED', 'URL HTTPS wajib diisi sebelum target diaktifkan.');
  if (url) await resolveMonitorAddress(new URL(url));
  const data = await rpc('support_monitor_config_set', {
    p_admin_user_id: owner.staff.user_id,
    p_component_id: componentId,
    p_enabled: body.enabled,
    p_url: url || null,
    p_timeout_ms: timeoutMs,
    p_expected_min: expectedMin,
    p_expected_max: expectedMax
  });
  return json(res, 200, { ok: true, code: url ? 'MONITOR_CONFIG_UPDATED' : 'MONITOR_CONFIG_CLEARED', componentId, monitor: data && data.monitor || null });
}

async function actionAdminIncidentCreate(req, res, body) {
  exactKeys(body, ['title', 'summary', 'impact', 'componentIds']); const owner = await requireAdmin(req, res, true); const impact = String(body.impact || 'minor'); if (!['minor', 'major', 'critical'].includes(impact)) throw new PublicError(400, 'IMPACT_INVALID', 'Dampak insiden tidak valid.');
  requireStaffRole(owner.staff, ['lead', 'admin'], 'membuat insiden');
  const componentIds = Array.isArray(body.componentIds) ? body.componentIds.slice(0, 20).map((value) => id(value, 'Component ID')) : [];
  await accountRateLimit('admin_incident_mutation', owner.staff.user_id, 60, 60, 60);
  const data = await rpc('support_incident_create', { p_admin_user_id: owner.staff.user_id, p_title: text(body.title, 4, 140, 'Judul'), p_summary: messageText(body.summary), p_impact: impact, p_component_ids: componentIds });
  return json(res, 201, { ok: true, code: 'INCIDENT_CREATED', incident: data && data.incident || data });
}

async function actionAdminIncidentAdvance(req, res, body) {
  exactKeys(body, ['incidentId', 'expectedRevision', 'stage', 'progress', 'message']); const owner = await requireAdmin(req, res, true); const incidentId = id(body.incidentId, 'Incident ID'); const stage = String(body.stage || ''); if (!INCIDENT_STAGES.has(stage)) throw new PublicError(400, 'INCIDENT_STAGE_INVALID', 'Tahap insiden tidak valid.');
  requireStaffRole(owner.staff, ['lead', 'admin'], 'memperbarui insiden');
  const revision = Number(body.expectedRevision); const progress = Number(body.progress); if (!Number.isSafeInteger(revision) || revision < 0 || !Number.isFinite(progress) || progress < 0 || progress > 100) throw new PublicError(400, 'INCIDENT_REVISION_INVALID', 'Revision atau progress insiden tidak valid.');
  await accountRateLimit('admin_incident_mutation', owner.staff.user_id, 60, 60, 60);
  const result = await supabase('/rest/v1/rpc/support_incident_advance', { method: 'POST', body: { p_admin_user_id: owner.staff.user_id, p_incident_id: incidentId, p_expected_revision: revision, p_stage: stage, p_progress: Math.round(progress), p_public_message: messageText(body.message) }, allowError: true });
  if (!result.ok) {
    const code = result.data && typeof result.data === 'object' && String(result.data.code || result.data.message || '');
    if (/revision|conflict/i.test(code)) throw new PublicError(409, 'INCIDENT_REVISION_CONFLICT', 'Insiden telah diperbarui oleh admin lain.');
    if (result.status === 429) throw new PublicError(429, 'DATABASE_RATE_LIMITED', 'Database support sedang membatasi perubahan. Coba kembali sesaat lagi.');
    if (result.status === 400 || result.status === 409 || result.status === 422) throw new PublicError(400, 'INCIDENT_TRANSITION_REJECTED', 'Transisi tahap insiden ditolak.');
    throw new PublicError(502, 'DATABASE_REQUEST_FAILED', 'Database support belum dapat memproses pembaruan insiden.');
  }
  return json(res, 200, { ok: true, code: 'INCIDENT_ADVANCED', incident: result.data && result.data.incident || result.data });
}

async function actionAdminMaintenanceCreate(req, res, body) {
  exactKeys(body, ['title', 'message', 'startsAt', 'endsAt', 'componentIds']); const owner = await requireAdmin(req, res, true); const startsAt = new Date(body.startsAt); const endsAt = new Date(body.endsAt); if (Number.isNaN(startsAt.getTime()) || Number.isNaN(endsAt.getTime()) || endsAt <= startsAt || endsAt.getTime() - startsAt.getTime() > 7 * 24 * 60 * 60 * 1000) throw new PublicError(400, 'MAINTENANCE_TIME_INVALID', 'Rentang pemeliharaan tidak valid.');
  requireStaffRole(owner.staff, ['lead', 'admin'], 'menjadwalkan pemeliharaan');
  const componentIds = Array.isArray(body.componentIds) ? body.componentIds.slice(0, 20).map((value) => id(value, 'Component ID')) : [];
  await accountRateLimit('admin_status_mutation', owner.staff.user_id, 60, 60, 60);
  const data = await rpc('support_maintenance_create', { p_admin_user_id: owner.staff.user_id, p_title: text(body.title, 4, 140, 'Judul'), p_message: messageText(body.message), p_starts_at: startsAt.toISOString(), p_ends_at: endsAt.toISOString(), p_component_ids: componentIds });
  return json(res, 201, { ok: true, code: 'MAINTENANCE_CREATED', maintenance: data && data.maintenance || data });
}

async function actionAdminLogout(req, res) {
  const session = readSession(req, ADMIN_COOKIE);
  if (session && session.refreshToken) {
    try { const refreshed = await refreshAuth(session.refreshToken); await auth('/logout?scope=local', { token: refreshed.access_token, body: {} }); } catch (_) {}
  }
  if (session && session.uid) await recordAdminAuth(req, session.uid, 'admin.auth.logout', session.email, 'success', 'ADMIN_LOGGED_OUT');
  clearCookie(res, ADMIN_COOKIE, 'Strict'); clearCookie(res, MFA_COOKIE, 'Strict'); return json(res, 200, { ok: true, code: 'ADMIN_LOGGED_OUT' });
}

function ipv4Number(address) {
  const parts = String(address || '').split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0] * 0x1000000) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0);
}

function ipv4InCidr(address, base, prefix) {
  const value = ipv4Number(address); const network = ipv4Number(base);
  if (value === null || network === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((value & mask) >>> 0) === ((network & mask) >>> 0);
}

function ipv6Number(address) {
  let source = String(address || '').toLowerCase();
  if (!source || source.includes('%')) return null;
  if (source.includes('.')) {
    const separator = source.lastIndexOf(':');
    const v4 = ipv4Number(source.slice(separator + 1));
    if (separator < 0 || v4 === null) return null;
    source = source.slice(0, separator) + ':' + ((v4 >>> 16) & 0xffff).toString(16) + ':' + (v4 & 0xffff).toString(16);
  }
  const halves = source.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const parts = left.concat(Array(Math.max(0, missing)).fill('0'), right);
  if (parts.length !== 8 || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  return parts.reduce((value, part) => (value << 16n) | BigInt(Number.parseInt(part, 16)), 0n);
}

function ipv6InCidr(addressValue, base, prefix) {
  const network = ipv6Number(base);
  if (addressValue === null || network === null) return false;
  const shift = 128n - BigInt(prefix);
  return (addressValue >> shift) === (network >> shift);
}

function isPrivateIp(address) {
  if (net.isIP(address) === 4) {
    const reserved = [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
      ['192.31.196.0', 24], ['192.52.193.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
      ['192.175.48.0', 24], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
      ['224.0.0.0', 4], ['240.0.0.0', 4]
    ];
    return reserved.some(([base, prefix]) => ipv4InCidr(address, base, prefix));
  }
  if (net.isIP(address) === 6) {
    const value = ipv6Number(address);
    if (value === null || !ipv6InCidr(value, '2000::', 3)) return true;
    // Within global unicast, exclude IETF protocol assignments, benchmarks,
    // documentation, transition mechanisms, and other special-use networks.
    const reserved = [
      ['2001::', 23], ['2001:db8::', 32], ['2002::', 16],
      ['2620:4f:8000::', 48], ['3fff::', 20]
    ];
    return reserved.some(([base, prefix]) => ipv6InCidr(value, base, prefix));
  }
  return true;
}

function normalizeMonitorUrl(value) {
  const raw = String(value || '').normalize('NFC').trim();
  if (!raw) return '';
  if (raw.length > 2048 || /[\u0000-\u0020\u007f]/.test(raw)) throw new PublicError(400, 'MONITOR_TARGET_INVALID', 'URL target monitor tidak valid.');
  let url;
  try { url = new URL(raw); } catch (_) { throw new PublicError(400, 'MONITOR_TARGET_INVALID', 'URL target monitor tidak valid.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || !url.hostname) throw new PublicError(400, 'MONITOR_TARGET_INVALID', 'Target wajib berupa URL HTTPS publik tanpa kredensial atau fragmen.');
  const port = url.port ? Number(url.port) : 443;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new PublicError(400, 'MONITOR_PORT_INVALID', 'Port HTTPS target monitor tidak valid.');
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!hostname || hostname === 'localhost' || /\.(?:localhost|local|localdomain|internal|home|lan)$/.test(hostname)) throw new PublicError(400, 'MONITOR_TARGET_UNSAFE', 'Hostname lokal atau internal tidak boleh dipantau.');
  if (net.isIP(hostname) && isPrivateIp(hostname)) throw new PublicError(400, 'MONITOR_TARGET_UNSAFE', 'Target monitor tidak boleh mengarah ke jaringan privat.');
  url.hostname = net.isIP(hostname) === 6 ? '[' + hostname + ']' : hostname;
  const canonical = url.toString();
  if (canonical.length > 2048) throw new PublicError(400, 'MONITOR_TARGET_INVALID', 'URL target monitor terlalu panjang.');
  return canonical;
}

async function resolveMonitorAddress(url) {
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  let records; let dnsTimer;
  try {
    if (net.isIP(hostname)) records = [{ address: hostname, family: net.isIP(hostname) }];
    else records = await Promise.race([
      dns.lookup(hostname, { all: true, verbatim: true }),
      new Promise((_, reject) => { dnsTimer = setTimeout(() => reject(new Error('DNS_TIMEOUT')), 3000); })
    ]);
  } catch (_) {
    throw new PublicError(400, 'MONITOR_DNS_UNAVAILABLE', 'Hostname target monitor belum dapat diresolusikan.');
  } finally {
    if (dnsTimer) clearTimeout(dnsTimer);
  }
  if (!records.length || records.some((record) => !net.isIP(record.address) || isPrivateIp(record.address))) throw new PublicError(400, 'MONITOR_TARGET_UNSAFE', 'Target monitor mengarah atau dapat mengarah ke jaringan privat.');
  return records[0];
}

async function probeTarget(target) {
  const url = new URL(normalizeMonitorUrl(target.url));
  const chosen = await resolveMonitorAddress(url); const started = Date.now(); const timeoutMs = Math.min(5000, Math.max(1000, Number(target.timeoutMs || 3000)));
  return new Promise((resolve) => {
    let finished = false; let deadline;
    const finish = (value) => { if (finished) return; finished = true; if (deadline) clearTimeout(deadline); resolve(value); };
    const request = https.request(url, { method: 'GET', headers: { Accept: 'text/plain,application/json;q=0.9,*/*;q=0.1', 'User-Agent': 'Dirac-Support-Monitor/2.1', Connection: 'close' }, family: chosen.family, autoSelectFamily: false, lookup: (_hostname, options, callback) => options && options.all ? callback(null, [{ address: chosen.address, family: chosen.family }]) : callback(null, chosen.address, chosen.family), servername: net.isIP(url.hostname.replace(/^\[|\]$/g, '')) ? '' : url.hostname, rejectUnauthorized: true }, (response) => {
      let bytes = 0; response.on('data', (chunk) => { bytes += chunk.length; if (bytes > 64 * 1024) request.destroy(new Error('RESPONSE_TOO_LARGE')); });
      response.on('end', () => { const range = Array.isArray(target.expectedStatus) ? target.expectedStatus : [200, 399]; const ok = response.statusCode >= Number(range[0]) && response.statusCode <= Number(range[1]); finish({ ok, latencyMs: Date.now() - started, statusCode: response.statusCode || 0, errorCode: ok ? '' : 'HTTP_STATUS' }); });
      response.on('aborted', () => finish({ ok: false, latencyMs: Date.now() - started, statusCode: response.statusCode || 0, errorCode: 'RESPONSE_ABORTED' }));
      response.on('error', () => finish({ ok: false, latencyMs: Date.now() - started, statusCode: response.statusCode || 0, errorCode: 'RESPONSE_ERROR' }));
    });
    deadline = setTimeout(() => request.destroy(new Error('TIMEOUT')), timeoutMs);
    request.on('error', (error) => finish({ ok: false, latencyMs: Date.now() - started, statusCode: 0, errorCode: String(error && error.message || 'NETWORK_ERROR').slice(0, 80) })); request.end();
  });
}

async function actionMonitorRun(req, res) {
  const cfg = config(); const expected = env('CRON_SECRET'); const authorization = String(req.headers && req.headers.authorization || ''); const candidate = authorization.replace(/^Bearer\s+/i, '');
  const cronReused = [cfg.cookieSecret, cfg.csrfSecret, cfg.ipSecret, cfg.mfaEnrollmentSecret].some((secret) => timingEqual(expected, secret));
  if (Buffer.byteLength(expected, 'utf8') < 32 || cronReused || !timingEqual(expected, candidate)) throw new PublicError(401, 'MONITOR_AUTH_INVALID', 'Monitor tidak diizinkan.');
  const leaseKey = hmac(cfg.ipSecret, 'monitor|global|lease', 'hex');
  try {
    await takeRateLimit('monitor_run_lease', leaseKey, 1, 240, 240);
  } catch (error) {
    if (error instanceof PublicError && error.code === 'RATE_LIMITED') return json(res, 200, { ok: true, code: 'MONITOR_RUN_SKIPPED', reason: 'overlap_or_duplicate' });
    throw error;
  }
  let targets = await rpc('support_monitor_targets', {});
  if (targets && Array.isArray(targets.targets)) targets = targets.targets;
  if (!Array.isArray(targets) || targets.length > 16) throw new PublicError(503, 'MONITOR_TARGETS_INVALID', 'Daftar target monitor tidak valid.');
  if (!targets.length) return json(res, 200, { ok: true, code: 'MONITOR_RUN_COMPLETE', checked: 0, failed: 0, changed: 0, results: [] });
  const results = [];
  for (let index = 0; index < targets.length; index += 4) {
    const batch = targets.slice(index, index + 4);
    const probed = await Promise.allSettled(batch.map((target) => probeTarget(target)));
    const rows = [];
    for (let offset = 0; offset < batch.length; offset += 1) {
      const target = batch[offset]; const value = probed[offset].status === 'fulfilled' ? probed[offset].value : { ok: false, latencyMs: 0, statusCode: 0, errorCode: 'PROBE_FAILED' };
      const targetId = text(target.id, 1, 80, 'Target ID'); const componentId = id(target.componentId, 'Component ID'); const configRevision = Number(target.configRevision);
      if (!Number.isSafeInteger(configRevision) || configRevision < 1) throw new PublicError(503, 'MONITOR_TARGETS_INVALID', 'Revisi konfigurasi target monitor tidak valid.');
      rows.push({ targetId, componentId, configRevision, value });
    }
    const recorded = await Promise.allSettled(rows.map((row) => rpc('support_monitor_record', { p_target_id: row.targetId, p_component_id: row.componentId, p_config_revision: row.configRevision, p_ok: row.value.ok, p_latency_ms: row.value.latencyMs, p_status_code: row.value.statusCode, p_error_code: row.value.errorCode, p_observed_at: nowIso() })));
    const failedWrite = recorded.find((item) => item.status === 'rejected'); if (failedWrite) throw failedWrite.reason;
    rows.forEach((row, offset) => {
      const databaseState = recorded[offset].status === 'fulfilled' && recorded[offset].value && typeof recorded[offset].value === 'object' ? recorded[offset].value : {};
      const stale = databaseState.stale === true;
      results.push({ id: row.targetId, ok: stale ? true : row.value.ok, skipped: stale, changed: databaseState.changed === true, latencyMs: row.value.latencyMs, statusCode: row.value.statusCode });
    });
  }
  return json(res, 200, { ok: true, code: 'MONITOR_RUN_COMPLETE', checked: results.length, skipped: results.filter((item) => item.skipped).length, failed: results.filter((item) => !item.ok).length, changed: results.filter((item) => item.changed).length, results });
}

async function dispatch(req, res, action, body) {
  if (action === 'status_bootstrap') return actionStatusBootstrap(req, res);
  if (action === 'chat_public_config') return actionChatPublicConfig(req, res);
  if (action === 'admin_public_config') return actionAdminPublicConfig(req, res);
  if (action === 'chat_bootstrap') return actionChatBootstrap(req, res);
  if (action === 'chat_start') return actionChatStart(req, res, body);
  if (action === 'chat_send') return actionChatSend(req, res, body);
  if (action === 'chat_close') return actionChatClose(req, res, body);
  if (action === 'customer_access_refresh') return actionCustomerRefresh(req, res);
  if (action === 'admin_login') return actionAdminLogin(req, res, body);
  if (action === 'admin_mfa_verify') return actionAdminMfaVerify(req, res, body);
  if (action === 'admin_bootstrap') return actionAdminBootstrap(req, res);
  if (action === 'admin_queue') return actionAdminQueue(req, res);
  if (action === 'admin_thread') return actionAdminThread(req, res);
  if (action === 'admin_send') return actionAdminSend(req, res, body);
  if (action === 'admin_conversation_update') return actionAdminConversationUpdate(req, res, body);
  if (action === 'admin_status_snapshot') return actionAdminStatusSnapshot(req, res);
  if (action === 'admin_component_update') return actionAdminComponentUpdate(req, res, body);
  if (action === 'admin_monitor_config_update') return actionAdminMonitorConfigUpdate(req, res, body);
  if (action === 'admin_incident_create') return actionAdminIncidentCreate(req, res, body);
  if (action === 'admin_incident_advance') return actionAdminIncidentAdvance(req, res, body);
  if (action === 'admin_maintenance_create') return actionAdminMaintenanceCreate(req, res, body);
  if (action === 'admin_logout') return actionAdminLogout(req, res);
  if (action === 'monitor_run') return actionMonitorRun(req, res);
  throw new PublicError(404, 'ACTION_NOT_FOUND', 'Action support tidak ditemukan.');
}

async function handler(req, res) {
  const requestId = uuid(); const rawAction = queryValue(req, 'action'); const action = rawAction.trim().toLowerCase();
  req.diracRequestId = requestId;
  securityHeaders(req, res, action);
  if (req.method === 'OPTIONS') {
    if (!originAllowed(req)) return json(res, 403, { ok: false, code: 'ORIGIN_NOT_ALLOWED', message: 'Origin tidak diizinkan.', requestId });
    res.statusCode = 204; return res.end();
  }
  let body = null;
  try {
    if (!/^[a-z0-9_]{1,64}$/.test(action)) throw new PublicError(400, 'ACTION_INVALID', 'Action support tidak valid.');
    if (rawAction !== action) throw new PublicError(400, 'ACTION_NON_CANONICAL', 'Nama action wajib menggunakan format kanonis.');
    verifyQueryShape(req, action);
    if (CUSTOMER_GET_ACTIONS.has(action) || ADMIN_GET_ACTIONS.has(action)) verifyAuthenticatedReadOrigin(req);
    const method = String(req.method || 'GET').toUpperCase();
    const expectedMethod = PUBLIC_GET_ACTIONS.has(action) || CUSTOMER_GET_ACTIONS.has(action) || ADMIN_GET_ACTIONS.has(action) ? 'GET' : 'POST';
    const allowedMethods = action === 'monitor_run' ? ['GET', 'POST'] : [expectedMethod];
    if (!allowedMethods.includes(method)) { setHeader(res, 'Allow', allowedMethods.join(', ')); throw new PublicError(405, 'METHOD_NOT_ALLOWED', 'Method tidak diizinkan untuk action ini.'); }
    if (method === 'POST') {
      if (action !== 'monitor_run') verifyCsrf(req);
      body = await readJson(req);
    }
    return await dispatch(req, res, action, body);
  } catch (error) {
    const safe = error instanceof PublicError ? error : new PublicError(500, 'SUPPORT_INTERNAL_ERROR', 'Sistem support sedang mengalami gangguan.');
    if ((action === 'admin_login' || action === 'admin_mfa_verify') && req.diracAuthAuditEligible === true && req.diracAuthOutcome !== 'success') {
      const pending = action === 'admin_mfa_verify' ? readSession(req, MFA_COOKIE) : null;
      const attemptedEmail = action === 'admin_login' && body && typeof body === 'object' ? String(body.email || '').slice(0, 254) : '';
      await recordAdminAuth(req, pending && pending.uid || null, 'admin.auth.rejected', attemptedEmail, 'rejected', safe.code);
    }
    if (safe.retryAfter) setHeader(res, 'Retry-After', String(safe.retryAfter));
    if (!(error instanceof PublicError)) {
      try { console.error('[dirac-support]', JSON.stringify({ requestId, action, code: String(error && (error.code || error.name) || 'ERROR').slice(0, 80), message: String(error && error.message || '').slice(0, 160) })); } catch (_) {}
    }
    return json(res, safe.status, { ok: false, code: safe.code, message: safe.message, requestId, time: nowIso() });
  }
}

handler.config = { api: { bodyParser: false } };
handler.__test = Object.freeze({ text, messageText, email, seal, unseal, isPrivateIp, normalizeMonitorUrl, resolveMonitorAddress, probeTarget, canManageStatus, decodeJwt, normalizeSnapshot, runtimeCookieName, clientIp, verifyQueryShape, fetchJson });
export default handler;

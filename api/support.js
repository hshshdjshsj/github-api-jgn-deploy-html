import crypto from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import https from 'node:https';
import { promises as dns } from 'node:dns';
import net from 'node:net';
const securityJson = (() => {
'use strict';

// Shared JSON trust boundary. Retain the original string representation until
// duplicate names and Unicode have been checked; JSON.parse alone loses both.
function inputError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function validUnicode(value) {
  if (value.includes('\u0000')) return false;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function parseStrictJson(input, options = {}) {
  const maxBytes = options.maxBytes || 196608;
  const maxDepth = options.maxDepth || 12;
  const maxNodes = options.maxNodes || 4096;
  let source;
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    if (input.byteLength > maxBytes) throw inputError('JSON_SIZE_LIMIT');
    try { source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input); }
    catch (_) { throw inputError('JSON_UTF8_INVALID'); }
  } else if (typeof input === 'string') source = input;
  else throw inputError('JSON_RAW_BODY_REQUIRED');
  if (!source || Buffer.byteLength(source, 'utf8') > maxBytes) throw inputError('JSON_SIZE_LIMIT');
  let index = 0;
  let nodes = 0;
  const fail = (code = 'JSON_INVALID') => { throw inputError(code); };
  const whitespace = () => { while (/[\x20\t\r\n]/.test(source[index] || '\0')) index += 1; };
  const string = () => {
    const start = index;
    if (source[index++] !== '"') fail();
    while (index < source.length) {
      const char = source[index++];
      if (char === '"') {
        let value;
        try { value = JSON.parse(source.slice(start, index)); } catch (_) { fail(); }
        if (!validUnicode(value)) fail('JSON_UNICODE_INVALID');
        return value;
      }
      if (char.charCodeAt(0) < 32) fail();
      if (char === '\\') {
        const escape = source[index++];
        if (escape === 'u') {
          if (!/^[a-fA-F0-9]{4}$/.test(source.slice(index, index + 4))) fail();
          index += 4;
        } else if (!['"', '\\', '/', 'b', 'f', 'n', 'r', 't'].includes(escape)) fail();
      }
    }
    fail();
  };
  const value = (depth) => {
    if (depth > maxDepth || ++nodes > maxNodes) fail('JSON_COMPLEXITY_LIMIT');
    whitespace();
    const char = source[index];
    if (char === '"') { string(); return; }
    if (char === '{') {
      index += 1; whitespace();
      const names = new Set();
      if (source[index] === '}') { index += 1; return; }
      while (index < source.length) {
        const key = string();
        if (['__proto__', 'proto', 'prototype', 'constructor'].includes(key)) fail('JSON_KEY_REJECTED');
        if (names.has(key)) fail('JSON_DUPLICATE_KEY');
        names.add(key);
        whitespace(); if (source[index++] !== ':') fail();
        value(depth + 1); whitespace();
        const delimiter = source[index++];
        if (delimiter === '}') return;
        if (delimiter !== ',') fail();
        whitespace();
      }
      fail();
    }
    if (char === '[') {
      index += 1; whitespace();
      if (source[index] === ']') { index += 1; return; }
      while (index < source.length) {
        value(depth + 1); whitespace();
        const delimiter = source[index++];
        if (delimiter === ']') return;
        if (delimiter !== ',') fail();
      }
      fail();
    }
    for (const literal of ['true', 'false', 'null']) {
      if (source.startsWith(literal, index)) { index += literal.length; return; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
    if (!number) fail();
    const numeric = Number(number[0]);
    if (!Number.isFinite(numeric) || (Number.isInteger(numeric) && !Number.isSafeInteger(numeric))) fail('JSON_NUMBER_INVALID');
    index += number[0].length;
  };
  value(0); whitespace();
  if (index !== source.length) fail();
  return JSON.parse(source);
}

return Object.freeze({ parseStrictJson, validUnicode });
})();
const securityProxy = (() => {
'use strict';

const { isIP } = net;

function normalizeIp(value) {
  if (typeof value !== 'string' || value.length > 128 || /[,\s%\u0000-\u001f]/.test(value)) return '';
  let clean = value.toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) clean = clean.slice(1, -1);
  if (/^::ffff:\d{1,3}(?:\.\d{1,3}){3}$/.test(clean)) clean = clean.slice(7);
  const version = isIP(clean);
  if (version === 4) return clean;
  if (version !== 6) return '';
  try {
    const canonical = new URL('http://[' + clean + ']/').hostname.slice(1, -1);
    const mapped = /^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/.exec(canonical);
    if (mapped) {
      const high = parseInt(mapped[1], 16), low = parseInt(mapped[2], 16);
      return [high >>> 8, high & 255, low >>> 8, low & 255].join('.');
    }
    return canonical;
  } catch (_) { return ''; }
}

function trustedClientIp(req, env = process.env) {
  const socketIp = normalizeIp(req && req.socket && req.socket.remoteAddress || '');
  const headers = req && req.headers || {};
  const mode = String(env.DIRAC_TRUSTED_PROXY_MODE || (env.VERCEL === '1' ? 'vercel' : 'none')).trim().toLowerCase();
  if (mode === 'none') return socketIp || 'unknown';
  if (mode === 'vercel') {
    // This mode is valid only in the provider runtime, where the platform owns
    // this header. A deployment setting alone does not authenticate a proxy.
    if (env.VERCEL !== '1') return socketIp || 'unknown';
    return normalizeIp(headers['x-vercel-forwarded-for']) || socketIp || 'unknown';
  }
  if (mode !== 'standard') return 'unknown';
  const rawTrusted = String(env.DIRAC_TRUSTED_PROXY_IPS || '');
  if (rawTrusted.length > 4096) return 'unknown';
  const configured = rawTrusted.split(',').map(item => item.trim()).filter(Boolean);
  const trusted = configured.map(normalizeIp);
  if (!trusted.length || trusted.some(item => !item) || !socketIp || !trusted.includes(socketIp)) {
    return socketIp || 'unknown';
  }
  const raw = headers['x-forwarded-for'];
  if (typeof raw !== 'string' || raw.length > 2048) return socketIp;
  const chain = raw.split(',').map(item => normalizeIp(item.trim()));
  if (!chain.length || chain.length > 16 || chain.some(item => !item)) return 'unknown';
  let current = socketIp;
  for (let index = chain.length - 1; index >= 0 && trusted.includes(current); index -= 1) {
    current = chain[index];
  }
  return current;
}

return Object.freeze({ normalizeIp, trustedClientIp });
})();

const { parseStrictJson, validUnicode } = securityJson;

const MAX_BODY_BYTES = 16 * 1024;
const MAX_MESSAGE_CHARS = 2000;
const MAX_MESSAGE_BYTES = 8 * 1024;
const MAX_CONVERSATION_MESSAGES = 1000;
const CUSTOMER_COOKIE = '__Host-dirac_support_guest';
const CUSTOMER_IDENTITY_MARKER = 'dirac_support_main_session_v1';
const CUSTOMER_AUTH_EMAIL_DOMAIN = 'support-auth.diracgroup.store';
const MAIN_COOKIE_MAX_CHUNKS = 12;
const ADMIN_COOKIE = '__Host-dirac_support_admin';
const MFA_COOKIE = '__Host-dirac_support_mfa';
const CSRF_COOKIE = '__Host-dirac_support_csrf_seed';
const SUPPORT_CSRF_TTL_MS_V356 = 15 * 60 * 1000;
const SUPPORT_CSRF_VERSION_V356 = 'dirac-support-csrf-session-bound-v356';
const ADMIN_BINDING_HEADER = 'x-dirac-admin-binding';
const ADMIN_BINDING_VERSION = 'dirac-support-admin-binding-v1';
const ACTIVE_CHAT_STATES = ['new', 'queued', 'active', 'waiting_customer', 'waiting_admin'];
const SERVICE_STATES = new Set(['operational', 'degraded', 'partial_outage', 'major_outage', 'maintenance', 'unknown']);
const INCIDENT_STAGES = new Set(['detected', 'investigating', 'identified', 'fixing', 'monitoring', 'resolved']);
const PUBLIC_GET_ACTIONS = new Set(['status_bootstrap', 'chat_public_config', 'admin_public_config']);
const CUSTOMER_GET_ACTIONS = new Set(['chat_bootstrap']);
const CUSTOMER_CONFIG_ACTIONS_V357 = new Set(['chat_public_config', 'chat_bootstrap', 'chat_start', 'chat_send', 'chat_close', 'customer_access_refresh']);
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
  const primaryAdminUserId = env('DIRAC_SUPPORT_PRIMARY_ADMIN_USER_ID').toLowerCase();
  const primaryAdminEmail = env('DIRAC_SUPPORT_PRIMARY_ADMIN_EMAIL').toLowerCase();
  const adminBindingSecret = env('DIRAC_SUPPORT_ADMIN_BINDING_SECRET');
  const turnstileSiteKey = env('DIRAC_SUPPORT_TURNSTILE_SITE_KEY'); const turnstileSecretKey = env('DIRAC_SUPPORT_TURNSTILE_SECRET_KEY');
  const turnstileRequired = envTrue('DIRAC_SUPPORT_REQUIRE_TURNSTILE', isProduction());
  const currentContext = supportCentralCurrentContextV146();
  const customerConfigOnly = Boolean(currentContext && CUSTOMER_CONFIG_ACTIONS_V357.has(String(currentContext.action || '')));
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(supabaseUrl)) throw new PublicError(503, 'SUPPORT_CONFIG_INVALID', 'Konfigurasi database support belum valid.');
  const publishableRole = decodeJwt(publishableKey).role; const secretRole = decodeJwt(secretKey).role;
  const publishableValid = /^sb_publishable_[A-Za-z0-9_-]{10,}$/.test(publishableKey) || publishableRole === 'anon';
  const secretValid = /^sb_secret_[A-Za-z0-9_-]{10,}$/.test(secretKey) || secretRole === 'service_role';
  if (!publishableValid || !secretValid || timingEqual(publishableKey, secretKey)) throw new PublicError(503, 'SUPPORT_KEYS_INVALID', 'Kelas kunci Supabase support tidak valid atau tertukar.');
  const customerSecuritySecrets = [cookieSecret, csrfSecret, ipSecret];
  const securitySecrets = customerConfigOnly ? customerSecuritySecrets : customerSecuritySecrets.concat([mfaEnrollmentSecret, adminBindingSecret]);
  if (isProduction() && !customerConfigOnly && (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(primaryAdminUserId)
      || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(primaryAdminEmail)
      || Buffer.byteLength(adminBindingSecret, 'utf8') < 32)) {
    throw new PublicError(503, 'PRIMARY_ADMIN_BINDING_CONFIG_INVALID', 'Binding admin utama belum dikonfigurasi lengkap.');
  }
  if (securitySecrets.some((value) => Buffer.byteLength(value, 'utf8') < 32) || new Set(securitySecrets).size !== securitySecrets.length) {
    throw new PublicError(503, 'SUPPORT_SECRETS_WEAK', 'Secret keamanan support wajib kuat dan berbeda satu sama lain.');
  }
  if (turnstileRequired && (!turnstileSiteKey || !turnstileSecretKey)) throw new PublicError(503, 'TURNSTILE_CONFIG_MISSING', 'Verifikasi anti-bot support belum dikonfigurasi lengkap.');
  return {
    supabaseUrl,
    publishableKey,
    secretKey,
    cookieSecret,
    csrfSecret,
    ipSecret,
    mfaEnrollmentSecret,
    primaryAdminUserId,
    primaryAdminEmail,
    adminBindingSecret,
    turnstileSiteKey,
    turnstileSecretKey,
    turnstileRequired,
    // Realtime admin authorization is deliberately AAL2-only in SQL, so the
    // HTTP capability must never be weaker than the channel capability.
    adminMfaRequired: true
  };
}

function primaryAdminBindingCanonical(cfg) {
  const current = cfg || config();
  return ADMIN_BINDING_VERSION + '\n' + current.primaryAdminUserId + '\n' + current.primaryAdminEmail;
}

function expectedAdminBindingProof(cfg) {
  const current = cfg || config();
  return hmac(current.adminBindingSecret, primaryAdminBindingCanonical(current), 'base64url');
}

function requireAdminBuildBinding(req) {
  const candidate = String(req && req.headers && req.headers[ADMIN_BINDING_HEADER] || '').trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(candidate)) {
    throw new PublicError(403, 'ADMIN_BUILD_BINDING_REQUIRED', 'Binding build admin tidak ditemukan.');
  }
  const expected = expectedAdminBindingProof(config());
  if (!timingEqual(candidate, expected)) {
    throw new PublicError(403, 'ADMIN_BUILD_BINDING_REJECTED', 'Binding build admin tidak valid.');
  }
  return true;
}

function requirePinnedPrimaryAdmin(staff) {
  const cfg = config();
  const staffId = String(staff && staff.user_id || '').toLowerCase();
  const staffEmail = String(staff && staff.email || '').trim().toLowerCase();
  if (!staff
      || staffId !== cfg.primaryAdminUserId
      || staffEmail !== cfg.primaryAdminEmail
      || String(staff.role || '') !== 'admin'
      || staff.is_active !== true
      || staff.mfa_required !== true) {
    throw new PublicError(403, 'PRIMARY_ADMIN_PIN_MISMATCH', 'Identitas admin tidak sesuai pin backend.');
  }
  return staff;
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
  setHeader(res, 'Access-Control-Allow-Headers', 'Content-Type, Accept, X-Dirac-CSRF, X-Dirac-Admin-Binding, Idempotency-Key, If-None-Match');
  setHeader(res, 'Access-Control-Expose-Headers', 'ETag, Retry-After, X-Dirac-Request-ID, X-Dirac-Central-Security-Guard');
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
  const guarded = supportCentralSerializeOutput(payload, status);
  res.statusCode = guarded.status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', String(Buffer.byteLength(guarded.body, 'utf8')));
  res.end(guarded.body);
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


function safeCookieName(value) {
  const clean = String(value || '').trim();
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/.test(clean) ? clean : '';
}

function escapeRegex(value) { return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function normalizeAuthority(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw.includes(',')) return '';
  if (!raw || /[\r\n\s/@]/.test(raw) || raw.length > 255) return '';
  try {
    const parsed = new URL('https://' + raw);
    if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
    return parsed.host.toLowerCase();
  } catch (_) { return ''; }
}

function mainCookieBases() {
  const defaults = {
    DOMAIN_SESSION_COOKIE: 'dirac_domain_session',
    DOMAIN_REFRESH_COOKIE: 'dirac_domain_refresh',
    DOMAIN_SIGNED_SESSION_COOKIE: 'dirac_domain_signed_session',
    DIRAC_CUSTOMER_MFA_COOKIE: 'dirac_customer_mfa_session'
  };
  const bases = [
    '__Host-dirac_cg_device_v221',
    '__Host-dirac_cg_session_v223',
    'dirac_cg_device_v221',
    'dirac_cg_session_v223'
  ];
  Object.entries(defaults).forEach(([name, fallback]) => {
    const configured = env(name);
    if (configured && !safeCookieName(configured)) throw new PublicError(503, 'MAIN_COOKIE_CONFIG_INVALID', 'Konfigurasi cookie sesi utama tidak valid.');
    [fallback, configured].filter(Boolean).forEach((value) => { if (!bases.includes(value)) bases.push(value); });
  });
  return bases;
}

function mainIdentityRoute(req) {
  verifyAuthenticatedReadOrigin(req);
  let frontend;
  try { frontend = new URL(requestOrigin(req)); } catch (_) { throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin permintaan tidak diizinkan.'); }
  if (frontend.origin !== requestOrigin(req) || !allowedOrigins().has(frontend.origin)) throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin permintaan tidak diizinkan.');
  if (isProduction() && frontend.protocol !== 'https:') throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin HTTPS wajib digunakan.');
  const frontendHost = frontend.hostname.toLowerCase().replace(/\.$/, '');
  if (!/^cs\.[a-z0-9.-]+$/.test(frontendHost)) throw new PublicError(503, 'MAIN_IDENTITY_ROUTE_INVALID', 'Origin frontend tidak dapat dipetakan ke API utama.');
  const expectedHostname = 'api.' + frontendHost.slice(3);
  const expectedAuthority = expectedHostname + (frontend.port ? ':' + frontend.port : '');
  const hostHeaders = [req.headers && req.headers['x-forwarded-host'], req.headers && req.headers.host].filter(Boolean);
  if (!hostHeaders.length || hostHeaders.some((value) => normalizeAuthority(value) !== expectedAuthority)) {
    throw new PublicError(503, 'MAIN_IDENTITY_HOST_MISMATCH', 'Hostname API tidak cocok dengan origin frontend.');
  }
  const forwardedProto = String(req.headers && (req.headers['x-forwarded-proto'] || req.headers['x-vercel-forwarded-proto']) || '').split(',')[0].trim().toLowerCase();
  if (isProduction() && forwardedProto !== 'https') throw new PublicError(503, 'MAIN_IDENTITY_HTTPS_REQUIRED', 'API utama wajib menggunakan HTTPS.');
  const protocol = isProduction() || frontend.protocol === 'https:' ? 'https:' : 'http:';
  const endpoint = new URL('/api/health?action=domain_me', protocol + '//' + expectedAuthority);
  return { endpoint: endpoint.toString(), cookieBases: mainCookieBases() };
}

function rawCookiePairs(req) {
  const raw = String(req && req.headers && req.headers.cookie || '');
  if (!raw || Buffer.byteLength(raw, 'utf8') > 32 * 1024) return [];
  return raw.split(';').slice(0, 180).map((part) => {
    const clean = String(part || '').trim(); const index = clean.indexOf('=');
    if (index < 1) return null;
    const name = safeCookieName(clean.slice(0, index)); const value = clean.slice(index + 1);
    if (!name || /[\r\n]/.test(value) || Buffer.byteLength(value, 'utf8') > 9 * 1024) return null;
    return { name, raw: name + '=' + value };
  }).filter(Boolean);
}

function mainCookieNameAllowed(name, bases) {
  return bases.some((base) => name === base || new RegExp('^' + escapeRegex(base) + '__(?:[0-9]|1[01])$').test(name));
}

function mainCookieHeader(req, route) {
  const header = rawCookiePairs(req).filter((item) => mainCookieNameAllowed(item.name, route.cookieBases)).map((item) => item.raw).join('; ');
  return Buffer.byteLength(header, 'utf8') <= 16 * 1024 ? header : '';
}

function responseSetCookies(headers) {
  if (!headers) return [];
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie().map(String);
  const combined = String(headers.get && headers.get('set-cookie') || '');
  return combined ? combined.split(/,(?=\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/g).map((value) => value.trim()).filter(Boolean) : [];
}

function forwardMainCookies(res, headers, route) {
  for (const value of responseSetCookies(headers)) {
    const clean = String(value || '');
    if (!clean || /[\r\n]/.test(clean) || Buffer.byteLength(clean, 'utf8') > 16 * 1024) continue;
    const first = clean.split(';', 1)[0]; const separator = first.indexOf('=');
    const name = separator > 0 ? safeCookieName(first.slice(0, separator)) : '';
    if (!name || !mainCookieNameAllowed(name, route.cookieBases) || /;\s*Domain=/i.test(clean)) continue;
    if (!/;\s*Path=\/(?:;|$)/i.test(clean) || !/;\s*HttpOnly(?:;|$)/i.test(clean)) continue;
    if (isProduction() && (!/;\s*Secure(?:;|$)/i.test(clean) || !/;\s*SameSite=Strict(?:;|$)/i.test(clean))) continue;
    appendCookie(res, clean);
  }
}

function mainDisplayName(emailValue) {
  const local = String(emailValue || '').split('@')[0].replace(/[._+-]+/g, ' ').replace(/\s+/g, ' ').trim();
  const titled = local.split(' ').filter(Boolean).map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ');
  const clean = String(titled || 'Pelanggan Dirac').normalize('NFC').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80);
  return clean.length >= 2 ? clean : 'Pelanggan Dirac';
}

function forwardedBrowserHeader(req, name, maxLength) {
  const raw = req && req.headers && req.headers[String(name || '').toLowerCase()];
  const value = String(Array.isArray(raw) ? raw[0] || '' : raw || '').trim();
  if (!value || /[\r\n]/.test(value)) return '';
  return value.slice(0, Math.max(1, Number(maxLength) || 512));
}

function mainIdentityHeaders(req, cookieHeader) {
  const headers = {
    Accept: 'application/json',
    Cookie: cookieHeader,
    Origin: requestOrigin(req),
    Referer: requestOrigin(req) + '/livechat.html'
  };
  const forwarded = [
    ['user-agent', 'User-Agent', 512],
    ['accept-language', 'Accept-Language', 160],
    ['sec-ch-ua', 'Sec-CH-UA', 300],
    ['sec-ch-ua-platform', 'Sec-CH-UA-Platform', 100],
    ['sec-fetch-site', 'Sec-Fetch-Site', 32],
    ['sec-fetch-mode', 'Sec-Fetch-Mode', 32],
    ['sec-fetch-dest', 'Sec-Fetch-Dest', 32]
  ];
  forwarded.forEach(([source, target, limit]) => {
    const value = forwardedBrowserHeader(req, source, limit);
    if (value) headers[target] = value;
  });
  return headers;
}

function mainIdentityDiagnosticV360(req, route, cookieHeader, headers) {
  const incomingPairs = rawCookiePairs(req);
  const allowedPairs = incomingPairs.filter((item) => mainCookieNameAllowed(item.name, route.cookieBases));
  const headerNames = Object.keys(headers || {}).map((value) => String(value).toLowerCase()).sort();
  let endpoint; try { endpoint = new URL(route.endpoint); } catch (_) { endpoint = null; }
  return {
    patch: 'dirac-support-main-identity-diagnostic-v360',
    phase: 'prepared',
    route: {
      protocol: endpoint ? endpoint.protocol : '',
      host: endpoint ? endpoint.host : '',
      pathname: endpoint ? endpoint.pathname : '',
      action: endpoint ? String(endpoint.searchParams.get('action') || '') : ''
    },
    source: {
      origin: requestOrigin(req).slice(0, 300),
      host: normalizeAuthority(req && req.headers && req.headers.host),
      forwardedHost: normalizeAuthority(req && req.headers && req.headers['x-forwarded-host']),
      forwardedProto: String(req && req.headers && (req.headers['x-forwarded-proto'] || req.headers['x-vercel-forwarded-proto']) || '').split(',')[0].trim().toLowerCase().slice(0, 16),
      userAgentPresent: Boolean(forwardedBrowserHeader(req, 'user-agent', 512)),
      secFetchSite: forwardedBrowserHeader(req, 'sec-fetch-site', 32),
      secFetchMode: forwardedBrowserHeader(req, 'sec-fetch-mode', 32),
      secFetchDest: forwardedBrowserHeader(req, 'sec-fetch-dest', 32)
    },
    cookies: {
      incomingHeaderBytes: Buffer.byteLength(String(req && req.headers && req.headers.cookie || ''), 'utf8'),
      incomingPairCount: incomingPairs.length,
      allowedPairCount: allowedPairs.length,
      allowedNames: allowedPairs.map((item) => item.name).slice(0, 64),
      allowedBytes: allowedPairs.map((item) => ({ name: item.name, bytes: Buffer.byteLength(item.raw, 'utf8') })).slice(0, 64),
      forwardedHeaderBytes: Buffer.byteLength(String(cookieHeader || ''), 'utf8'),
      forwardedPairCount: String(cookieHeader || '').split(';').map((value) => value.trim()).filter(Boolean).length,
      expectedBaseCount: route.cookieBases.length,
      expectedBases: route.cookieBases.slice(0, 32)
    },
    outbound: { headerNames, cookiePresent: headerNames.includes('cookie'), authorizationPresent: headerNames.includes('authorization') },
    egress: { authorized: null },
    response: null,
    decision: ''
  };
}

function mainIdentityResponseDiagnosticV360(result) {
  const headers = result && result.headers;
  const data = result && result.data;
  const objectData = data && typeof data === 'object' && !Array.isArray(data) ? data : null;
  const user = objectData && objectData.user && typeof objectData.user === 'object' && !Array.isArray(objectData.user) ? objectData.user : null;
  const setCookieNames = responseSetCookies(headers).map((value) => {
    const first = String(value || '').split(';', 1)[0]; const separator = first.indexOf('=');
    return separator > 0 ? safeCookieName(first.slice(0, separator)) : '';
  }).filter(Boolean).slice(0, 64);
  return {
    ok: Boolean(result && result.ok),
    status: Number(result && result.status || 0),
    contentType: String(headers && headers.get && headers.get('content-type') || '').slice(0, 120),
    contentLength: String(headers && headers.get && headers.get('content-length') || '').slice(0, 32),
    upstreamRequestId: String(headers && headers.get && headers.get('x-dirac-request-id') || '').slice(0, 100),
    upstreamCentralGuard: String(headers && headers.get && headers.get('x-dirac-central-security-guard') || '').slice(0, 120),
    vercelId: String(headers && headers.get && headers.get('x-vercel-id') || '').slice(0, 160),
    setCookieNames,
    body: {
      kind: objectData ? 'object' : Array.isArray(data) ? 'array' : data === null ? 'null' : typeof data,
      keys: objectData ? Object.keys(objectData).sort().slice(0, 40) : [],
      ok: objectData ? objectData.ok === true : false,
      code: objectData ? String(objectData.code || '').slice(0, 120) : '',
      message: objectData ? supportSafeDiagnosticMessageV356({ message: objectData.message || '' }) : '',
      requestId: objectData ? String(objectData.requestId || objectData.request_id || '').slice(0, 100) : '',
      userPresent: Boolean(user),
      userIdShapeOk: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(String(user && user.id || '').trim().toLowerCase()),
      userEmailShapeOk: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(user && user.email || '').trim().toLowerCase())
    }
  };
}

async function resolveMainIdentity(req, res, required) {
  const route = mainIdentityRoute(req); const cookieHeader = mainCookieHeader(req, route);
  const diagnosticEnabledV360 = String(req && req.diracSupportAction || '').trim().toLowerCase() === 'chat_public_config';
  const identityHeadersV360 = cookieHeader ? mainIdentityHeaders(req, cookieHeader) : {};
  const identityDiagnosticV360 = diagnosticEnabledV360 ? mainIdentityDiagnosticV360(req, route, cookieHeader, identityHeadersV360) : null;
  if (identityDiagnosticV360) req.__diracSupportMainIdentityDiagnosticV360 = identityDiagnosticV360;
  if (!cookieHeader) {
    if (identityDiagnosticV360) { identityDiagnosticV360.phase = 'no_cookie'; identityDiagnosticV360.decision = required ? 'main_login_required' : 'anonymous'; }
    clearCookie(res, CUSTOMER_COOKIE, 'Strict');
    if (required) throw new PublicError(401, 'MAIN_LOGIN_REQUIRED', 'Silakan masuk ke akun Dirac terlebih dahulu.');
    return null;
  }
  let result;
  try {
    if (identityDiagnosticV360) { identityDiagnosticV360.phase = 'before_fetch'; identityDiagnosticV360.egress.authorized = supportCentralAuthorizeHealthEgressV355(route.endpoint, { method: 'GET', headers: identityHeadersV360 }); }
    result = await fetchJson(route.endpoint, {
      method: 'GET',
      headers: identityHeadersV360
    }, 9000);
    if (identityDiagnosticV360) { identityDiagnosticV360.phase = 'after_fetch'; identityDiagnosticV360.response = mainIdentityResponseDiagnosticV360(result); }
  } catch (_) {
    if (identityDiagnosticV360) {
      identityDiagnosticV360.phase = 'fetch_error';
      identityDiagnosticV360.decision = 'main_identity_unavailable';
      identityDiagnosticV360.fetchError = { name: String(_ && _.name || '').slice(0, 80), code: String(_ && _.code || '').slice(0, 120), status: Number(_ && _.status || 0), message: supportSafeDiagnosticMessageV356(_) };
    }
    throw new PublicError(502, 'MAIN_IDENTITY_UNAVAILABLE', 'Sesi akun Dirac belum dapat diverifikasi.');
  }
  forwardMainCookies(res, result.headers, route);
  if (result.status === 401 || result.status === 403) {
    if (identityDiagnosticV360) identityDiagnosticV360.decision = required ? 'main_login_required' : 'anonymous_upstream_auth_rejected';
    clearCookie(res, CUSTOMER_COOKIE, 'Strict');
    if (required) throw new PublicError(401, 'MAIN_LOGIN_REQUIRED', 'Sesi akun Dirac tidak ditemukan atau sudah berakhir.');
    return null;
  }
  if (!result.ok) {
    if (identityDiagnosticV360) identityDiagnosticV360.decision = 'upstream_non_2xx_mapped_to_502';
    throw new PublicError(502, 'MAIN_IDENTITY_UNAVAILABLE', 'Sesi akun Dirac belum dapat diverifikasi.');
  }
  const user = result.data && result.data.ok === true && result.data.user && typeof result.data.user === 'object' ? result.data.user : null;
  const userId = String(user && user.id || '').trim().toLowerCase();
  const userEmail = String(user && user.email || '').trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(userId)
      || userEmail.length > 254
      || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userEmail)) {
    if (identityDiagnosticV360) identityDiagnosticV360.decision = 'upstream_2xx_identity_invalid';
    throw new PublicError(502, 'MAIN_IDENTITY_INVALID', 'Identitas akun Dirac tidak valid.');
  }
  if (identityDiagnosticV360) identityDiagnosticV360.decision = 'identity_valid';
  const context = supportCentralCurrentContextV146();
  if (context) context.verifiedCustomerId = userId;
  return { id: userId, email: userEmail, displayName: mainDisplayName(userEmail) };
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
    const encoded = String(value || '');
    const packed = Buffer.from(encoded, 'base64url');
    if (packed.toString('base64url') !== encoded) return null;
    if (packed.length < 29 || packed.length > 7000) return null;
    const nonce = packed.subarray(0, 12); const tag = packed.subarray(12, 28); const ciphertext = packed.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey(), nonce, { authTagLength: 16 });
    decipher.setAAD(Buffer.from(name, 'utf8')); decipher.setAuthTag(tag);
    const payload = parseStrictJson(Buffer.concat([decipher.update(ciphertext), decipher.final()]), { maxBytes: 7000 });
    if (!payload || payload.v !== 1 || !Number.isSafeInteger(payload.exp) || payload.exp <= Date.now()) return null;
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

function supportCsrfScopeV356(action) {
  const clean = String(action || '');
  if (clean === 'chat_public_config' || clean === 'chat_start') return 'chat_start';
  if (clean === 'admin_public_config' || clean === 'admin_login') return 'admin_login';
  if (clean === 'admin_mfa_verify') return 'admin_mfa_verify';
  if (['chat_bootstrap', 'chat_send', 'chat_close', 'customer_access_refresh'].includes(clean)) return 'customer_mutation';
  if (['admin_bootstrap', 'admin_send', 'admin_conversation_update', 'admin_component_update', 'admin_monitor_config_update', 'admin_incident_create', 'admin_incident_advance', 'admin_maintenance_create', 'admin_logout'].includes(clean)) return 'admin_mutation';
  return 'public';
}

function supportCsrfSessionBindingV356(req, action, explicitSession) {
  let session = explicitSession;
  if (session === undefined) {
    if (String(action || '') === 'admin_mfa_verify') session = readSession(req, MFA_COOKIE);
    else if (String(action || '').startsWith('admin_') && String(action || '') !== 'admin_login' && String(action || '') !== 'admin_public_config') session = readSession(req, ADMIN_COOKIE);
    else if (['chat_bootstrap', 'chat_send', 'chat_close', 'customer_access_refresh'].includes(String(action || ''))) session = readSession(req, CUSTOMER_COOKIE);
    else if (String(action || '') === 'chat_start' || String(action || '') === 'chat_public_config') session = readSession(req, CUSTOMER_COOKIE) || null;
    else if (String(action || '') === 'admin_public_config') session = null;
    else session = null;
  }
  if (!session || typeof session !== 'object') return 'public';
  if (session.kind === 'admin' && session.uid && session.sessionId) return 'admin|' + String(session.uid) + '|' + String(session.sessionId) + '|' + String(session.sessionVersion || 0) + '|' + String(session.iat || 0);
  if (session.kind === 'admin_mfa' && session.uid && session.challengeId) return 'admin_mfa|' + String(session.uid) + '|' + String(session.challengeId);
  if (session.kind === 'customer' && session.uid && session.mainUid) return 'customer|' + String(session.uid) + '|' + String(session.mainUid) + '|' + String(session.iat || 0);
  return 'public';
}

function csrfBundle(req, res, options = {}) {
  const cookies = parseCookies(req); const cookieName = runtimeCookieName(CSRF_COOKIE);
  let seed = options.rotate === true ? '' : String(cookies[cookieName] || '');
  if (!/^[A-Za-z0-9_-]{32,96}$/.test(seed)) seed = b64u(crypto.randomBytes(32));
  appendCookie(res, cookieString(CSRF_COOKIE, seed, { maxAge: Math.ceil(SUPPORT_CSRF_TTL_MS_V356 / 1000), sameSite: 'Strict' }));
  const action = String(options.action || queryValue(req, 'action') || '');
  const scope = String(options.scope || supportCsrfScopeV356(action));
  const origin = requestOrigin(req);
  if (!origin || !allowedOrigins().has(origin)) throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin permintaan tidak diizinkan.');
  const binding = supportCsrfSessionBindingV356(req, action, Object.prototype.hasOwnProperty.call(options, 'session') ? options.session : undefined);
  const exp = Date.now() + SUPPORT_CSRF_TTL_MS_V356;
  const material = SUPPORT_CSRF_VERSION_V356 + '|' + seed + '|' + exp + '|' + scope + '|POST|' + origin + '|' + binding;
  return String(exp) + '.' + hmac(config().csrfSecret, material);
}

function verifyCsrf(req) {
  if (!originAllowed(req)) throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin permintaan tidak diizinkan.');
  const fetchSite = String(req.headers && req.headers['sec-fetch-site'] || '').toLowerCase();
  if (fetchSite && !['same-origin', 'same-site', 'none'].includes(fetchSite)) throw new PublicError(403, 'FETCH_SITE_REJECTED', 'Konteks browser tidak diizinkan.');
  const token = String(req.headers && req.headers['x-dirac-csrf'] || '');
  const match = /^(\d{13})\.([A-Za-z0-9_-]{43})$/.exec(token);
  const exp = match ? Number(match[1]) : 0;
  if (!match || exp <= Date.now() || exp > Date.now() + SUPPORT_CSRF_TTL_MS_V356 + 60_000) throw new PublicError(403, 'CSRF_INVALID', 'Token keamanan halaman tidak valid atau kedaluwarsa.');
  const cookies = parseCookies(req); const seed = String(cookies[runtimeCookieName(CSRF_COOKIE)] || '');
  const action = queryValue(req, 'action'); const scope = supportCsrfScopeV356(action); const origin = requestOrigin(req);
  const binding = supportCsrfSessionBindingV356(req, action);
  const material = SUPPORT_CSRF_VERSION_V356 + '|' + seed + '|' + match[1] + '|' + scope + '|POST|' + origin + '|' + binding;
  const expected = hmac(config().csrfSecret, material);
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
  const type = String(req.headers && req.headers['content-type'] || '').trim().toLowerCase();
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/.test(type)) throw new PublicError(415, 'CONTENT_TYPE_INVALID', 'Content-Type wajib application/json UTF-8.');
  if (String(req.headers && req.headers['transfer-encoding'] || '').trim()) throw new PublicError(400, 'TRANSFER_ENCODING_REJECTED', 'Framing request tidak diizinkan.');
  const encoding = String(req.headers && req.headers['content-encoding'] || '').trim().toLowerCase();
  if (encoding && encoding !== 'identity') throw new PublicError(415, 'CONTENT_ENCODING_REJECTED', 'Content-Encoding request tidak diizinkan.');
  const declared = String(req.headers && req.headers['content-length'] || '').trim();
  if (declared && !/^(?:0|[1-9][0-9]{0,11})$/.test(declared)) throw new PublicError(400, 'CONTENT_LENGTH_INVALID', 'Content-Length request tidak valid.');
  if (declared && Number(declared) > MAX_BODY_BYTES) throw new PublicError(413, 'BODY_TOO_LARGE', 'Ukuran request melebihi batas.');
  let raw = Buffer.isBuffer(req.rawBody) || typeof req.rawBody === 'string' ? req.rawBody : req.body;
  if (raw !== undefined && raw !== null && !Buffer.isBuffer(raw) && typeof raw !== 'string') throw new PublicError(400, 'RAW_BODY_REQUIRED', 'Request wajib mempertahankan JSON asli.');
  if (raw === undefined || raw === null) {
    const chunks = []; let total = 0;
    for await (const chunk of req) {
      const bytes = Buffer.from(chunk); total += bytes.length;
      if (total > MAX_BODY_BYTES) throw new PublicError(413, 'BODY_TOO_LARGE', 'Ukuran request melebihi batas.');
      chunks.push(bytes);
    }
    raw = Buffer.concat(chunks, total);
  }
  const size = Buffer.byteLength(raw);
  if (size > MAX_BODY_BYTES) throw new PublicError(413, 'BODY_TOO_LARGE', 'Ukuran request melebihi batas.');
  if (declared && size !== Number(declared)) throw new PublicError(400, 'CONTENT_LENGTH_MISMATCH', 'Framing request tidak cocok.');
  try { return parseStrictJson(raw, { maxBytes: MAX_BODY_BYTES, maxDepth: 8, maxNodes: 512 }); }
  catch (_) { throw new PublicError(400, 'JSON_INVALID', 'JSON request tidak valid.'); }
}

function exactKeys(body, allowed) {
  if (!body || Object.getPrototypeOf(body) !== Object.prototype) throw new PublicError(400, 'BODY_INVALID', 'Bentuk request tidak valid.');
  const unknown = Object.keys(body).filter((key) => !allowed.includes(key));
  if (unknown.length) throw new PublicError(400, 'FIELDS_UNKNOWN', 'Request memuat field yang tidak diizinkan.');
}

function text(value, min, max, label) {
  if (typeof value !== 'string' || !validUnicode(value)) throw new PublicError(400, 'TEXT_INVALID', (label || 'Teks') + ' tidak valid.');
  const normalized = value.normalize('NFC').trim();
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
  // The URL is the sole query representation used by guard and handlers.
  try { return new URL(req.url, 'https://local.invalid').searchParams.get(name) || ''; } catch (_) { return ''; }
}

function clientIp(req) { return securityProxy.trustedClientIp(req, process.env); }

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
    if (Array.isArray(req.query[name]) || typeof req.query[name] !== 'string' || req.query[name] !== queryValue(req, name) || !seen.has(name)) throw new PublicError(400, 'QUERY_REPRESENTATION_MISMATCH', 'Representasi parameter URL tidak cocok.');
  }
}

async function fetchJson(url, options, timeoutMs) {
  if (!supportCentralAuthorizeHealthEgressV355(url, options)) {
    throw new PublicError(500, 'CENTRAL_EGRESS_CONTEXT_REQUIRED', 'Konteks keamanan egress tidak tersedia.');
  }
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs || 8000);
  try {
    const requestOptions = Object.assign({}, options, { signal: controller.signal, redirect: 'error' });
    const broker = DIRAC_SUPPORT_HEALTH_EGRESS_BROKER_V355;
    if (!broker || broker.version !== 'dirac-central-support-egress-broker-v355' || typeof broker.fetch !== 'function') {
      throw new PublicError(503, 'CENTRAL_EGRESS_BROKER_REQUIRED', 'Broker egress pusat untuk support tidak tersedia.');
    }
    const response = await broker.fetch(url, requestOptions);
    const maxBytes = 2 * 1024 * 1024;
    const declared = Number(response.headers.get('content-length') || 0);
    if (Number.isFinite(declared) && declared > maxBytes) {
      try { if (response.body && typeof response.body.cancel === 'function') Promise.resolve(response.body.cancel()).catch(() => {}); } catch (_) {}
      throw new PublicError(502, 'UPSTREAM_RESPONSE_TOO_LARGE', 'Respons upstream terlalu besar.');
    }
    const chunks = []; let total = 0;
    if (response.body && typeof response.body.getReader === 'function') {
      const reader = response.body.getReader();
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          const chunk = Buffer.from(part.value);
          total += chunk.length;
          if (total > maxBytes) {
            try { Promise.resolve(reader.cancel()).catch(() => {}); } catch (_) {}
            throw new PublicError(502, 'UPSTREAM_RESPONSE_TOO_LARGE', 'Respons upstream terlalu besar.');
          }
          chunks.push(chunk);
        }
      } finally { reader.releaseLock(); }
    }
    const raw = Buffer.concat(chunks, total).toString('utf8');
    let data = null; try { data = raw ? JSON.parse(raw) : null; } catch (_) { data = raw; }
    return { ok: response.ok, status: response.status, data, headers: response.headers };
  } catch (error) {
    if (error instanceof PublicError) throw error;
    throw new PublicError(502, error && error.name === 'AbortError' ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_UNAVAILABLE', 'Layanan data support belum dapat dihubungi.');
  } finally { clearTimeout(timer); }
}

function supportAssertDatabaseOperationV361(path, settings) {
  const ctx = supportCentralCurrentContextV146();
  if (!ctx || (!ctx.fullyPassed && ctx.currentStage !== 'rate limit')) throw new PublicError(503, 'SUPPORT_DB_CONTEXT_REQUIRED', 'Konteks database tidak tersedia.');
  const url = new URL('https://support.invalid' + path);
  if (url.pathname + url.search !== path || url.hash || /%(?:2f|5c|2e)/i.test(url.pathname)) throw new PublicError(503, 'SUPPORT_DB_PATH_REJECTED', 'Target database tidak valid.');
  const method = String(settings.method || 'GET');
  const rpcActions = {
    support_take_rate_limit: DIRAC_SUPPORT_CENTRAL_EXPECTED_ACTIONS_V146,
    support_auth_audit: ['admin_login', 'admin_mfa_verify', 'admin_logout'],
    support_status_snapshot: ['status_bootstrap', 'admin_login', 'admin_mfa_verify', 'admin_bootstrap', 'admin_status_snapshot'],
    support_chat_open: ['chat_start'], support_chat_send: ['chat_send', 'admin_send'], support_chat_close: ['chat_close'],
    support_admin_queue: ['admin_login', 'admin_mfa_verify', 'admin_bootstrap', 'admin_queue'],
    support_admin_thread: ['admin_thread'], support_admin_conversation_update: ['admin_conversation_update'],
    support_status_component_set: ['admin_component_update'], support_monitor_config_set: ['admin_monitor_config_update'],
    support_incident_create: ['admin_incident_create'], support_incident_advance: ['admin_incident_advance'],
    support_maintenance_create: ['admin_maintenance_create'],
    support_monitor_targets: ['monitor_run'], support_monitor_record: ['monitor_run']
  };
  if (url.pathname.startsWith('/rest/v1/rpc/')) {
    const name = url.pathname.slice('/rest/v1/rpc/'.length);
    if (method !== 'POST' || url.search || !rpcActions[name] || !rpcActions[name].includes(ctx.action)) throw new PublicError(503, 'SUPPORT_DB_RPC_REJECTED', 'Operasi database tidak diizinkan.');
    const body = settings.body || {};
    if (body.p_admin_user_id !== undefined && (!ctx.verifiedAdminId || body.p_admin_user_id !== ctx.verifiedAdminId)) throw new PublicError(403, 'SUPPORT_DB_ADMIN_REQUIRED', 'Identitas admin belum diverifikasi.');
    if (body.p_customer_user_id !== undefined && (!ctx.verifiedCustomerId || body.p_customer_user_id !== ctx.verifiedCustomerId)) throw new PublicError(403, 'SUPPORT_DB_OWNER_REQUIRED', 'Pemilik belum diverifikasi.');
    if (name === 'support_status_snapshot' && body.p_admin === true && !ctx.verifiedAdminId) throw new PublicError(403, 'SUPPORT_DB_ADMIN_REQUIRED', 'Identitas admin belum diverifikasi.');
    if (name === 'support_chat_send') {
      const expectedId = body.p_sender_kind === 'customer' ? ctx.verifiedCustomerId : body.p_sender_kind === 'admin' ? ctx.verifiedAdminId : '';
      if (!expectedId || body.p_sender_user_id !== expectedId || body.p_conversation_id !== String(ctx.body && ctx.body.conversationId || '')) throw new PublicError(403, 'SUPPORT_DB_OWNER_REQUIRED', 'Pemilik belum diverifikasi.');
    }
    return;
  }
  if (method !== 'GET' || !['/rest/v1/support_staff', '/rest/v1/support_chat_sessions', '/rest/v1/support_chat_messages'].includes(url.pathname)) throw new PublicError(503, 'SUPPORT_DB_TABLE_REJECTED', 'Operasi database tidak diizinkan.');
  if (url.pathname === '/rest/v1/support_staff') {
    const expected = ctx.verifiedCustomerId || config().primaryAdminUserId;
    if (!expected || url.searchParams.get('user_id') !== 'eq.' + expected) throw new PublicError(403, 'SUPPORT_DB_OWNER_REQUIRED', 'Pemilik belum diverifikasi.');
  } else if (!ctx.verifiedAdminId && !ctx.verifiedCustomerId) throw new PublicError(403, 'SUPPORT_DB_OWNER_REQUIRED', 'Pemilik belum diverifikasi.');
  else if (url.pathname === '/rest/v1/support_chat_sessions' && !ctx.verifiedAdminId && url.searchParams.get('customer_user_id') !== 'eq.' + ctx.verifiedCustomerId) throw new PublicError(403, 'SUPPORT_DB_OWNER_REQUIRED', 'Pemilik belum diverifikasi.');
  if (url.pathname === '/rest/v1/support_chat_messages' && !ctx.verifiedAdminId) {
    const conversationId = String(url.searchParams.get('conversation_id') || '').slice(3);
    if (!ctx.authorizedConversations || !ctx.authorizedConversations.has(conversationId)) throw new PublicError(403, 'SUPPORT_DB_RESOURCE_REQUIRED', 'Percakapan belum diverifikasi.');
  }
}

async function supabase(path, options) {
  supportAssertDatabaseOperationV361(path, options || {});
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


async function supportAuthAdmin(path, options) {
  if (!/^\/admin\/users(?:\/[0-9a-f-]{36})?$/.test(String(path || ''))) throw new PublicError(500, 'SUPPORT_AUTH_ADMIN_PATH_INVALID', 'Path administrasi Auth tidak valid.');
  const cfg = config(); const settings = options || {};
  const context = supportCentralCurrentContextV146();
  if (!context || context.action !== 'chat_start' || !context.verifiedCustomerId
      || (path !== '/admin/users' && path !== '/admin/users/' + context.verifiedCustomerId)
      || (settings.body && (settings.body.email !== supportCustomerMaterial({ id: context.verifiedCustomerId }).email
          || (settings.body.id !== undefined && settings.body.id !== context.verifiedCustomerId)))) throw new PublicError(403, 'SUPPORT_IDENTITY_SCOPE_INVALID', 'Pemetaan identitas tidak diizinkan.');
  const headers = { apikey: cfg.secretKey, Accept: 'application/json' };
  if (decodeJwt(cfg.secretKey).role === 'service_role') headers.Authorization = 'Bearer ' + cfg.secretKey;
  if (settings.body !== undefined) headers['Content-Type'] = 'application/json';
  return fetchJson(cfg.supabaseUrl + '/auth/v1' + path, {
    method: settings.method || 'GET',
    headers,
    body: settings.body === undefined ? undefined : JSON.stringify(settings.body)
  }, 9000);
}

function supportAuthUser(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const value = data.user && typeof data.user === 'object' ? data.user : data;
  return value && value.id ? value : null;
}

function supportCustomerMaterial(identity) {
  const userId = id(identity && identity.id, 'Main user ID'); const cfg = config();
  const passwordDigest = crypto.createHmac('sha512', cfg.cookieSecret).update('support-customer-password:v1|' + userId, 'utf8').digest('base64url');
  const versionDigest = crypto.createHmac('sha512', cfg.cookieSecret).update('support-customer-version:v1|' + userId, 'utf8').digest('hex').slice(0, 20);
  const authEmail = 'customer.' + userId.replace(/-/g, '') + '@' + CUSTOMER_AUTH_EMAIL_DOMAIN;
  const passwordVersion = 'v1.' + versionDigest;
  return {
    userId,
    email: authEmail,
    password: 'Dg!8-' + passwordDigest.slice(0, 58),
    passwordVersion,
    appMetadata: {
      provider: 'email',
      providers: ['email'],
      dirac_support_customer: true,
      dirac_support_identity: CUSTOMER_IDENTITY_MARKER,
      dirac_main_user_id: userId,
      dirac_support_password_version: passwordVersion
    },
    userMetadata: { source: 'dirac_main_session' }
  };
}

function authAppMetadata(user) {
  if (!user || typeof user !== 'object') return {};
  if (user.app_metadata && typeof user.app_metadata === 'object') return user.app_metadata;
  if (user.raw_app_meta_data && typeof user.raw_app_meta_data === 'object') return user.raw_app_meta_data;
  return {};
}

function audAuthenticated(value) {
  if (Array.isArray(value)) return value.includes('authenticated');
  return String(value || '') === 'authenticated';
}

function supportProviderUserAllowed(user) {
  if (!user || typeof user !== 'object' || Array.isArray(user)) return false;
  const ban = user.banned_until;
  const banTime = ban === undefined || ban === null || ban === '' ? 0 : Date.parse(String(ban));
  const emailConfirmed = Date.parse(String(user.email_confirmed_at || ''));
  return (user.email_verified === true || (Number.isFinite(emailConfirmed) && emailConfirmed <= Date.now()))
    && !user.deleted_at && !user.disabled_at && user.disabled !== true && user.is_disabled !== true
    && user.is_anonymous !== true && Number.isFinite(banTime) && banTime <= Date.now();
}

function supportProviderClaims(authSession) {
  // Call only on the authenticated provider response, never a request bearer.
  const token = String(authSession && authSession.access_token || '');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part)) || token.length > 16000) throw new PublicError(401, 'AUTH_PROVIDER_TOKEN_INVALID', 'Sesi Auth tidak valid.');
  let header, claims;
  try { header = parseStrictJson(Buffer.from(parts[0], 'base64url')); claims = parseStrictJson(Buffer.from(parts[1], 'base64url')); }
  catch (_) { throw new PublicError(401, 'AUTH_PROVIDER_TOKEN_INVALID', 'Sesi Auth tidak valid.'); }
  const now = Math.floor(Date.now() / 1000);
  if (!['HS256', 'RS256', 'ES256'].includes(header.alg) || header.crit !== undefined
      || !claims || !supportCentralCanonicalUuidV146(claims.sub) || claims.role !== 'authenticated'
      || !audAuthenticated(claims.aud) || claims.iss !== config().supabaseUrl + '/auth/v1'
      || !Number.isSafeInteger(claims.exp) || claims.exp <= now
      || !Number.isSafeInteger(claims.iat) || claims.iat > now + 30 || claims.exp <= claims.iat
      || (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > now))) {
    throw new PublicError(401, 'AUTH_PROVIDER_TOKEN_INVALID', 'Sesi Auth tidak valid.');
  }
  return claims;
}

function verifySupportCustomerCore(user, material) {
  const metadata = authAppMetadata(user); const bannedUntil = Date.parse(String(user && user.banned_until || ''));
  if (!supportProviderUserAllowed(user)
      || String(user.id || '').toLowerCase() !== material.userId
      || String(user.email || '').toLowerCase() !== material.email
      || user.is_anonymous === true
      || Boolean(user.deleted_at)
      || (Number.isFinite(bannedUntil) && bannedUntil > Date.now())
      || metadata.provider !== 'email'
      || !Array.isArray(metadata.providers)
      || !metadata.providers.includes('email')
      || metadata.dirac_support_customer !== true
      || metadata.dirac_support_identity !== CUSTOMER_IDENTITY_MARKER
      || String(metadata.dirac_main_user_id || '').toLowerCase() !== material.userId) {
    throw new PublicError(409, 'SUPPORT_IDENTITY_COLLISION', 'Pemetaan akun support tidak aman untuk digunakan.');
  }
  return metadata;
}

async function rejectStaffCollision(userId) {
  const result = await supabase('/rest/v1/support_staff?select=user_id&user_id=eq.' + encodeURIComponent(userId) + '&limit=1', {});
  if (Array.isArray(result.data) && result.data.length) throw new PublicError(409, 'SUPPORT_IDENTITY_COLLISION', 'Identitas akun bertabrakan dengan akun staff support.');
}

async function supportCustomerById(userId) {
  const result = await supportAuthAdmin('/admin/users/' + userId, { method: 'GET' });
  if (result.status === 404) return null;
  if (!result.ok) throw new PublicError(503, 'SUPPORT_IDENTITY_LOOKUP_FAILED', 'Akun support terhubung belum dapat diperiksa.');
  return supportAuthUser(result.data);
}

function verifySupportAuthSession(authSession, material) {
  if (!authSession || !authSession.access_token || !authSession.refresh_token || !authSession.user) throw new PublicError(503, 'SUPPORT_IDENTITY_LOGIN_FAILED', 'Sesi support terhubung belum dapat diterbitkan.');
  const metadata = verifySupportCustomerCore(authSession.user, material); const claims = supportProviderClaims(authSession); const claimMetadata = claims.app_metadata && typeof claims.app_metadata === 'object' ? claims.app_metadata : {};
  if (String(claims.sub || '').toLowerCase() !== material.userId
      || String(claims.role || '') !== 'authenticated'
      || !audAuthenticated(claims.aud)
      || String(metadata.dirac_support_password_version || '') !== material.passwordVersion
      || claimMetadata.dirac_support_customer !== true
      || claimMetadata.dirac_support_identity !== CUSTOMER_IDENTITY_MARKER
      || String(claimMetadata.dirac_main_user_id || '').toLowerCase() !== material.userId
      || String(claimMetadata.dirac_support_password_version || '') !== material.passwordVersion) {
    throw new PublicError(409, 'SUPPORT_IDENTITY_COLLISION', 'Token akun support tidak cocok dengan identitas utama.');
  }
  return authSession;
}

async function signInSupportCustomer(material, turnstileToken) {
  const token = text(turnstileToken === undefined ? '' : turnstileToken, config().turnstileRequired ? 10 : 0, 4096, 'Token Turnstile');
  const body = { email: material.email, password: material.password };
  if (token) body.gotrue_meta_security = { captcha_token: token };
  const result = await auth('/token?grant_type=password', { body });
  if (!result.ok) throw new PublicError(503, 'SUPPORT_IDENTITY_LOGIN_FAILED', 'Sesi support terhubung belum dapat diterbitkan.');
  return verifySupportAuthSession(result.data, material);
}

async function provisionSupportCustomer(identity, turnstileToken) {
  const material = supportCustomerMaterial(identity); await rejectStaffCollision(material.userId);
  let user = await supportCustomerById(material.userId);
  let createdWithCurrentMaterial = false;
  if (!user) {
    const created = await supportAuthAdmin('/admin/users', {
      method: 'POST',
      body: {
        id: material.userId,
        email: material.email,
        password: material.password,
        email_confirm: true,
        app_metadata: material.appMetadata,
        user_metadata: material.userMetadata
      }
    });
    if (created.ok) {
      user = supportAuthUser(created.data);
      const appMetadata = authAppMetadata(user);
      const userMetadata = user && user.user_metadata || {};
      createdWithCurrentMaterial = Object.entries(material.appMetadata).every(([key, value]) => JSON.stringify(appMetadata[key]) === JSON.stringify(value))
        && Object.entries(material.userMetadata).every(([key, value]) => JSON.stringify(userMetadata[key]) === JSON.stringify(value));
    }
    else if ([409, 422].includes(created.status)) user = await supportCustomerById(material.userId);
    else throw new PublicError(503, 'SUPPORT_IDENTITY_CREATE_FAILED', 'Akun support terhubung belum dapat dibuat.');
  }
  if (!user) throw new PublicError(409, 'SUPPORT_IDENTITY_COLLISION', 'Pemetaan akun support sudah digunakan oleh identitas lain.');
  verifySupportCustomerCore(user, material);
  // A successful create already wrote this exact credential material. Existing
  // accounts still resynchronize, and every path performs a fresh Auth login.
  if (!createdWithCurrentMaterial) {
    const updated = await supportAuthAdmin('/admin/users/' + material.userId, {
      method: 'PUT',
      body: {
        email: material.email,
        password: material.password,
        email_confirm: true,
        app_metadata: material.appMetadata,
        user_metadata: material.userMetadata
      }
    });
    if (!updated.ok) throw new PublicError(503, 'SUPPORT_IDENTITY_UPDATE_FAILED', 'Akun support terhubung belum dapat disinkronkan.');
    const updatedUser = supportAuthUser(updated.data) || await supportCustomerById(material.userId);
    verifySupportCustomerCore(updatedUser, material);
  }
  await rejectStaffCollision(material.userId);
  return signInSupportCustomer(material, turnstileToken);
}

function customerSessionMatches(session, identity) {
  return Boolean(session
    && session.v === 1
    && session.kind === 'customer'
    && session.uid === identity.id
    && session.mainUid === identity.id
    && session.refreshToken);
}

function decodeJwt(token) {
  try { return JSON.parse(Buffer.from(String(token || '').split('.')[1], 'base64url').toString('utf8')); } catch (_) { return {}; }
}

async function refreshAuth(refreshToken) {
  const result = await auth('/token?grant_type=refresh_token', { body: { refresh_token: refreshToken } });
  if (!result.ok || !result.data || !result.data.access_token || !result.data.refresh_token || !result.data.user) throw new PublicError(401, 'SESSION_REFRESH_FAILED', 'Sesi sudah berakhir. Silakan masuk kembali.');
  if (!supportProviderUserAllowed(result.data.user)) throw new PublicError(403, 'AUTH_ACCOUNT_BLOCKED', 'Akun tidak diizinkan.');
  supportProviderClaims(result.data);
  return result.data;
}

async function refreshCustomerAuth(res, session, identity) {
  try {
    if (!customerSessionMatches(session, identity)) throw new PublicError(401, 'CUSTOMER_IDENTITY_MISMATCH', 'Sesi chat tidak sesuai dengan akun Dirac yang sedang masuk.');
    const refreshed = await refreshAuth(session.refreshToken); const material = supportCustomerMaterial(identity);
    return verifySupportAuthSession(refreshed, material);
  } catch (error) {
    clearCookie(res, CUSTOMER_COOKIE, 'Strict');
    throw error;
  }
}

async function staffByUser(userId) {
  const result = await supabase('/rest/v1/support_staff?select=user_id,email,display_name,role,is_active,mfa_required,session_version&user_id=eq.' + encodeURIComponent(userId) + '&limit=2', {});
  const rows = Array.isArray(result.data) ? result.data : [];
  if (rows.length !== 1 || rows[0].is_active !== true) throw new PublicError(403, 'STAFF_NOT_ALLOWED', 'Akun ini tidak memiliki akses staff aktif.');
  return requirePinnedPrimaryAdmin(rows[0]);
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
  { // Recheck the provider on every privileged read or mutation, including logout revocation.
    authSession = await refreshAuth(session.refreshToken);
    const claims = supportProviderClaims(authSession);
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
  const context = supportCentralCurrentContextV146();
  if (context) context.verifiedAdminId = staff.user_id;
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
  const cfg = config(); const identity = await resolveMainIdentity(req, res, false); const session = readSession(req, CUSTOMER_COOKIE);
  const hasSession = Boolean(identity && customerSessionMatches(session, identity));
  if (session && !hasSession) clearCookie(res, CUSTOMER_COOKIE, 'Strict');
  return json(res, 200, {
    ok: true,
    code: 'CHAT_CONFIG_OK',
    csrfToken: csrfBundle(req, res, { session: hasSession ? session : null, scope: hasSession ? 'customer_mutation' : 'chat_start' }),
    authenticated: Boolean(identity),
    user: identity ? { displayName: identity.displayName, email: identity.email } : null,
    hasSession,
    turnstileRequired: cfg.turnstileRequired,
    turnstileSiteKey: cfg.turnstileRequired ? cfg.turnstileSiteKey : ''
  });
}

async function actionAdminPublicConfig(req, res) {
  const cfg = config(); const session = readSession(req, ADMIN_COOKIE); const hasSession = Boolean(session && session.kind === 'admin');
  return json(res, 200, { ok: true, code: 'ADMIN_CONFIG_OK', csrfToken: csrfBundle(req, res, { session: hasSession ? session : null, scope: hasSession ? 'admin_mutation' : 'admin_login' }), hasSession, mfaRequired: cfg.adminMfaRequired, turnstileRequired: cfg.turnstileRequired, turnstileSiteKey: cfg.turnstileRequired ? cfg.turnstileSiteKey : '' });
}

async function findActiveConversation(userId) {
  const path = '/rest/v1/support_chat_sessions?select=id,public_code,customer_name,customer_email,category,subject,status,priority,assigned_to,created_at,updated_at,last_message_at,revision&customer_user_id=eq.' + encodeURIComponent(userId) + '&status=in.(' + ACTIVE_CHAT_STATES.join(',') + ')&expires_at=gt.' + encodeURIComponent(nowIso()) + '&order=last_message_at.desc.nullslast&limit=1';
  const result = await supabase(path, {}); const conversation = Array.isArray(result.data) && result.data[0] ? result.data[0] : null;
  if (conversation) supportRememberConversationV361(conversation.id);
  return conversation;
}

function supportRememberConversationV361(conversationId) {
  const context = supportCentralCurrentContextV146();
  if (!context || !context.verifiedCustomerId || !supportCentralCanonicalUuidV146(conversationId)) throw new PublicError(503, 'SUPPORT_CONVERSATION_INVALID', 'Identitas percakapan tidak valid.');
  if (!context.authorizedConversations) context.authorizedConversations = new Set();
  context.authorizedConversations.add(conversationId);
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
  const identity = await resolveMainIdentity(req, res, true); const session = readSession(req, CUSTOMER_COOKIE);
  if (!customerSessionMatches(session, identity)) {
    clearCookie(res, CUSTOMER_COOKIE, 'Strict');
    throw new PublicError(401, 'CUSTOMER_SESSION_REQUIRED', 'Sesi chat belum tersedia untuk akun Dirac ini.');
  }
  await accountRateLimit('chat_bootstrap_account', identity.id, 60, 60, 60);
  const refreshed = await refreshCustomerAuth(res, session, identity);
  const next = Object.assign({}, session, { mainEmail: identity.email, refreshToken: refreshed.refresh_token, exp: Date.now() + 180 * 24 * 60 * 60 * 1000 });
  writeSession(res, CUSTOMER_COOKIE, next, 180 * 24 * 60 * 60, 'Strict');
  const conversation = await findActiveConversation(identity.id);
  const after = Math.max(0, Number(queryValue(req, 'after_sequence') || 0));
  const messages = conversation ? await messagesForConversation(conversation.id, after, 50) : [];
  return json(res, 200, { ok: true, code: 'CHAT_BOOTSTRAP_OK', csrfToken: csrfBundle(req, res), conversation, messages, realtime: conversation ? chatRealtime(conversation.id, refreshed.access_token) : null });
}

async function actionChatStart(req, res, body) {
  exactKeys(body, ['category', 'subject', 'message', 'website', 'consent', 'turnstileToken']);
  if (String(body.website || '').trim()) throw new PublicError(400, 'AUTOMATION_REJECTED', 'Permintaan tidak valid.');
  if (body.consent !== true) throw new PublicError(400, 'CONSENT_REQUIRED', 'Persetujuan pemrosesan percakapan wajib diberikan.');
  await rateLimit(req, 'chat_start', 3, 600, 900, 'burst'); await rateLimit(req, 'chat_start_daily', 10, 86400, 3600, 'daily');
  await takeRateLimit('chat_start_global', hmac(config().ipSecret, 'chat|global|start', 'hex'), 5000, 86400, 3600);
  const identity = await resolveMainIdentity(req, res, true);
  const category = String(body.category || 'other'); if (!['technical', 'account', 'billing', 'domain', 'other'].includes(category)) throw new PublicError(400, 'CATEGORY_INVALID', 'Kategori chat tidak valid.');
  const subject = text(body.subject, 3, 120, 'Judul'); const initialMessage = messageText(body.message);
  const clientMessageId = idempotencyKey(req, '', 'Idempotency key chat');
  let session = readSession(req, CUSTOMER_COOKIE); let authSession = null;
  if (customerSessionMatches(session, identity)) {
    try { authSession = await refreshCustomerAuth(res, session, identity); }
    catch (error) { if (!(error instanceof PublicError) || error.status !== 401) throw error; session = null; }
    if (authSession) await verifyTurnstile(req, body.turnstileToken);
  } else if (session) {
    clearCookie(res, CUSTOMER_COOKIE, 'Strict');
    session = null;
  }
  if (!authSession) authSession = await provisionSupportCustomer(identity, body.turnstileToken);
  const userId = identity.id; const existing = await findActiveConversation(userId);
  let result;
  if (existing) {
    result = { conversation: existing, messages: await messagesForConversation(existing.id, 0, 50) };
  } else {
    result = await rpc('support_chat_open', { p_customer_user_id: userId, p_customer_name: identity.displayName, p_customer_email: identity.email, p_category: category, p_subject: subject, p_body: initialMessage, p_client_message_id: clientMessageId });
    if (Array.isArray(result)) result = result[0];
  }
  if (!result || !result.conversation) throw new PublicError(500, 'CHAT_OPEN_FAILED', 'Percakapan belum dapat dibuka.');
  supportRememberConversationV361(result.conversation.id);
  session = { v: 1, kind: 'customer', uid: userId, mainUid: identity.id, mainEmail: identity.email, refreshToken: authSession.refresh_token, iat: Date.now(), exp: Date.now() + 180 * 24 * 60 * 60 * 1000 };
  writeSession(res, CUSTOMER_COOKIE, session, 180 * 24 * 60 * 60, 'Strict');
  const messages = Array.isArray(result.messages) ? result.messages : result.message ? [result.message] : await messagesForConversation(result.conversation.id, 0, 50);
  return json(res, 201, { ok: true, code: 'CHAT_OPENED', csrfToken: csrfBundle(req, res, { rotate: true, session, scope: 'customer_mutation' }), conversation: result.conversation, messages, realtime: chatRealtime(result.conversation.id, authSession.access_token) });
}

async function requireCustomer(req, res, conversationId) {
  const identity = await resolveMainIdentity(req, res, true); const session = readSession(req, CUSTOMER_COOKIE);
  if (!customerSessionMatches(session, identity)) {
    clearCookie(res, CUSTOMER_COOKIE, 'Strict');
    throw new PublicError(401, 'CUSTOMER_SESSION_REQUIRED', 'Sesi chat tidak ditemukan untuk akun Dirac ini.');
  }
  const refreshed = await refreshCustomerAuth(res, session, identity);
  const next = Object.assign({}, session, { mainEmail: identity.email, refreshToken: refreshed.refresh_token, exp: Date.now() + 180 * 24 * 60 * 60 * 1000 });
  writeSession(res, CUSTOMER_COOKIE, next, 180 * 24 * 60 * 60, 'Strict');
  const path = '/rest/v1/support_chat_sessions?select=id,customer_user_id,status,expires_at,message_count,revision&id=eq.' + encodeURIComponent(conversationId) + '&customer_user_id=eq.' + encodeURIComponent(identity.id) + '&limit=2';
  const result = await supabase(path, {}); const rows = Array.isArray(result.data) ? result.data : [];
  if (rows.length !== 1) throw new PublicError(404, 'CONVERSATION_NOT_FOUND', 'Percakapan tidak ditemukan.');
  if (rows[0].id !== conversationId || rows[0].customer_user_id !== identity.id) throw new PublicError(403, 'SUPPORT_DB_OWNER_REQUIRED', 'Pemilik belum diverifikasi.');
  supportRememberConversationV361(conversationId);
  if (rows[0].status === 'blocked') throw new PublicError(403, 'CONVERSATION_BLOCKED', 'Percakapan diblokir oleh sistem keamanan.');
  if (!rows[0].expires_at || !Number.isFinite(Date.parse(rows[0].expires_at)) || Date.parse(rows[0].expires_at) <= Date.now()) throw new PublicError(409, 'CONVERSATION_EXPIRED', 'Masa simpan percakapan telah berakhir. Silakan buka percakapan baru.');
  return { session: next, conversation: rows[0] };
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
  const identity = await resolveMainIdentity(req, res, true); const session = readSession(req, CUSTOMER_COOKIE);
  if (!customerSessionMatches(session, identity)) {
    clearCookie(res, CUSTOMER_COOKIE, 'Strict');
    throw new PublicError(401, 'CUSTOMER_SESSION_REQUIRED', 'Sesi chat sudah berakhir untuk akun Dirac ini.');
  }
  await accountRateLimit('customer_refresh', identity.id, 20, 600, 600);
  const refreshed = await refreshCustomerAuth(res, session, identity); const conversation = await findActiveConversation(identity.id);
  const next = Object.assign({}, session, { mainEmail: identity.email, refreshToken: refreshed.refresh_token, exp: Date.now() + 180 * 24 * 60 * 60 * 1000 }); writeSession(res, CUSTOMER_COOKIE, next, 180 * 24 * 60 * 60, 'Strict');
  return json(res, 200, { ok: true, code: 'CUSTOMER_ACCESS_REFRESHED', csrfToken: csrfBundle(req, res, { rotate: true, session: next, scope: 'customer_mutation' }), realtime: conversation ? chatRealtime(conversation.id, refreshed.access_token) : null });
}

async function issueAdminSession(res, authSession, staff, mfaAt) {
  const claims = supportProviderClaims(authSession); const sessionId = id(claims.session_id, 'Auth session ID');
  if (claims.aal !== 'aal2'
     || String(claims.sub || '') !== String(staff.user_id)
     || authSession.user && String(authSession.user.id || '') !== String(staff.user_id)) {
    throw new PublicError(403, 'MFA_ASSURANCE_INVALID', 'Identitas atau tingkat jaminan sesi admin tidak valid.');
  }
  const session = { v: 1, kind: 'admin', uid: staff.user_id, email: staff.email, role: staff.role, sessionVersion: Number(staff.session_version), sessionId, refreshToken: authSession.refresh_token, aal: 'aal2', mfaAt: mfaAt || Date.now(), authCheckedAt: Date.now(), iat: Date.now(), exp: Date.now() + 12 * 60 * 60 * 1000 };
  const context = supportCentralCurrentContextV146();
  if (context) context.verifiedAdminId = staff.user_id;
  writeSession(res, ADMIN_COOKIE, session, 12 * 60 * 60, 'Strict'); clearCookie(res, MFA_COOKIE, 'Strict');
  return session;
}

async function actionAdminLogin(req, res, body) {
  exactKeys(body, ['email', 'password', 'turnstileToken', 'enrollmentSecret']); const adminEmail = email(body.email, true); const password = String(body.password || ''); const token = text(body.turnstileToken === undefined ? '' : body.turnstileToken, config().turnstileRequired ? 10 : 0, 4096, 'Token Turnstile');
  if (adminEmail !== config().primaryAdminEmail) throw new PublicError(401, 'CREDENTIALS_INVALID', 'Email atau password belum sesuai.');
  if (password.length < 8 || password.length > 256) throw new PublicError(400, 'CREDENTIALS_INVALID', 'Email atau password belum sesuai.');
  await rateLimit(req, 'admin_login_ip', 5, 900, 1800, 'ip'); await accountRateLimit('admin_login_account', adminEmail, 5, 900, 1800);
  req.diracAuthAuditEligible = true;
  const loginBody = { email: adminEmail, password }; if (token) loginBody.gotrue_meta_security = { captcha_token: token };
  const login = await auth('/token?grant_type=password', { body: loginBody });
  if (!login.ok || !login.data || !login.data.access_token || !login.data.refresh_token || !login.data.user) throw new PublicError(401, 'CREDENTIALS_INVALID', 'Email atau password belum sesuai.');
  if (!supportProviderUserAllowed(login.data.user)) throw new PublicError(403, 'AUTH_ACCOUNT_BLOCKED', 'Akun tidak diizinkan.');
  const staff = await staffByUser(login.data.user.id); if (String(staff.email).toLowerCase() !== adminEmail) throw new PublicError(403, 'STAFF_IDENTITY_MISMATCH', 'Identitas staff tidak cocok.');
  const claims = supportProviderClaims(login.data); const mustMfa = config().adminMfaRequired || staff.mfa_required === true;
  if (!mustMfa || claims.aal === 'aal2') {
    const adminSession = await issueAdminSession(res, login.data, staff, Date.now());
    req.diracAuthOutcome = 'success'; await recordAdminAuth(req, staff.user_id, 'admin.auth.session_issued', adminEmail, 'success', 'ADMIN_LOGIN_OK');
    const queue = await adminQueue(staff, 'active', 50); const snapshot = await statusSnapshot(canManageStatus(staff));
    return json(res, 200, { ok: true, code: 'ADMIN_LOGIN_OK', csrfToken: csrfBundle(req, res, { rotate: true, session: adminSession, scope: 'admin_mutation' }), admin: publicAdmin(staff), queue, status: snapshot, realtime: adminRealtime(login.data.access_token) });
  }
  const factors = Array.isArray(login.data.user.factors) ? login.data.user.factors : [];
  let factor = factors.find((item) => item && item.status === 'verified' && item.factor_type === 'totp'); let enrollmentPayload = null;
  if (!factor) {
    // A separate out-of-band secret prevents a stolen initial password from
    // binding an attacker's authenticator before the legitimate first login.
    if (!timingEqual(config().mfaEnrollmentSecret, String(body.enrollmentSecret || ''))) throw new PublicError(403, 'MFA_ENROLLMENT_AUTH_REQUIRED', 'Secret bootstrap enrollment TOTP tidak valid.');
    for (const stale of factors.filter((item) => item && item.status !== 'verified' && item.factor_type === 'totp').slice(0, 5)) {
      let removed;
      try { removed = await auth('/factors/' + encodeURIComponent(stale.id), { method: 'DELETE', token: login.data.access_token, body: {} }); }
      catch (_) { throw new PublicError(502, 'MFA_ENROLLMENT_CLEANUP_FAILED', 'Faktor TOTP lama belum dapat dibersihkan dengan aman.'); }
      if (!removed || removed.ok !== true) throw new PublicError(502, 'MFA_ENROLLMENT_CLEANUP_FAILED', 'Faktor TOTP lama belum dapat dibersihkan dengan aman.');
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
  return json(res, 200, { ok: true, code: 'ADMIN_MFA_REQUIRED', csrfToken: csrfBundle(req, res, { rotate: true, session: temp, scope: 'admin_mfa_verify' }), mfaRequired: true, mfaEnrollment: enrollmentPayload });
}

async function actionAdminMfaVerify(req, res, body) {
  exactKeys(body, ['code']); const code = String(body.code || '').trim(); if (!/^\d{6}$/.test(code)) throw new PublicError(400, 'MFA_CODE_INVALID', 'Kode TOTP wajib enam digit.');
  const temp = readSession(req, MFA_COOKIE); if (!temp || temp.kind !== 'admin_mfa') throw new PublicError(401, 'MFA_CHALLENGE_EXPIRED', 'Challenge MFA sudah berakhir. Silakan login ulang.');
  await rateLimit(req, 'admin_mfa_ip', 8, 900, 1800, 'verify'); await accountRateLimit('admin_mfa_account', temp.uid, 5, 900, 1800);
  req.diracAuthAuditEligible = true;
  const verified = await auth('/factors/' + encodeURIComponent(temp.factorId) + '/verify', { token: temp.accessToken, body: { challenge_id: temp.challengeId, code } });
  if (!verified.ok || !verified.data || !verified.data.access_token || !verified.data.refresh_token) throw new PublicError(401, 'MFA_CODE_REJECTED', 'Kode autentikator tidak valid.');
  const claims = supportProviderClaims(verified.data); if (claims.aal !== 'aal2' || String(claims.sub || '') !== String(temp.uid)) throw new PublicError(403, 'MFA_ASSURANCE_INVALID', 'Tingkat jaminan MFA belum terpenuhi.');
  const staff = await staffByUser(temp.uid); const adminSession = await issueAdminSession(res, verified.data, staff, Date.now());
  req.diracAuthOutcome = 'success'; await recordAdminAuth(req, staff.user_id, 'admin.auth.session_issued', staff.email, 'success', 'ADMIN_MFA_OK');
  const queue = await adminQueue(staff, 'active', 50); const snapshot = await statusSnapshot(canManageStatus(staff));
  return json(res, 200, { ok: true, code: 'ADMIN_MFA_OK', csrfToken: csrfBundle(req, res, { rotate: true, session: adminSession, scope: 'admin_mutation' }), admin: publicAdmin(staff), queue, status: snapshot, realtime: adminRealtime(verified.data.access_token) });
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
  const session = readSession(req, ADMIN_COOKIE); let upstreamConfirmed = true;
  if (session && session.refreshToken) {
    try {
      const refreshed = await refreshAuth(session.refreshToken);
      const logout = await auth('/logout?scope=local', { token: refreshed.access_token, body: {} });
      if (!logout || logout.ok !== true) upstreamConfirmed = false;
    } catch (_) { upstreamConfirmed = false; }
  }
  clearCookie(res, ADMIN_COOKIE, 'Strict'); clearCookie(res, MFA_COOKIE, 'Strict');
  if (!upstreamConfirmed) {
    if (session && session.uid) await recordAdminAuth(req, session.uid, 'admin.auth.logout', session.email, 'upstream_unconfirmed', 'ADMIN_LOGOUT_UPSTREAM_UNCONFIRMED');
    throw new PublicError(503, 'ADMIN_LOGOUT_UPSTREAM_UNCONFIRMED', 'Sesi lokal ditutup, tetapi pencabutan sesi upstream belum dapat dikonfirmasi.');
  }
  if (session && session.uid) await recordAdminAuth(req, session.uid, 'admin.auth.logout', session.email, 'success', 'ADMIN_LOGGED_OUT');
  return json(res, 200, { ok: true, code: 'ADMIN_LOGGED_OUT', csrfToken: csrfBundle(req, res, { rotate: true, session: null, scope: 'admin_login' }) });
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
  supportCentralAssertDynamicEgress('dns');
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
  supportCentralAssertDynamicEgress('https');
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

/* ============================================================
   DIRAC SUPPORT CENTRAL SECURITY GUARD v146 - SUPPORT FLOW
   Ported into this physical file only. The policy below contains support
   actions exclusively; no /api/health action allowlist is inherited.
   ============================================================ */

const DIRAC_SUPPORT_CENTRAL_SECURITY_GUARD_V146 = 'dirac-support-central-security-guard-v146';
const DIRAC_SUPPORT_CENTRAL_HARDENING_V221 = 'dirac-support-central-owasp-hardening-v221';
const DIRAC_SUPPORT_CENTRAL_CONTEXT_V146 = new AsyncLocalStorage();
const DIRAC_SUPPORT_CENTRAL_CIRCUIT_V146 = globalThis.__DIRAC_SUPPORT_CENTRAL_CIRCUIT_V146__ || new Map();
globalThis.__DIRAC_SUPPORT_CENTRAL_CIRCUIT_V146__ = DIRAC_SUPPORT_CENTRAL_CIRCUIT_V146;
const DIRAC_SUPPORT_CENTRAL_BAN_AUTHORITY_V354 = 'dirac-support-health-ban-authority-v354';
let DIRAC_SUPPORT_HEALTH_HANDLER_PROMISE_V354 = null;

async function supportCentralBanAuthorityV354() {
  if (!DIRAC_SUPPORT_HEALTH_HANDLER_PROMISE_V354) {
    DIRAC_SUPPORT_HEALTH_HANDLER_PROMISE_V354 = import('./health.js').then((loaded) => loaded && (loaded.default || loaded));
  }
  const handler = await DIRAC_SUPPORT_HEALTH_HANDLER_PROMISE_V354.catch(() => null);
  const authority = handler && handler.__diracCentralBanAuthorityV354;
  const createEgressBroker = handler && handler.__diracCentralCreateSupportEgressBrokerV355;
  if (typeof handler !== 'function' || Object.isFrozen(handler) !== true
      || handler.__diracCentralSecurityGuardV146 !== true
      || handler.__diracCentralHardeningV221 !== true
      || !authority || authority.version !== 'dirac-central-ban-authority-v354'
      || typeof authority.check !== 'function' || typeof authority.ban !== 'function'
      || typeof createEgressBroker !== 'function') {
    DIRAC_SUPPORT_HEALTH_HANDLER_PROMISE_V354 = null;
    throw new PublicError(503, 'CENTRAL_BAN_AUTHORITY_INVALID', 'Otoritas blokir keamanan pusat tidak tersedia.');
  }
  if (!DIRAC_SUPPORT_HEALTH_EGRESS_BROKER_V355) {
    const broker = createEgressBroker(DIRAC_SUPPORT_HEALTH_EGRESS_BRIDGE_OBJECT_V355);
    if (!broker || Object.isFrozen(broker) !== true
        || broker.version !== 'dirac-central-support-egress-broker-v355'
        || typeof broker.fetch !== 'function') {
      DIRAC_SUPPORT_HEALTH_HANDLER_PROMISE_V354 = null;
      throw new PublicError(503, 'CENTRAL_EGRESS_BROKER_INVALID', 'Broker egress pusat untuk support tidak tersedia.');
    }
    DIRAC_SUPPORT_HEALTH_EGRESS_BROKER_V355 = broker;
  }
  return authority;
}

function supportCentralPolicyV146(methods, principal, options) {
  const settings = options || {};
  return Object.freeze({
    methods: Object.freeze(methods.slice()),
    principal,
    csrf: settings.csrf === true,
    mfa: settings.mfa === true,
    bodyKeys: Object.freeze((settings.bodyKeys || []).slice()),
    queryKeys: Object.freeze((settings.queryKeys || []).slice()),
    idBodyKeys: Object.freeze((settings.idBodyKeys || []).slice()),
    idQueryKeys: Object.freeze((settings.idQueryKeys || []).slice()),
    idArrayKeys: Object.freeze((settings.idArrayKeys || []).slice()),
    idempotency: String(settings.idempotency || 'none'),
    browser: principal !== 'cron'
  });
}

const DIRAC_SUPPORT_CENTRAL_EXPECTED_ACTIONS_V146 = Object.freeze([
  'admin_bootstrap',
  'admin_component_update',
  'admin_conversation_update',
  'admin_incident_advance',
  'admin_incident_create',
  'admin_login',
  'admin_logout',
  'admin_maintenance_create',
  'admin_mfa_verify',
  'admin_monitor_config_update',
  'admin_public_config',
  'admin_queue',
  'admin_send',
  'admin_status_snapshot',
  'admin_thread',
  'chat_bootstrap',
  'chat_close',
  'chat_public_config',
  'chat_send',
  'chat_start',
  'customer_access_refresh',
  'monitor_run',
  'status_bootstrap'
]);

const DIRAC_SUPPORT_CENTRAL_ACTION_POLICY_V146 = Object.freeze({
  status_bootstrap: supportCentralPolicyV146(['GET'], 'public', {}),
  chat_public_config: supportCentralPolicyV146(['GET'], 'public', {}),
  admin_public_config: supportCentralPolicyV146(['GET'], 'public', {}),
  chat_bootstrap: supportCentralPolicyV146(['GET'], 'customer', { queryKeys: ['after_sequence'] }),
  chat_start: supportCentralPolicyV146(['POST'], 'customer_main', {
    csrf: true,
    bodyKeys: ['category', 'subject', 'message', 'website', 'consent', 'turnstileToken'],
    idempotency: 'header'
  }),
  chat_send: supportCentralPolicyV146(['POST'], 'customer', {
    csrf: true,
    bodyKeys: ['conversationId', 'clientMessageId', 'body'],
    idBodyKeys: ['conversationId', 'clientMessageId'],
    idempotency: 'header_matches_body'
  }),
  chat_close: supportCentralPolicyV146(['POST'], 'customer', {
    csrf: true,
    bodyKeys: ['conversationId'],
    idBodyKeys: ['conversationId']
  }),
  customer_access_refresh: supportCentralPolicyV146(['POST'], 'customer', { csrf: true }),
  admin_login: supportCentralPolicyV146(['POST'], 'public', {
    csrf: true,
    bodyKeys: ['email', 'password', 'turnstileToken', 'enrollmentSecret']
  }),
  admin_mfa_verify: supportCentralPolicyV146(['POST'], 'admin_mfa_pending', {
    csrf: true,
    bodyKeys: ['code']
  }),
  admin_bootstrap: supportCentralPolicyV146(['GET'], 'admin', { mfa: true }),
  admin_queue: supportCentralPolicyV146(['GET'], 'admin', { mfa: true, queryKeys: ['filter', 'limit'] }),
  admin_thread: supportCentralPolicyV146(['GET'], 'admin', {
    mfa: true,
    queryKeys: ['conversation_id', 'after_sequence', 'limit'],
    idQueryKeys: ['conversation_id']
  }),
  admin_send: supportCentralPolicyV146(['POST'], 'admin', {
    csrf: true,
    mfa: true,
    bodyKeys: ['conversationId', 'clientMessageId', 'body'],
    idBodyKeys: ['conversationId', 'clientMessageId'],
    idempotency: 'header_matches_body'
  }),
  admin_conversation_update: supportCentralPolicyV146(['POST'], 'admin', {
    csrf: true,
    mfa: true,
    bodyKeys: ['conversationId', 'operation'],
    idBodyKeys: ['conversationId']
  }),
  admin_status_snapshot: supportCentralPolicyV146(['GET'], 'admin', { mfa: true }),
  admin_component_update: supportCentralPolicyV146(['POST'], 'admin', {
    csrf: true,
    mfa: true,
    bodyKeys: ['componentId', 'status'],
    idBodyKeys: ['componentId']
  }),
  admin_monitor_config_update: supportCentralPolicyV146(['POST'], 'admin', {
    csrf: true,
    mfa: true,
    bodyKeys: ['componentId', 'enabled', 'url', 'timeoutMs', 'expectedMin', 'expectedMax'],
    idBodyKeys: ['componentId']
  }),
  admin_incident_create: supportCentralPolicyV146(['POST'], 'admin', {
    csrf: true,
    mfa: true,
    bodyKeys: ['title', 'summary', 'impact', 'componentIds'],
    idArrayKeys: ['componentIds']
  }),
  admin_incident_advance: supportCentralPolicyV146(['POST'], 'admin', {
    csrf: true,
    mfa: true,
    bodyKeys: ['incidentId', 'expectedRevision', 'stage', 'progress', 'message'],
    idBodyKeys: ['incidentId']
  }),
  admin_maintenance_create: supportCentralPolicyV146(['POST'], 'admin', {
    csrf: true,
    mfa: true,
    bodyKeys: ['title', 'message', 'startsAt', 'endsAt', 'componentIds'],
    idArrayKeys: ['componentIds']
  }),
  admin_logout: supportCentralPolicyV146(['POST'], 'admin_optional', { csrf: true }),
  monitor_run: supportCentralPolicyV146(['GET', 'POST'], 'cron', {})
});

const DIRAC_SUPPORT_CENTRAL_ACTIVE_ACTIONS_V146 = new Set(Object.keys(DIRAC_SUPPORT_CENTRAL_ACTION_POLICY_V146));
const DIRAC_SUPPORT_CENTRAL_ALLOWED_REFERER_PATHS_V146 = new Set([
  '/', '/chat', '/chat/', '/admin', '/admin/', '/status', '/status/',
  '/chat.html', '/chat-admin.html', '/status.html'
]);
const DIRAC_SUPPORT_CENTRAL_PREFLIGHT_HEADERS_V146 = new Set([
  'accept', 'content-type', 'x-dirac-csrf', 'x-dirac-admin-binding', 'idempotency-key', 'if-none-match'
]);
const DIRAC_SUPPORT_CENTRAL_SCANNER_UA_REGEX_V146 = /\b(?:curl|wget|httpie|fetch-cli|python|python-requests|aiohttp|urllib|requests|mechanize|scrapy|node-fetch|axios|got|undici|go-http-client|java|okhttp|apache-httpclient|libwww-perl|lwp|ruby|php|powershell|httpclient|postman|postmanruntime|insomnia|paw|hoppscotch|burp|burp\s*suite|owasp\s*zap|zap|mitmproxy|fiddler|charles|caido|sqlmap|nuclei|nikto|acunetix|netsparker|invicti|nessus|openvas|qualys|appscan|webinspect|w3af|arachni|skipfish|jaeles|xray|x-ray|whatweb|wpscan|joomscan|droopescan|ffuf|gobuster|dirb|dirbuster|feroxbuster|wfuzz|dirsearch|hydra|medusa|patator|nmap|masscan|zgrab|zmap|shodan|censys|binaryedge|commix|havij|xsser|dalfox|tplmap|ysoserial|metasploit|msfconsole|headlesschrome|phantomjs|selenium|playwright|puppeteer|chromedriver|geckodriver)\b/i;
const DIRAC_SUPPORT_CENTRAL_STRUCTURAL_THREATS_V146 = Object.freeze([
  Object.freeze(['sql_injection', /\bunion\s+(?:all\s+)?select\b|(?:^|[\s'"`])(?:or|and)\s+1\s*=\s*1(?:$|[\s'"`])|true\s*=\s*true|' or '1'='1|" or "1"="1|--\s|#\s|(?<!\*)\/\*|\*\/(?!\*)|;\s*(?:select|insert|update|delete|drop|alter|truncate|create|grant|revoke)\b|\binformation_schema\b|\bpg_catalog\b|\bsqlite_master\b|\bmysql\.user\b|\bsysobjects\b|\bsyscolumns\b|\bsleep\s*\(|\bpg_sleep\s*\(|\bbenchmark\s*\(|\bwaitfor\s+delay\b|\bload_file\s*\(|\binto\s+outfile\b|\bxp_cmdshell\b|\bextractvalue\s*\(|\bupdatexml\s*\(|\bcopy\s+.*\bto\s+program\b/i]),
  Object.freeze(['xss', /<\s*script\b|<\s*\/\s*script\b|\bjavascript\s*:|\bon(?:error|load|click|mouseover|focus|blur|submit|toggle|pointerenter)\s*=|<\s*(?:img|svg|iframe|object|embed|body|meta|link|math|video|audio)\b|\bsrcdoc\s*=|\bdata:text\/html\b|\bdocument\.cookie\b|\blocalstorage\b|\bsessionstorage\b|\b(?:alert|confirm|prompt|eval|function|settimeout|setinterval)\s*\(|\binnerhtml\b/i]),
  Object.freeze(['ssrf', /\blocalhost\b|\b127\.0\.0\.1\b|\b0\.0\.0\.0\b|(?:^|[^a-f0-9])::1(?:[^a-f0-9]|$)|\[::1\]|\b10\.\d+\.\d+\.\d+\b|\b172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+\b|\b192\.168\.\d+\.\d+\b|\b169\.254\.169\.254\b|\b169\.254\.\d+\.\d+\b|\bmetadata\.google\.internal\b|\binstance-data\b|\b(?:file|gopher|dict|ftp|ldap|sftp|tftp):\/\//i]),
  Object.freeze(['path_traversal', /\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f|\/etc\/passwd|\/etc\/shadow|\/proc\/self\/environ|\bboot\.ini\b|\bwin\.ini\b|\bWEB-INF\b|php:\/\/|zip:\/\/|expect:\/\//i]),
  Object.freeze(['command_injection', /(?:;|\||&&|`|\$\()\s*(?:whoami|id|uname|cat|ls|pwd)\b|\b(?:shell_exec|passthru|proc_open|popen|system)\s*\(/i]),
  Object.freeze(['prototype_pollution', /__proto__|constructor\.prototype|prototype\s*=|prototype\[|constructor\[/i]),
  Object.freeze(['nosql_injection', /\$(?:ne|gt|gte|lt|lte|where|regex|or|and|nor|expr|jsonschema)\b/i]),
  Object.freeze(['xxe', /<!DOCTYPE|<!ENTITY|\bSYSTEM\b|\bPUBLIC\b|file:\/\/\/etc\/passwd/i]),
  Object.freeze(['ssti', /\{\{7\*7\}\}|\$\{7\*7\}|<%=\s*7\*7\s*%>|#\{7\*7\}|\{\{.*(?:config|self|class|mro|subclasses).*\}\}/i]),
  Object.freeze(['log4shell', /\$\{jndi:|\b(?:ldap|rmi|dns):\/\//i]),
  Object.freeze(['crlf', /%0d%0a|\\r\\n|\bSet-Cookie:|\bLocation:|\bContent-Length:|\bTransfer-Encoding:/i]),
  Object.freeze(['request_smuggling', /transfer-encoding[\s\S]{0,80}transfer-encoding|content-length[\s\S]{0,80}content-length|content-length[\s\S]{0,80}transfer-encoding|transfer-encoding[\s\S]{0,80}content-length|\bchunked\b[\s\S]{0,80}\bchunked\b/i]),
  Object.freeze(['secret_file_probe', /\.env\b|\.git\b|\.svn\b|\.hg\b|\.aws\/credentials\b|\bid_rsa\b|\bwp-config\.php\b|\bconfig\.php\b|\bcomposer\.json\b|\bpackage-lock\.json\b/i]),
  Object.freeze(['graphql_introspection', /\b__schema\b|\b__type\b|\bintrospectionquery\b/i])
]);

function supportCentralCurrentContextV146() {
  return DIRAC_SUPPORT_CENTRAL_CONTEXT_V146.getStore() || null;
}

function supportCentralRequestFingerprintV146(req) {
  const ua = String(req && req.headers && req.headers['user-agent'] || '').slice(0, 512);
  return hash(clientIp(req) + '|' + ua).slice(0, 48);
}

function supportCentralRecordSuppressedExceptionV221(error) {
  try {
    const name = String(error && error.name || 'Error').slice(0, 80);
    const code = String(error && error.code || 'UNCLASSIFIED').slice(0, 120);
    console.error('[dirac-support-central-suppressed]', JSON.stringify({ name, code, patch: DIRAC_SUPPORT_CENTRAL_HARDENING_V221 }));
  } catch (_) {}
}

function supportSafeDiagnosticMessageV356(error) {
  let value = String(error && error.message || '').replace(/[\r\n\t]+/g, ' ');
  value = value.replace(/\b(authorization|bearer|cookie|set-cookie|password|secret|access[_ -]?token|refresh[_ -]?token|token|otp|totp)\s*[:=]\s*[^,;\s]{4,}/gi, '$1=[redacted]');
  value = value.replace(/[A-Za-z0-9_-]{48,}/g, '[redacted]');
  value = value.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[redacted-email]');
  return value.slice(0, 160);
}

function supportCentralExpectedAuthoritiesV146() {
  const values = new Set();
  for (const origin of allowedOrigins()) {
    try {
      const parsed = new URL(origin);
      const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
      if (!hostname.startsWith('cs.')) continue;
      values.add('api.' + hostname.slice(3) + (parsed.port ? ':' + parsed.port : ''));
    } catch (_) {}
  }
  return values;
}

function supportCentralValidateHostV146(req) {
  if (!isProduction()) return true;
  const expected = supportCentralExpectedAuthoritiesV146();
  if (!expected.size) throw new PublicError(503, 'CENTRAL_HOST_POLICY_EMPTY', 'Allowlist hostname API support belum valid.');
  const values = [req.headers && req.headers['x-forwarded-host'], req.headers && req.headers.host].filter(Boolean);
  if (!values.length || values.some((value) => !expected.has(normalizeAuthority(value)))) {
    throw new PublicError(421, 'CENTRAL_HOST_REJECTED', 'Hostname permintaan tidak diizinkan.');
  }
  const proto = String(req.headers && (req.headers['x-forwarded-proto'] || req.headers['x-vercel-forwarded-proto']) || '').split(',')[0].trim().toLowerCase();
  if (proto !== 'https') throw new PublicError(403, 'CENTRAL_HTTPS_REQUIRED', 'HTTPS wajib digunakan.');
  return true;
}

function supportCentralStrictCookiePairsV146(req) {
  const raw = String(req && req.headers && req.headers.cookie || '');
  if (!raw) return [];
  if (Buffer.byteLength(raw, 'utf8') > 32 * 1024 || /[\r\n\u0000]/.test(raw)) throw new PublicError(400, 'CENTRAL_COOKIE_INVALID', 'Header cookie tidak valid.');
  const seen = new Set();
  const pairs = raw.split(';');
  if (pairs.length > 180) throw new PublicError(400, 'CENTRAL_COOKIE_INVALID', 'Jumlah cookie melebihi batas.');
  return pairs.map((part) => {
    const clean = String(part || '').trim();
    const index = clean.indexOf('=');
    if (index < 1) throw new PublicError(400, 'CENTRAL_COOKIE_INVALID', 'Format cookie tidak valid.');
    const name = safeCookieName(clean.slice(0, index));
    const value = clean.slice(index + 1);
    if (!name || seen.has(name) || Buffer.byteLength(value, 'utf8') > 9 * 1024) throw new PublicError(400, 'CENTRAL_COOKIE_INVALID', 'Cookie duplikat atau tidak valid.');
    seen.add(name);
    return { name, value };
  });
}

function supportCentralHeaderBudgetV146(req) {
  let total = 0;
  const headers = req && req.headers && typeof req.headers === 'object' ? req.headers : {};
  const names = Object.keys(headers);
  if (names.length > 96) throw new PublicError(431, 'CENTRAL_HEADERS_TOO_LARGE', 'Jumlah header melebihi batas.');
  for (const name of names) {
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/.test(name)) throw new PublicError(400, 'CENTRAL_HEADER_INVALID', 'Nama header tidak valid.');
    const value = Array.isArray(headers[name]) ? headers[name].join(',') : String(headers[name] || '');
    if (/[\r\n\u0000]/.test(value)) throw new PublicError(400, 'CENTRAL_HEADER_INVALID', 'Nilai header tidak valid.');
    total += Buffer.byteLength(name + ':' + value, 'utf8');
  }
  if (total > 64 * 1024) throw new PublicError(431, 'CENTRAL_HEADERS_TOO_LARGE', 'Ukuran header melebihi batas.');
}

function supportCentralPreflightV146(ctx) {
  const req = ctx.req;
  if (ctx.method !== 'OPTIONS') return false;
  if (!ctx.policy.browser || !originAllowed(req)) throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin tidak diizinkan.');
  const requestedMethod = String(req.headers && req.headers['access-control-request-method'] || '').trim().toUpperCase();
  if (!requestedMethod || !ctx.policy.methods.includes(requestedMethod)) throw new PublicError(405, 'PREFLIGHT_METHOD_REJECTED', 'Method preflight tidak diizinkan.');
  const requestedHeaders = String(req.headers && req.headers['access-control-request-headers'] || '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean);
  if (requestedHeaders.some((name) => !DIRAC_SUPPORT_CENTRAL_PREFLIGHT_HEADERS_V146.has(name))) {
    throw new PublicError(403, 'PREFLIGHT_HEADERS_REJECTED', 'Header preflight tidak diizinkan.');
  }
  ctx.preflight = true;
  return true;
}

function supportCentralBrowserAuthenticityV146(ctx) {
  if (!ctx.policy.browser) {
    if (requestOrigin(ctx.req)) throw new PublicError(403, 'CRON_ORIGIN_REJECTED', 'Origin browser tidak diizinkan untuk monitor cron.');
    return;
  }
  const origin = requestOrigin(ctx.req);
  if (!origin || !allowedOrigins().has(origin)) throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin permintaan tidak diizinkan.');
  let parsedOrigin;
  try { parsedOrigin = new URL(origin); } catch (_) { throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin permintaan tidak valid.'); }
  if (isProduction() && parsedOrigin.protocol !== 'https:') throw new PublicError(403, 'ORIGIN_NOT_ALLOWED', 'Origin HTTPS wajib digunakan.');
  const fetchSite = String(ctx.req.headers && ctx.req.headers['sec-fetch-site'] || '').trim().toLowerCase();
  const fetchMode = String(ctx.req.headers && ctx.req.headers['sec-fetch-mode'] || '').trim().toLowerCase();
  const fetchDest = String(ctx.req.headers && ctx.req.headers['sec-fetch-dest'] || '').trim().toLowerCase();
  if (isProduction() && !['same-site', 'same-origin'].includes(fetchSite)) throw new PublicError(403, 'FETCH_SITE_REJECTED', 'Konteks situs browser tidak diizinkan.');
  if (fetchMode && fetchMode !== 'cors') throw new PublicError(403, 'FETCH_MODE_REJECTED', 'Mode browser tidak diizinkan.');
  if (fetchDest && fetchDest !== 'empty') throw new PublicError(403, 'FETCH_DEST_REJECTED', 'Tujuan fetch browser tidak diizinkan.');
  const referer = String(ctx.req.headers && ctx.req.headers.referer || '').trim();
  if (referer) {
    let parsed;
    try { parsed = new URL(referer); } catch (_) { throw new PublicError(403, 'REFERER_REJECTED', 'Referer tidak valid.'); }
    if (parsed.origin !== origin || !DIRAC_SUPPORT_CENTRAL_ALLOWED_REFERER_PATHS_V146.has(parsed.pathname)) throw new PublicError(403, 'REFERER_REJECTED', 'Referer tidak diizinkan.');
  }
  const ua = String(ctx.req.headers && ctx.req.headers['user-agent'] || '');
  if (DIRAC_SUPPORT_CENTRAL_SCANNER_UA_REGEX_V146.test(ua)) throw new PublicError(403, 'AUTOMATION_REJECTED', 'Klien otomatis tidak diizinkan pada endpoint browser support.');
}

function supportCentralStructuralSampleV146(ctx) {
  const body = ctx.body && typeof ctx.body === 'object' ? ctx.body : {};
  const structuralBody = {};
  const freeText = new Set(['message', 'body', 'summary', 'title', 'subject', 'password', 'turnstileToken', 'enrollmentSecret']);
  for (const [key, value] of Object.entries(body)) {
    if (freeText.has(key)) continue;
    structuralBody[key] = value;
  }
  return JSON.stringify({
    path: ctx.parsedUrl && ctx.parsedUrl.pathname,
    query: ctx.parsedUrl ? Array.from(ctx.parsedUrl.searchParams.entries()) : [],
    action: ctx.action,
    body: structuralBody
  }).slice(0, 32768);
}

function supportCentralComplexityV146(value, depth, state) {
  if (depth > 8) throw new PublicError(400, 'CENTRAL_BODY_COMPLEXITY_REJECTED', 'Struktur request terlalu dalam.');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new PublicError(400, 'CENTRAL_BODY_VALUE_REJECTED', 'Nilai numerik tidak valid.');
    return;
  }
  if (typeof value === 'string') {
    state.strings += 1;
    state.bytes += Buffer.byteLength(value, 'utf8');
    if (state.strings > 128 || state.bytes > MAX_BODY_BYTES) throw new PublicError(400, 'CENTRAL_BODY_COMPLEXITY_REJECTED', 'Kompleksitas request melebihi batas.');
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 50) throw new PublicError(400, 'CENTRAL_BODY_COMPLEXITY_REJECTED', 'Jumlah elemen array melebihi batas.');
    value.forEach((item) => supportCentralComplexityV146(item, depth + 1, state));
    return;
  }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) throw new PublicError(400, 'CENTRAL_BODY_SHAPE_REJECTED', 'Bentuk object request tidak valid.');
  const entries = Object.entries(value);
  state.keys += entries.length;
  if (state.keys > 128) throw new PublicError(400, 'CENTRAL_BODY_COMPLEXITY_REJECTED', 'Jumlah field request melebihi batas.');
  for (const [key, item] of entries) {
    if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key) || ['__proto__', 'proto', 'prototype', 'constructor'].includes(key)) {
      throw new PublicError(400, 'CENTRAL_BODY_KEY_REJECTED', 'Nama field request tidak diizinkan.');
    }
    supportCentralComplexityV146(item, depth + 1, state);
  }
}

function supportCentralCanonicalUuidV146(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(String(value || ''));
}

function supportCentralValidateIdentifiersV146(ctx) {
  if (ctx.preflight) return;
  const policy = ctx.policy;
  const body = ctx.body || {};
  for (const key of policy.idBodyKeys) {
    if (!supportCentralCanonicalUuidV146(body[key])) throw new PublicError(400, 'ID_INVALID', key + ' tidak valid.');
  }
  for (const key of policy.idQueryKeys) {
    if (!supportCentralCanonicalUuidV146(queryValue(ctx.req, key))) throw new PublicError(400, 'ID_INVALID', key + ' tidak valid.');
  }
  for (const key of policy.idArrayKeys) {
    const values = body[key];
    if (!Array.isArray(values) || values.length > 20 || values.some((value) => !supportCentralCanonicalUuidV146(value))) {
      throw new PublicError(400, 'ID_ARRAY_INVALID', key + ' tidak valid.');
    }
  }
  if (policy.idempotency !== 'none') {
    const header = String(ctx.req.headers && ctx.req.headers['idempotency-key'] || '').trim().toLowerCase();
    if (!supportCentralCanonicalUuidV146(header)) throw new PublicError(400, 'IDEMPOTENCY_KEY_INVALID', 'Idempotency-Key wajib berupa UUID kanonis.');
    if (policy.idempotency === 'header_matches_body' && header !== String(body.clientMessageId || '').trim().toLowerCase()) {
      throw new PublicError(400, 'IDEMPOTENCY_MISMATCH', 'Idempotency-Key tidak cocok dengan clientMessageId.');
    }
  }
}

function supportValidateBodySchemaV361(action, body) {
  const required = {
    chat_start: ['subject', 'message', 'consent'], chat_send: ['conversationId', 'clientMessageId', 'body'],
    chat_close: ['conversationId'], admin_login: ['email', 'password'], admin_mfa_verify: ['code'],
    admin_send: ['conversationId', 'clientMessageId', 'body'], admin_conversation_update: ['conversationId', 'operation'],
    admin_component_update: ['componentId', 'status'],
    admin_monitor_config_update: ['componentId', 'enabled', 'url', 'timeoutMs', 'expectedMin', 'expectedMax'],
    admin_incident_create: ['title', 'summary', 'componentIds'],
    admin_incident_advance: ['incidentId', 'expectedRevision', 'stage', 'progress', 'message'],
    admin_maintenance_create: ['title', 'message', 'startsAt', 'endsAt', 'componentIds']
  };
  for (const key of required[action] || []) {
    if (!Object.prototype.hasOwnProperty.call(body, key)) throw new PublicError(400, 'FIELD_REQUIRED', 'Field wajib tidak tersedia.');
  }
  for (const [key, value] of Object.entries(body)) {
    if (['consent', 'enabled'].includes(key)) {
      if (typeof value !== 'boolean') throw new PublicError(400, 'FIELD_TYPE_INVALID', 'Tipe field tidak valid.');
    } else if (['timeoutMs', 'expectedMin', 'expectedMax', 'expectedRevision', 'progress'].includes(key)) {
      if (typeof value !== 'number' || !Number.isFinite(value)) throw new PublicError(400, 'FIELD_TYPE_INVALID', 'Tipe field tidak valid.');
    } else if (key === 'componentIds') {
      if (!Array.isArray(value) || value.length > 20 || new Set(value).size !== value.length) throw new PublicError(400, 'FIELD_TYPE_INVALID', 'Daftar komponen tidak valid.');
    } else if (typeof value !== 'string' || !validUnicode(value)) {
      throw new PublicError(400, 'FIELD_TYPE_INVALID', 'Tipe field tidak valid.');
    }
  }
}

function supportCentralValidateNumericQueryV146(ctx) {
  const parsed = ctx.parsedUrl;
  for (const name of ['after_sequence', 'limit']) {
    if (!parsed.searchParams.has(name)) continue;
    const value = parsed.searchParams.get(name);
    if (!/^(?:0|[1-9]\d{0,9})$/.test(String(value || ''))) throw new PublicError(400, 'QUERY_NUMBER_INVALID', 'Parameter numerik tidak kanonis.');
  }
  if (parsed.searchParams.has('filter') && !['active', 'new', 'mine', 'closed'].includes(String(parsed.searchParams.get('filter') || ''))) {
    throw new PublicError(400, 'QUERY_FILTER_INVALID', 'Filter antrean tidak valid.');
  }
}

function supportCentralSessionPrecheckV146(ctx) {
  if (ctx.preflight) return;
  const pairs = supportCentralStrictCookiePairsV146(ctx.req);
  const names = new Set(pairs.map((item) => item.name));
  if (ctx.policy.principal === 'customer' || ctx.policy.principal === 'customer_main') {
    const route = mainIdentityRoute(ctx.req);
    if (!mainCookieHeader(ctx.req, route)) throw new PublicError(401, 'MAIN_LOGIN_REQUIRED', 'Silakan masuk ke akun Dirac terlebih dahulu.');
    if (ctx.policy.principal === 'customer' && !names.has(runtimeCookieName(CUSTOMER_COOKIE))) {
      throw new PublicError(401, 'CUSTOMER_SESSION_REQUIRED', 'Sesi chat tidak ditemukan.');
    }
  }
  if (ctx.policy.principal === 'admin' && !names.has(runtimeCookieName(ADMIN_COOKIE))) {
    throw new PublicError(401, 'ADMIN_SESSION_REQUIRED', 'Sesi admin tidak ditemukan atau sudah berakhir.');
  }
  if (ctx.policy.principal === 'admin_mfa_pending' && !names.has(runtimeCookieName(MFA_COOKIE))) {
    throw new PublicError(401, 'MFA_SESSION_REQUIRED', 'Sesi verifikasi MFA tidak ditemukan.');
  }
}

function supportCentralMfaPrecheckV146(ctx) {
  if (ctx.preflight || !ctx.policy.mfa) return;
  const session = readSession(ctx.req, ADMIN_COOKIE);
  if (!session || session.kind !== 'admin' || session.aal !== 'aal2' || Number(session.mfaAt || 0) < Date.now() - 12 * 60 * 60 * 1000) {
    throw new PublicError(401, 'ADMIN_MFA_EXPIRED', 'Verifikasi MFA admin sudah berakhir. Silakan masuk kembali.');
  }
}

async function supportCentralDistributedRateV354(ctx) {
  const policyLimit = ctx.policy.principal === 'cron' ? 30 : ctx.policy.principal === 'public' ? 180 : 360;
  const key = hmac(config().ipSecret, 'central-guard-rate-v354|' + ctx.fingerprint + '|' + ctx.action, 'hex');
  return takeRateLimit('central_guard_rate_v354', key, policyLimit, 60, 60);
}

function supportCentralCircuitCheckV146(ctx) {
  const state = DIRAC_SUPPORT_CENTRAL_CIRCUIT_V146.get(ctx.action);
  if (state && Number(state.openUntil || 0) > Date.now()) throw new PublicError(503, 'CENTRAL_CIRCUIT_OPEN', 'Layanan support sedang dipulihkan. Coba kembali sesaat lagi.');
}

function supportCentralRecordOutcomeV146(ctx, error) {
  if (!ctx || !DIRAC_SUPPORT_CENTRAL_ACTIVE_ACTIONS_V146.has(ctx.action)) return;
  const now = Date.now();
  let state = DIRAC_SUPPORT_CENTRAL_CIRCUIT_V146.get(ctx.action) || { startedAt: now, failures: 0, openUntil: 0 };
  if (now - Number(state.startedAt || 0) > 30_000) state = { startedAt: now, failures: 0, openUntil: 0 };
  const internalFailure = Boolean(error && (!(error instanceof PublicError) || Number(error.status || 500) >= 500));
  if (internalFailure) {
    state.failures += 1;
    if (state.failures >= 12) state.openUntil = now + 15_000;
  } else if (!error) {
    state.failures = Math.max(0, state.failures - 1);
    if (!state.failures) state.openUntil = 0;
  }
  DIRAC_SUPPORT_CENTRAL_CIRCUIT_V146.set(ctx.action, state);
}

function supportCentralOutputSecretsV146() {
  return [
    env('DIRAC_SUPPORT_SUPABASE_SECRET_KEY'),
    env('DIRAC_SUPPORT_SUPABASE_SERVICE_ROLE_KEY'),
    env('DIRAC_SUPPORT_COOKIE_SECRET'),
    env('DIRAC_SUPPORT_CSRF_SECRET'),
    env('DIRAC_SUPPORT_IP_HMAC_SECRET'),
    env('DIRAC_SUPPORT_MFA_ENROLLMENT_SECRET'),
    env('DIRAC_SUPPORT_ADMIN_BINDING_SECRET'),
    env('DIRAC_SUPPORT_TURNSTILE_SECRET_KEY'),
    env('CRON_SECRET')
  ].filter((value) => Buffer.byteLength(value, 'utf8') >= 16);
}

function supportCentralSerializeOutput(payload, status) {
  let safeStatus = Number.isInteger(Number(status)) ? Number(status) : 500;
  try {
    const body = JSON.stringify(payload);
    if (Buffer.byteLength(body, 'utf8') > 2 * 1024 * 1024 || /"(?:refreshToken|refresh_token|password)"\s*:/.test(body)) {
      throw new Error('CENTRAL_OUTPUT_POLICY_REJECTED');
    }
    for (const secret of supportCentralOutputSecretsV146()) {
      if (secret && body.includes(secret)) throw new Error('CENTRAL_OUTPUT_SECRET_DETECTED');
    }
    return { status: safeStatus, body };
  } catch (error) {
    supportCentralRecordSuppressedExceptionV221(error);
    safeStatus = 500;
    return { status: safeStatus, body: JSON.stringify({ ok: false, code: 'CENTRAL_OUTPUT_REJECTED', message: 'Respons diblokir oleh pemeriksaan keamanan.', time: nowIso() }) };
  }
}

function supportCentralAssertExecutionContextV146() {
  if (!isProduction()) return null;
  const ctx = supportCentralCurrentContextV146();
  if (!ctx || ctx.fullyPassed !== true || !['handler', 'audit'].includes(ctx.phase)) {
    throw new PublicError(500, 'CENTRAL_EGRESS_CONTEXT_REQUIRED', 'Konteks keamanan egress tidak tersedia.');
  }
  return ctx;
}

function supportCentralAssertFixedEgress(urlValue) {
  const ctx = supportCentralAssertExecutionContextV146();
  if (!isProduction()) return true;
  let target;
  try { target = new URL(String(urlValue || '')); } catch (_) { throw new PublicError(500, 'CENTRAL_EGRESS_URL_INVALID', 'Target egress tidak valid.'); }
  if (target.protocol !== 'https:' || target.username || target.password || target.hash) throw new PublicError(500, 'CENTRAL_EGRESS_REJECTED', 'Target egress tidak diizinkan.');
  const cfg = config();
  const supabase = new URL(cfg.supabaseUrl);
  if (target.origin === supabase.origin && (/^\/rest\/v1(?:\/|$)/.test(target.pathname) || /^\/auth\/v1(?:\/|$)/.test(target.pathname))) return true;
  if (target.origin === 'https://challenges.cloudflare.com' && target.pathname === '/turnstile/v0/siteverify' && ctx.action === 'chat_start') return true;
  const expectedAuthorities = supportCentralExpectedAuthoritiesV146();
  if (expectedAuthorities.has(target.host.toLowerCase()) && target.pathname === '/api/health' && target.searchParams.size === 1 && target.searchParams.get('action') === 'domain_me') {
    if (['chat_public_config', 'chat_bootstrap', 'chat_start', 'chat_send', 'chat_close', 'customer_access_refresh'].includes(ctx.action)) return true;
  }
  throw new PublicError(500, 'CENTRAL_EGRESS_REJECTED', 'Target egress tidak termasuk allowlist support.');
}

function supportCentralAssertDynamicEgress(kind) {
  const ctx = supportCentralAssertExecutionContextV146();
  if (!isProduction()) return true;
  const actionAllowed = ctx.action === 'monitor_run' || (kind === 'dns' && ctx.action === 'admin_monitor_config_update');
  if (!actionAllowed) throw new PublicError(500, 'CENTRAL_DYNAMIC_EGRESS_REJECTED', 'Egress dinamis tidak diizinkan untuk action ini.');
  return true;
}

const DIRAC_SUPPORT_HEALTH_EGRESS_BRIDGE_V355 = 'dirac-support-health-egress-bridge-v355';
let DIRAC_SUPPORT_HEALTH_EGRESS_BROKER_V355 = null;

function supportCentralAuthorizeHealthEgressV355(input, options) {
  const ctx = supportCentralCurrentContextV146();
  if (!ctx) return !isProduction();
  const method = String(options && options.method || 'GET').trim().toUpperCase();
  if (ctx.phase === 'guard') {
    if (ctx.currentStage !== 'rate limit' || method !== 'POST') return false;
    let target;
    let supportDatabaseOrigin;
    try {
      target = new URL(String(input || ''));
      supportDatabaseOrigin = new URL(config().supabaseUrl).origin;
    } catch (_) {
      return false;
    }
    return target.origin === supportDatabaseOrigin
      && target.pathname === '/rest/v1/rpc/support_take_rate_limit'
      && target.search === '';
  }
  if (ctx.fullyPassed !== true || !['handler', 'audit'].includes(ctx.phase)) return false;
  try {
    supportCentralAssertFixedEgress(input);
    return true;
  } catch (_) {
    return false;
  }
}

const DIRAC_SUPPORT_HEALTH_EGRESS_BRIDGE_OBJECT_V355 = Object.freeze({
  version: DIRAC_SUPPORT_HEALTH_EGRESS_BRIDGE_V355,
  guardVersion: DIRAC_SUPPORT_CENTRAL_SECURITY_GUARD_V146,
  authorize: supportCentralAuthorizeHealthEgressV355
});

async function supportCentralGuardIdentityV202(ctx) {
  if (!ctx.req || !ctx.res || typeof ctx.req !== 'object' || typeof ctx.res !== 'object') throw new PublicError(400, 'CENTRAL_REQUEST_INVALID', 'Object request tidak valid.');
  supportCentralHeaderBudgetV146(ctx.req);
  ctx.fingerprint = supportCentralRequestFingerprintV146(ctx.req);
}
async function supportCentralGuardMemoryBanV202(ctx) {
  if (!ctx || !ctx.req) throw new PublicError(400, 'CENTRAL_REQUEST_INVALID', 'Object request tidak valid.');
}
async function supportCentralGuardPersistentBanV202(ctx) {
  if (typeof takeRateLimit !== 'function' || typeof accountRateLimit !== 'function') throw new PublicError(503, 'CENTRAL_RATE_GUARD_UNAVAILABLE', 'Rate guard support tidak tersedia.');
  const authority = await supportCentralBanAuthorityV354();
  const decision = await authority.check(ctx.req);
  if (!decision || decision.ok !== true) throw new PublicError(503, 'CENTRAL_BAN_CHECK_UNAVAILABLE', 'Status blokir keamanan pusat tidak tersedia.');
  if (decision.blocked === true) {
    const error = new PublicError(403, 'CENTRAL_CLIENT_BLOCKED', 'Permintaan diblokir oleh sistem keamanan pusat.');
    error.retryAfter = Math.max(1, Math.floor(Number(decision.retry_after_seconds || 300)));
    throw error;
  }
}
async function supportCentralGuardActionFormatV202(ctx) {
  ctx.rawAction = queryValue(ctx.req, 'action');
  ctx.action = ctx.rawAction.trim().toLowerCase();
  if (!/^[a-z0-9_]{1,64}$/.test(ctx.action)) throw new PublicError(400, 'ACTION_INVALID', 'Action support tidak valid.');
}
async function supportCentralGuardAliasV202(ctx) {
  if (ctx.rawAction !== ctx.action) throw new PublicError(400, 'ACTION_NON_CANONICAL', 'Nama action wajib menggunakan format kanonis.');
}
async function supportCentralGuardWhitelistV202(ctx) {
  if (!DIRAC_SUPPORT_CENTRAL_ACTIVE_ACTIONS_V146.has(ctx.action)) throw new PublicError(404, 'ACTION_NOT_FOUND', 'Action support tidak ditemukan.');
  ctx.policy = DIRAC_SUPPORT_CENTRAL_ACTION_POLICY_V146[ctx.action];
}
async function supportCentralGuardServerRoleV202(ctx) { supportCentralValidateHostV146(ctx.req); }
async function supportCentralGuardEnvironmentV202() { config(); }
async function supportCentralGuardClassificationV202(ctx) {
  if (!ctx.policy || !Object.isFrozen(ctx.policy)) throw new PublicError(500, 'CENTRAL_POLICY_INVALID', 'Policy action support tidak valid.');
}
async function supportCentralGuardRateV202(ctx) { await supportCentralDistributedRateV354(ctx); }
async function supportCentralGuardServerAuthenticationV202(ctx) {
  if (ctx.policy.principal !== 'cron') return;
  const authorization = String(ctx.req.headers && ctx.req.headers.authorization || '');
  if (!/^Bearer [^\s]{32,4096}$/.test(authorization)) throw new PublicError(401, 'MONITOR_AUTH_INVALID', 'Monitor tidak diizinkan.');
}
async function supportCentralGuardBrowserAuthenticityV202(ctx) {
  supportCentralBrowserAuthenticityV146(ctx);
  supportCentralPreflightV146(ctx);
}
async function supportCentralGuardCsrfV202(ctx) {
  if (!ctx.preflight && ctx.policy.csrf) verifyCsrf(ctx.req);
}
async function supportCentralGuardPageNonceV202(ctx) {
  if (!ctx.policy.csrf || ctx.preflight) return;
  const token = String(ctx.req.headers && ctx.req.headers['x-dirac-csrf'] || '');
  const match = /^(\d{13})\.[A-Za-z0-9_-]{43}$/.exec(token);
  const expiresAt = match ? Number(match[1]) : 0;
  if (!expiresAt || expiresAt > Date.now() + SUPPORT_CSRF_TTL_MS_V356 + 60_000) throw new PublicError(403, 'PAGE_NONCE_INVALID', 'Nonce halaman tidak valid.');
}
async function supportCentralGuardBrowserSignalsV202(ctx) {
  if (!ctx.policy.browser) return;
  const mode = String(ctx.req.headers && ctx.req.headers['sec-fetch-mode'] || '').toLowerCase();
  const dest = String(ctx.req.headers && ctx.req.headers['sec-fetch-dest'] || '').toLowerCase();
  if (isProduction() && (mode !== 'cors' || dest !== 'empty')) throw new PublicError(403, 'BROWSER_SIGNAL_REJECTED', 'Sinyal browser tidak sesuai.');
}
async function supportCentralGuardDeviceBindingV202(ctx) { supportCentralSessionPrecheckV146(ctx); }
async function supportCentralGuardAdminAuthenticationV202(ctx) {
  if (ctx.preflight) return;
  if (ctx.policy.principal === 'admin_mfa_pending') {
    const pending = readSession(ctx.req, MFA_COOKIE);
    if (!pending || pending.kind !== 'admin_mfa' || !pending.uid || !pending.refreshToken || !pending.challengeId) throw new PublicError(401, 'MFA_SESSION_REQUIRED', 'Sesi verifikasi MFA tidak ditemukan.');
  }
}
async function supportCentralGuardPublicReadV202(ctx) {
  if (ctx.preflight) return;
  if (ctx.policy.principal === 'public' && ctx.method !== 'GET' && ctx.action !== 'admin_login') {
    throw new PublicError(405, 'METHOD_NOT_ALLOWED', 'Method tidak diizinkan untuk action publik ini.');
  }
}
async function supportCentralGuardBodyV202(ctx) {
  if (ctx.preflight || ctx.method !== 'POST') { ctx.body = null; return; }
  ctx.body = await readJson(ctx.req);
}
async function supportCentralGuardLightV202(ctx) {
  supportCentralStrictCookiePairsV146(ctx.req);
  if (ctx.body) supportCentralComplexityV146(ctx.body, 0, { keys: 0, strings: 0, bytes: 0 });
}
async function supportCentralGuardContractV202(ctx) {
  verifyQueryShape(ctx.req, ctx.action);
  supportCentralValidateNumericQueryV146(ctx);
  if (ctx.method !== 'OPTIONS' && !ctx.policy.methods.includes(ctx.method)) {
    const error = new PublicError(405, 'METHOD_NOT_ALLOWED', 'Method tidak diizinkan untuk action ini.');
    error.allow = ctx.policy.methods.join(', ');
    throw error;
  }
  if (ctx.method === 'POST') {
    exactKeys(ctx.body, ctx.policy.bodyKeys);
    supportValidateBodySchemaV361(ctx.action, ctx.body);
  }
}
async function supportCentralGuardA2FV202(ctx) {
  if (ctx.preflight) return;
  if (ctx.policy.principal === 'admin_mfa_pending') {
    const code = String(ctx.body && ctx.body.code || '');
    if (!/^\d{6}$/.test(code)) throw new PublicError(400, 'MFA_CODE_INVALID', 'Kode TOTP wajib enam digit.');
  }
}
async function supportCentralGuardSecurityReportV202(ctx) {
  if (!ctx.policy || !DIRAC_SUPPORT_CENTRAL_ACTIVE_ACTIONS_V146.has(ctx.action)) {
    throw new PublicError(404, 'ACTION_NOT_FOUND', 'Action support tidak ditemukan.');
  }
}
async function supportCentralGuardRequestSampleV202(ctx) { ctx.sample = supportCentralStructuralSampleV146(ctx); }
async function supportCentralGuardThreatV202(ctx) {
  for (const [name, pattern] of DIRAC_SUPPORT_CENTRAL_STRUCTURAL_THREATS_V146) {
    if (pattern.test(ctx.sample || '')) {
      const authority = await supportCentralBanAuthorityV354();
      const persisted = await authority.ban(ctx.req, 'support_' + name, 15 * 60);
      if (!persisted || persisted.ok !== true) throw new PublicError(503, 'CENTRAL_BAN_PERSISTENCE_FAILED', 'Blokir keamanan pusat tidak dapat dipastikan tersimpan.');
      const error = new PublicError(403, 'CENTRAL_THREAT_REJECTED', 'Request diblokir oleh pemeriksaan keamanan: ' + name + '.');
      error.retryAfter = Math.max(1, Math.floor(Number(persisted.ttl_seconds || 15 * 60)));
      throw error;
    }
  }
}
async function supportCentralGuardZeroDayV202(ctx) {
  const rawUrl = String(ctx.req.url || '');
  if (Buffer.byteLength(rawUrl, 'utf8') > 4096 || /%(?:00|0d|0a)/i.test(rawUrl)) throw new PublicError(400, 'CENTRAL_REQUEST_ENCODING_REJECTED', 'Encoding request tidak diizinkan.');
}
async function supportCentralGuardOwnershipV202(ctx) { supportCentralValidateIdentifiersV146(ctx); }
async function supportCentralGuardCircuitBreakerV202(ctx) { supportCentralCircuitCheckV146(ctx); }
async function supportCentralGuardMfaV202(ctx) { supportCentralMfaPrecheckV146(ctx); }
async function supportCentralGuardIntegrityV202(ctx) {
  const policyActions = Object.keys(DIRAC_SUPPORT_CENTRAL_ACTION_POLICY_V146).sort();
  const handlerActions = Object.keys(DIRAC_SUPPORT_ACTION_HANDLERS_V146).sort();
  const expectedActions = DIRAC_SUPPORT_CENTRAL_EXPECTED_ACTIONS_V146.slice();
  if (JSON.stringify(policyActions) !== JSON.stringify(handlerActions)
      || JSON.stringify(policyActions) !== JSON.stringify(expectedActions)
      || DIRAC_SUPPORT_CENTRAL_PIPELINE_V146.length !== 30
      || ctx.policy !== DIRAC_SUPPORT_CENTRAL_ACTION_POLICY_V146[ctx.action]) {
    throw new PublicError(500, 'CENTRAL_INTEGRITY_FAILED', 'Integritas Central Guard support gagal.');
  }
}

const DIRAC_SUPPORT_CENTRAL_PIPELINE_V146 = Object.freeze([
  Object.freeze({ name: 'identity', guard: supportCentralGuardIdentityV202 }),
  Object.freeze({ name: 'memory ban', guard: supportCentralGuardMemoryBanV202 }),
  Object.freeze({ name: 'persistent ban', guard: supportCentralGuardPersistentBanV202 }),
  Object.freeze({ name: 'action format', guard: supportCentralGuardActionFormatV202 }),
  Object.freeze({ name: 'alias', guard: supportCentralGuardAliasV202 }),
  Object.freeze({ name: 'whitelist', guard: supportCentralGuardWhitelistV202 }),
  Object.freeze({ name: 'server role', guard: supportCentralGuardServerRoleV202 }),
  Object.freeze({ name: 'ENV partition', guard: supportCentralGuardEnvironmentV202 }),
  Object.freeze({ name: 'classification', guard: supportCentralGuardClassificationV202 }),
  Object.freeze({ name: 'rate limit', guard: supportCentralGuardRateV202 }),
  Object.freeze({ name: 'server authentication', guard: supportCentralGuardServerAuthenticationV202 }),
  Object.freeze({ name: 'browser authenticity', guard: supportCentralGuardBrowserAuthenticityV202 }),
  Object.freeze({ name: 'CSRF', guard: supportCentralGuardCsrfV202 }),
  Object.freeze({ name: 'page nonce', guard: supportCentralGuardPageNonceV202 }),
  Object.freeze({ name: 'browser signal', guard: supportCentralGuardBrowserSignalsV202 }),
  Object.freeze({ name: 'device binding', guard: supportCentralGuardDeviceBindingV202 }),
  Object.freeze({ name: 'admin authentication', guard: supportCentralGuardAdminAuthenticationV202 }),
  Object.freeze({ name: 'public-read policy', guard: supportCentralGuardPublicReadV202 }),
  Object.freeze({ name: 'body validation', guard: supportCentralGuardBodyV202 }),
  Object.freeze({ name: 'light guard', guard: supportCentralGuardLightV202 }),
  Object.freeze({ name: 'contract validation', guard: supportCentralGuardContractV202 }),
  Object.freeze({ name: 'A2F signature', guard: supportCentralGuardA2FV202 }),
  Object.freeze({ name: 'security report', guard: supportCentralGuardSecurityReportV202 }),
  Object.freeze({ name: 'request sample', guard: supportCentralGuardRequestSampleV202 }),
  Object.freeze({ name: 'threat detection', guard: supportCentralGuardThreatV202 }),
  Object.freeze({ name: 'zero-day protection', guard: supportCentralGuardZeroDayV202 }),
  Object.freeze({ name: 'IDOR/BOLA', guard: supportCentralGuardOwnershipV202 }),
  Object.freeze({ name: 'circuit breaker', guard: supportCentralGuardCircuitBreakerV202 }),
  Object.freeze({ name: 'MFA', guard: supportCentralGuardMfaV202 }),
  Object.freeze({ name: 'integrity', guard: supportCentralGuardIntegrityV202 })
]);

const DIRAC_SUPPORT_ACTION_HANDLERS_V146 = Object.freeze({
  status_bootstrap: actionStatusBootstrap,
  chat_public_config: actionChatPublicConfig,
  admin_public_config: actionAdminPublicConfig,
  chat_bootstrap: actionChatBootstrap,
  chat_start: actionChatStart,
  chat_send: actionChatSend,
  chat_close: actionChatClose,
  customer_access_refresh: actionCustomerRefresh,
  admin_login: actionAdminLogin,
  admin_mfa_verify: actionAdminMfaVerify,
  admin_bootstrap: actionAdminBootstrap,
  admin_queue: actionAdminQueue,
  admin_thread: actionAdminThread,
  admin_send: actionAdminSend,
  admin_conversation_update: actionAdminConversationUpdate,
  admin_status_snapshot: actionAdminStatusSnapshot,
  admin_component_update: actionAdminComponentUpdate,
  admin_monitor_config_update: actionAdminMonitorConfigUpdate,
  admin_incident_create: actionAdminIncidentCreate,
  admin_incident_advance: actionAdminIncidentAdvance,
  admin_maintenance_create: actionAdminMaintenanceCreate,
  admin_logout: actionAdminLogout,
  monitor_run: actionMonitorRun
});

async function dispatch(req, res, action, body) {
  if (String(action || '').startsWith('admin_')) requireAdminBuildBinding(req);
  const actionHandler = DIRAC_SUPPORT_ACTION_HANDLERS_V146[action];
  if (typeof actionHandler !== 'function') throw new PublicError(404, 'ACTION_NOT_FOUND', 'Action support tidak ditemukan.');
  return actionHandler(req, res, body);
}

function supportCentralContextV146(req, res) {
  let parsedUrl;
  try { parsedUrl = new URL(String(req && req.url || '/'), 'https://support.invalid'); }
  catch (_) { parsedUrl = new URL('https://support.invalid/'); }
  return {
    req,
    res,
    requestId: uuid(),
    parsedUrl,
    rawAction: '',
    action: '',
    method: String(req && req.method || 'GET').trim().toUpperCase(),
    policy: null,
    body: null,
    sample: '',
    fingerprint: '',
    passport: 0n,
    phase: 'guard',
    fullyPassed: false,
    preflight: false,
    currentStage: '',
    startedAt: Date.now()
  };
}

async function handler(req, res) {
  const ctx = supportCentralContextV146(req, res);
  return DIRAC_SUPPORT_CENTRAL_CONTEXT_V146.run(ctx, async () => {
    req.diracRequestId = ctx.requestId;
    try {
      const diagnosticEntryActionV359 = String(queryValue(req, 'action') || '').trim().toLowerCase();
      if (diagnosticEntryActionV359 === 'chat_public_config') console.error('[dirac-support-chat-public-config-entry-v359]', JSON.stringify({ patch: 'dirac-support-chat-public-config-diagnostic-v359', event: 'entry', requestId: ctx.requestId, method: ctx.method, originPresent: Boolean(requestOrigin(req)), originAllowed: originAllowed(req) }));
    } catch (_) {}
    let caught = null;
    try {
      securityHeaders(req, res, String(queryValue(req, 'action') || '').trim().toLowerCase());
      setHeader(res, 'X-Dirac-Request-ID', ctx.requestId);
      setHeader(res, 'X-Dirac-Central-Security-Guard', DIRAC_SUPPORT_CENTRAL_SECURITY_GUARD_V146);
      for (let index = 0; index < DIRAC_SUPPORT_CENTRAL_PIPELINE_V146.length; index += 1) {
        const stage = DIRAC_SUPPORT_CENTRAL_PIPELINE_V146[index];
        ctx.currentStage = stage.name;
        if (Date.now() - ctx.startedAt > 5000) throw new PublicError(503, 'CENTRAL_GUARD_TIMEOUT', 'Central Guard support melewati batas waktu.');
        await stage.guard(ctx);
        ctx.passport |= 1n << BigInt(index);
      }
      const allCheckpoints = (1n << BigInt(DIRAC_SUPPORT_CENTRAL_PIPELINE_V146.length)) - 1n;
      if (ctx.passport !== allCheckpoints) throw new PublicError(500, 'CENTRAL_INTEGRITY_FAILED', 'Checkpoint Central Guard tidak lengkap.');
      if (ctx.preflight) {
        res.statusCode = 204;
        return res.end();
      }
      ctx.fullyPassed = true;
      ctx.phase = 'handler';
      Object.defineProperty(req, '__diracSupportCentralSecurityGuardPassedV146', { value: true, enumerable: false, writable: false, configurable: false });
      req.diracSupportAction = ctx.action;
      req.diracSupportBody = ctx.body;
      const result = await dispatch(req, res, ctx.action, ctx.body);
      supportCentralRecordOutcomeV146(ctx, null);
      return result;
    } catch (error) {
      caught = error;
      ctx.phase = 'audit';
      const safe = error instanceof PublicError ? error : new PublicError(500, 'SUPPORT_INTERNAL_ERROR', 'Sistem support sedang mengalami gangguan.');
      if ((ctx.action === 'admin_login' || ctx.action === 'admin_mfa_verify') && req.diracAuthAuditEligible === true && req.diracAuthOutcome !== 'success') {
        const pending = ctx.action === 'admin_mfa_verify' ? readSession(req, MFA_COOKIE) : null;
        const attemptedEmail = ctx.action === 'admin_login' && ctx.body && typeof ctx.body === 'object' ? String(ctx.body.email || '').slice(0, 254) : '';
        try { await recordAdminAuth(req, pending && pending.uid || null, 'admin.auth.rejected', attemptedEmail, 'rejected', safe.code); }
        catch (auditError) { supportCentralRecordSuppressedExceptionV221(auditError); }
      }
      if (safe.allow) setHeader(res, 'Allow', safe.allow);
      if (safe.retryAfter) setHeader(res, 'Retry-After', String(safe.retryAfter));
      supportCentralRecordOutcomeV146(ctx, error);
      let diagnosticRequestedActionV359 = String(ctx.action || '').trim().toLowerCase();
      try { if (!diagnosticRequestedActionV359) diagnosticRequestedActionV359 = String(queryValue(req, 'action') || '').trim().toLowerCase(); } catch (_) {}
      if (diagnosticRequestedActionV359 === 'chat_public_config') {
        try {
          const diagnosticPublishableKeyV358 = env('DIRAC_SUPPORT_SUPABASE_PUBLISHABLE_KEY') || env('DIRAC_SUPPORT_SUPABASE_ANON_KEY');
          const diagnosticSecretKeyV358 = env('DIRAC_SUPPORT_SUPABASE_SECRET_KEY') || env('DIRAC_SUPPORT_SUPABASE_SERVICE_ROLE_KEY');
          const diagnosticCookieSecretV358 = env('DIRAC_SUPPORT_COOKIE_SECRET');
          const diagnosticCsrfSecretV358 = env('DIRAC_SUPPORT_CSRF_SECRET');
          const diagnosticIpSecretV358 = env('DIRAC_SUPPORT_IP_HMAC_SECRET');
          const diagnosticCustomerSecretsV358 = [diagnosticCookieSecretV358, diagnosticCsrfSecretV358, diagnosticIpSecretV358];
          const diagnosticTurnstileRequiredV358 = envTrue('DIRAC_SUPPORT_REQUIRE_TURNSTILE', isProduction());
          console.error('[dirac-support-chat-public-config-diagnostic-v359]', JSON.stringify({
            patch: 'dirac-support-chat-public-config-diagnostic-v359',
            event: 'chat_public_config_failed',
            requestId: ctx.requestId,
            requestedAction: diagnosticRequestedActionV359,
            parsedAction: String(ctx.action || '').slice(0, 64),
            status: safe.status,
            code: safe.code,
            rawCode: String(error && (error.code || '') || '').slice(0, 80),
            rawName: String(error && (error.name || '') || '').slice(0, 80),
            boundary: ctx.fullyPassed === true ? 'handler' : 'guard',
            stage: String(ctx.currentStage || '').slice(0, 80),
            passportHex: ctx.passport.toString(16),
            request: { method: ctx.method, originPresent: Boolean(requestOrigin(req)), originAllowed: originAllowed(req) },
            mainIdentity: req.__diracSupportMainIdentityDiagnosticV360 || null,
            customerConfig: {
              supabaseUrlShapeOk: /^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(env('DIRAC_SUPPORT_SUPABASE_URL').replace(/\/+$/, '')),
              publishableKeyClassOk: /^sb_publishable_[A-Za-z0-9_-]{10,}$/.test(diagnosticPublishableKeyV358) || decodeJwt(diagnosticPublishableKeyV358).role === 'anon',
              secretKeyClassOk: /^sb_secret_[A-Za-z0-9_-]{10,}$/.test(diagnosticSecretKeyV358) || decodeJwt(diagnosticSecretKeyV358).role === 'service_role',
              customerCookieSecretStrong: Buffer.byteLength(diagnosticCookieSecretV358, 'utf8') >= 32,
              customerCsrfSecretStrong: Buffer.byteLength(diagnosticCsrfSecretV358, 'utf8') >= 32,
              customerIpSecretStrong: Buffer.byteLength(diagnosticIpSecretV358, 'utf8') >= 32,
              customerSecretsDistinct: new Set(diagnosticCustomerSecretsV358).size === diagnosticCustomerSecretsV358.length,
              turnstileRequired: diagnosticTurnstileRequiredV358,
              turnstileSiteKeyPresent: Boolean(env('DIRAC_SUPPORT_TURNSTILE_SITE_KEY')),
              turnstileSecretKeyPresent: Boolean(env('DIRAC_SUPPORT_TURNSTILE_SECRET_KEY'))
            }
          }));
        } catch (diagnosticErrorV358) { supportCentralRecordSuppressedExceptionV221(diagnosticErrorV358); }
      }
      if (!(error instanceof PublicError)) {
        try { console.error('[dirac-support]', JSON.stringify({ requestId: ctx.requestId, action: ctx.action, stage: ctx.currentStage, code: String(error && (error.code || error.name) || 'ERROR').slice(0, 80), message: supportSafeDiagnosticMessageV356(error) })); } catch (_) {}
      }
      return json(res, safe.status, { ok: false, code: safe.code, message: safe.message, requestId: ctx.requestId, time: nowIso() });
    } finally {
      ctx.sample = '';
      ctx.body = null;
      req.diracSupportBody = null;
      if (caught && !(caught instanceof PublicError)) supportCentralRecordSuppressedExceptionV221(caught);
    }
  });
}

const supportActionNamesV146 = Object.keys(DIRAC_SUPPORT_CENTRAL_ACTION_POLICY_V146).sort();
const supportHandlerNamesV146 = Object.keys(DIRAC_SUPPORT_ACTION_HANDLERS_V146).sort();
if (JSON.stringify(supportActionNamesV146) !== JSON.stringify(supportHandlerNamesV146)
    || JSON.stringify(supportActionNamesV146) !== JSON.stringify(DIRAC_SUPPORT_CENTRAL_EXPECTED_ACTIONS_V146)
    || DIRAC_SUPPORT_CENTRAL_PIPELINE_V146.length !== 30) {
  throw new Error('DIRAC_SUPPORT_CENTRAL_STARTUP_INTEGRITY_FAILED');
}

handler.config = { api: { bodyParser: false } };
handler.__diracSupportCentralSecurityGuardV146 = true;
handler.__diracSupportCentralBanAuthorityV354 = DIRAC_SUPPORT_CENTRAL_BAN_AUTHORITY_V354;
handler.__diracSupportCentralActionCountV146 = supportActionNamesV146.length;
handler.__test = Object.freeze({
  text, messageText, email, seal, unseal, isPrivateIp, normalizeMonitorUrl,
  resolveMonitorAddress, probeTarget, canManageStatus, decodeJwt, normalizeSnapshot,
  runtimeCookieName, clientIp, verifyQueryShape, fetchJson, normalizeAuthority,
  readJson, supportValidateBodySchemaV361, supportProviderUserAllowed, supportProviderClaims,
  csrfBundle, verifyCsrf, supportAssertDatabaseOperationV361,
  mainDisplayName, supportCustomerMaterial, customerSessionMatches,
  centralActionNames: Object.freeze(supportActionNamesV146.slice()),
  centralPipelineNames: Object.freeze(DIRAC_SUPPORT_CENTRAL_PIPELINE_V146.map((stage) => stage.name)),
  centralGuardVersion: DIRAC_SUPPORT_CENTRAL_SECURITY_GUARD_V146
});
Object.freeze(handler.config.api);
Object.freeze(handler.config);
Object.freeze(handler);
export default handler;

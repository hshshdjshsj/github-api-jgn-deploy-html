'use strict';

// Standalone administrator endpoint. The browser page is handled entirely by this module.
const crypto = require('node:crypto');
const tls = require('node:tls');

const ADMIN_EMAIL = 'dinzganteng888999@gmail.com';
const VERSION = 'dirac-admin-v405';
const PREFIX = 's2s-admin-v405:';
const PASSWORD_VERSION = 'dirac-admin-password-v411';
const PASSWORD_PREFIX = 's2s-admin-v411:password:';
const PAGE_NONCE_PREFIX = 's2s-admin-v411:page-nonce:';
const SECURITY_REPORT_PREFIX = 's2s-admin-v411:security-report:';
const SECURITY_BLOCK_PREFIX = 's2s-admin-v411:security-block:';
const SECURITY_BLOCK_SECONDS = 86400;
const PASSWORD_COOKIE = '__Host-dirac_admin_password_v411';
const SESSION_COOKIE = '__Host-dirac_admin_v405';
const EMAIL_CODE_MIN = 600;
const EMAIL_CODE_MAX = 960;
const EMAIL_CODE_SECONDS = 300;
const FACTOR_SECONDS = 600;
const ENROLLMENT_SECONDS = 100 * 365 * 24 * 60 * 60;
const PASSWORD_SECONDS = ENROLLMENT_SECONDS;
const SESSION_SECONDS = ENROLLMENT_SECONDS;
const PENDING_ENROLLMENT_SECONDS = 24 * 60 * 60;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const COMMON_PROOF = ['csrf', 'nonce', 'idempotency_key'];
const PASSKEY_FIELDS = ['credential', 'id', 'rawId', 'type', 'response', 'clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle', 'clientExtensionResults', 'credProps', 'rk', 'transports', 'authenticatorAttachment'];
const post = (fields, required = [], max = 16384) => Object.freeze({ methods: Object.freeze(['POST']), allowed: Object.freeze(['action', ...COMMON_PROOF, ...fields]), required: Object.freeze(required), maxBodyBytes: max, maxFieldBytes: max === 98304 ? 81920 : 4096, mutation: true, allowArrayItems: max === 98304 });
const get = (fields = []) => Object.freeze({ methods: Object.freeze(['GET', 'HEAD']), allowed: Object.freeze(['action', '_csrf_boot', '_csrf_bootstrap', '_dirac_page_nonce_for', '_page_nonce_for', 'page_nonce_for', '_ts', '_t', '_', ...fields]), required: Object.freeze([]), maxBodyBytes: 1024, maxFieldBytes: 3000, mutation: false });
const CONTRACTS = Object.freeze({
  admin_entry: get(),
  admin_security_report: post(['reason', 'type', 'page', 'event', 'evidence', 'version'], ['reason', 'type', 'page', 'event', 'evidence', 'version'], 32768),
  admin_login: post(['email', 'password'], ['email', 'password']),
  admin_status: get(),
  admin_email_start: post([]),
  admin_email_verify: post(['ticket', 'code'], ['ticket', 'code']),
  admin_action_email_start: post(['operation', 'payload'], ['operation', 'payload']),
  admin_action_email_verify: post(['ticket', 'code'], ['ticket', 'code']),
  admin_passkey_start: post(['ticket'], ['ticket']),
  admin_passkey_verify: post(['ticket', ...PASSKEY_FIELDS], ['ticket', 'credential'], 98304),
  admin_totp_verify: post(['ticket', 'code'], ['ticket', 'code']),
  admin_logout: post([]),
  admin_orders: get(['kind', 'offset']),
  admin_shipment_update: post(['kind', 'order_id', 'expected_revision', 'tracking_number', 'courier', 'status', 'location', 'origin', 'destination', 'estimated_delivery', 'description', 'approval'], ['kind', 'order_id', 'expected_revision', 'tracking_number', 'courier', 'status', 'approval']),
  admin_shipment_cancel: post(['kind', 'order_id', 'expected_revision', 'description', 'approval'], ['kind', 'order_id', 'expected_revision', 'approval']),
  admin_blocks: get(['offset']),
  admin_unban: post(['block_id', 'approval'], ['block_id', 'approval']),
  admin_monitor: get()
});
const ACTIONS = Object.freeze(Object.keys(CONTRACTS));
const ADMIN_APPROVAL_MUTATIONS = Object.freeze({ admin_shipment_update: 'shipment_update', admin_shipment_cancel: 'shipment_cancel', admin_unban: 'unban' });
const ORDER_SELECT = Object.freeze({
  regular: 'id,order_id,customer_id,customer_name,customer_email,customer_phone,shipping_address,service_type,total,payment_method,payment_status,order_status,created_at',
  domain: 'id,customer_id,customer_name,customer_email,customer_whatsapp,domain_name,total_price,currency,payment_status,order_status,created_at'
});
const SHIPMENT_PREFIX = 's2s-admin-shipment-v406:';
const SHIPMENT_SELECT = 'security_key,record_json,blocked_until_ms,expires_at,updated_at';
const ACCESS_BLOCK_SELECT = 'security_key,record_json,blocked_until_ms,expires_at';
const ACCESS_BLOCK_RECORD_KEYS = Object.freeze(['action', 'block_id', 'blocked_until_ms', 'created_at_ms', 'customer_id', 'device_hash', 'fail_count', 'ip_hash', 'metadata', 'reason', 'revocation', 'schema', 'state', 'storage_keys', 'updated_at_ms', 'version'].sort());
const ALLOWED_RESPONSE_STATUSES = new Set([400, 401, 403, 404, 405, 409, 413, 415, 429, 503]);

function fail(code, status = 400) { throw Object.assign(new Error(code), { code, status, statusCode: status }); }
function digest(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function digest512(value) { return crypto.createHash('sha512').update(String(value)).digest('hex'); }
function randomToken() { return crypto.randomBytes(32).toString('base64url'); }
function adminEmailCode() {
  const length = crypto.randomInt(EMAIL_CODE_MIN, EMAIL_CODE_MAX + 1), chars = crypto.randomBytes(length).toString('base64url').slice(0, length).split(''), letterAt = crypto.randomInt(0, length);
  let digitAt = crypto.randomInt(0, length - 1); if (digitAt >= letterAt) digitAt += 1;
  const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', digits = '23456789'; chars[letterAt] = letters[crypto.randomInt(0, letters.length)]; chars[digitAt] = digits[crypto.randomInt(0, digits.length)];
  return chars.join('');
}
function validAdminEmailCode(value) { return typeof value === 'string' && value.length >= EMAIL_CODE_MIN && value.length <= EMAIL_CODE_MAX && /^[A-Za-z0-9_-]+$/.test(value) && /[A-Za-z]/.test(value) && /[0-9]/.test(value); }
function exactToken(value) { return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value); }
function safeEqual(a, b) { const aa = Buffer.from(String(a)), bb = Buffer.from(String(b)); return aa.length === bb.length && crypto.timingSafeEqual(aa, bb); }
function isUuid(value) { return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(String(value || '').trim().toLowerCase()); }
function isEmail(value) { return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(String(value || '').trim().toLowerCase()); }
function stableJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stableJson(value[key])).join(',') + '}';
}
function syntheticAdminUuid() {
  const source = digest('dirac-admin-audit-id:' + ADMIN_EMAIL).slice(0, 32).split('');
  source[12] = '4'; source[16] = '8';
  const hex = source.join('');
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
}
const ADMIN_USER_ID = syntheticAdminUuid();

function isProduction() { return String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production'; }
function rootSecret() {
  const secret = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '').trim();
  const minimum = isProduction() ? 3000 : 32;
  if (Buffer.byteLength(secret, 'utf8') < minimum) fail('ADMIN_SECRET_UNAVAILABLE', 503);
  return secret;
}
function deriveSecret(scope) { return crypto.createHmac('sha512', rootSecret()).update('dirac-derived-secret-v146:' + String(scope || 'default').slice(0, 120)).digest(); }
function adminSecretState() {
  const secret = String(process.env.AI_ADMIN_SECRET || '');
  if (!secret) return { configured: false, secret: '' };
  if (Buffer.byteLength(secret, 'utf8') < 32 || /[\u0000\r\n]/.test(secret)) return { configured: false, secret: '' };
  return { configured: true, secret };
}
function secretBinding(secret) {
  const key = deriveSecret('admin-secret-binding-v411');
  try { return crypto.createHmac('sha256', key).update(digest(secret)).digest('hex'); }
  finally { key.fill(0); }
}
function base32(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, value = 0, out = '';
  for (const byte of buffer) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { out += alphabet[(value >>> (bits -= 5)) & 31]; } }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
function totp(secret, counter) {
  const message = Buffer.alloc(8); message.writeBigUInt64BE(BigInt(counter));
  const hash = crypto.createHmac('sha1', secret).update(message).digest();
  const index = hash[hash.length - 1] & 15;
  return String((hash.readUInt32BE(index) & 0x7fffffff) % 1000000).padStart(6, '0');
}
function encryptionKey(ops) {
  const key = ops.deriveKey('totp-storage');
  if (!Buffer.isBuffer(key) || key.length !== 32) fail('ADMIN_SECRET_UNAVAILABLE', 503);
  return key;
}
function seal(ops, value, context) {
  const key = encryptionKey(ops), nonce = crypto.randomBytes(12);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(VERSION + ':' + context));
    const encrypted = Buffer.concat([cipher.update(value), cipher.final()]);
    return [nonce, encrypted, cipher.getAuthTag()].map(v => v.toString('base64url')).join('.');
  } finally { key.fill(0); }
}
function open(ops, value, context) {
  const key = encryptionKey(ops);
  try {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) fail('ADMIN_STATE_INVALID', 503);
    const parts = value.split('.').map(v => decodeB64url(v, 64));
    if (parts[0].length !== 12 || parts[1].length !== 32 || parts[2].length !== 16) fail('ADMIN_STATE_INVALID', 503);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, parts[0]);
    decipher.setAAD(Buffer.from(VERSION + ':' + context)); decipher.setAuthTag(parts[2]);
    return Buffer.concat([decipher.update(parts[1]), decipher.final()]);
  } catch (error) { if (error && error.code === 'ADMIN_SECRET_UNAVAILABLE') throw error; fail('ADMIN_STATE_INVALID', 503); }
  finally { key.fill(0); }
}

function cleanHost(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw || /[\u0000-\u0020\u007f/@\\]/.test(raw)) return '';
  try { const url = new URL('https://' + raw); return url.username || url.password || url.pathname !== '/' || url.search || url.hash ? '' : url.host; }
  catch (_) { return ''; }
}
function loopbackHost(hostname) { return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]'; }
function requestHost(req) {
  const headers = req && req.headers || {}, forwardedRaw = String(headers['x-forwarded-host'] || ''), directRaw = String(headers.host || '');
  const forwarded = forwardedRaw ? cleanHost(forwardedRaw) : '', direct = directRaw ? cleanHost(directRaw) : '';
  if ((forwardedRaw && !forwarded) || (directRaw && !direct) || (forwarded && direct && forwarded !== direct)) return '';
  return forwarded || direct;
}
function sourceOrigin(req) {
  const raw = String(req.headers && req.headers.origin || '').trim();
  let origin;
  try { origin = new URL(raw); } catch (_) { fail('ADMIN_ORIGIN_INVALID', 403); }
  if (origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') fail('ADMIN_ORIGIN_INVALID', 403);
  const host = requestHost(req); if (!host) fail('ADMIN_ORIGIN_INVALID', 403);
  const requestName = new URL('https://' + host).hostname.toLowerCase();
  const sourceName = origin.hostname.toLowerCase();
  if (loopbackHost(requestName) && loopbackHost(sourceName)) {
    if (!['http:', 'https:'].includes(origin.protocol)) fail('ADMIN_ORIGIN_INVALID', 403);
  } else {
    if (origin.protocol !== 'https:' || origin.port || !requestName.startsWith('api.') || sourceName !== 'pt.' + requestName.slice(4)) fail('ADMIN_ORIGIN_INVALID', 403);
  }
  return origin.origin;
}
function validateReferer(req, origin, allowPreflight = false) {
  const raw = String(req.headers && (req.headers.referer || req.headers.referrer) || '').trim();
  if (!raw && allowPreflight) return true;
  let ref; try { ref = new URL(raw); } catch (_) { fail('ADMIN_REFERER_INVALID', 403); }
  if (ref.origin !== origin || ref.pathname !== '/admin.html' || ref.search || ref.hash || ref.username || ref.password) fail('ADMIN_REFERER_INVALID', 403);
  return true;
}
function deviceFingerprint(req, origin) {
  const h = req.headers || {};
  const values = [origin, String(h['user-agent'] || ''), String(h['sec-ch-ua'] || ''), String(h['sec-ch-ua-platform'] || ''), String(h['accept-language'] || '')];
  if (values.some(value => value.length > 2048 || /[\u0000\r\n]/.test(value))) fail('ADMIN_CLIENT_HEADERS_INVALID', 400);
  return digest(values.join('\0'));
}
function requestIp(req) {
  const value = String(req.headers && (req.headers['x-forwarded-for'] || req.headers['x-real-ip']) || '').split(',')[0].trim();
  return value && value.length <= 80 && !/[\u0000\r\n]/.test(value) ? value : 'unknown';
}
function parseCookies(req) {
  const raw = String(req.headers && req.headers.cookie || '');
  if (!raw || raw.length > 16384 || /[\u0000\r\n]/.test(raw)) return new Map();
  return raw.split(';').reduce((map, item) => {
    const index = item.indexOf('='); if (index <= 0) return map;
    const name = item.slice(0, index).trim(), value = item.slice(index + 1).trim();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/.test(name)) return map;
    if (map.has(name)) { map.set(name, null); return map; }
    map.set(name, value); return map;
  }, new Map());
}
function appendCookie(res, value) {
  const current = res.getHeader && res.getHeader('Set-Cookie');
  const list = current ? (Array.isArray(current) ? current.slice() : [String(current)]) : [];
  list.push(value); res.setHeader('Set-Cookie', list);
}
function cookieToken(req, name) { const value = parseCookies(req).get(name) || ''; return exactToken(value) ? value : ''; }

function securityCredentials() {
  const url = String(process.env.DIRAC_SECURITY_SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const anon = String(process.env.DIRAC_SECURITY_SUPABASE_ANON_KEY || '').trim();
  const service = String(process.env.DIRAC_SECURITY_SUPABASE_SERVICE_ROLE_KEY || '').trim();
  if (!url || !anon || !service) fail('ADMIN_SECURITY_DATABASE_UNAVAILABLE', 503);
  validateSupabaseOrigin(url); return { url, anon, service };
}
function multiDbEnabled() { return /^(?:1|true|yes|on)$/i.test(String(process.env.DIRAC_ENABLE_MULTI_DB_ROUTER || process.env.DIRAC_MULTI_DB_ROUTER_ENABLED || '').trim()); }
function businessTarget(table) {
  const map = { domain_orders: 'DOMAIN', orders: 'COMMERCE', security_customer_events: 'PAYMENT_SERVICE' };
  if (!multiDbEnabled() || !map[table]) return legacyCredentials();
  const prefix = 'DIRAC_' + map[table] + '_SUPABASE_';
  const url = String(process.env[prefix + 'URL'] || '').trim().replace(/\/+$/, '');
  const anon = String(process.env[prefix + 'ANON_KEY'] || '').trim();
  const service = String(process.env[prefix + 'SERVICE_ROLE_KEY'] || '').trim();
  if (url && anon && service) { validateSupabaseOrigin(url); return { url, anon, service }; }
  if (/^(?:1|true|yes|on)$/i.test(String(process.env.DIRAC_MULTI_DB_STRICT || '').trim())) fail('ADMIN_DATA_UNAVAILABLE', 503);
  return legacyCredentials();
}
function legacyCredentials() {
  const url = String(process.env.DOMAIN_SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const anon = String(process.env.DOMAIN_SUPABASE_ANON_KEY || '').trim();
  const service = String(process.env.DOMAIN_SUPABASE_SERVICE_ROLE_KEY || '').trim();
  if (!url || !anon || !service) fail('ADMIN_DATA_UNAVAILABLE', 503);
  validateSupabaseOrigin(url); return { url, anon, service };
}
function validateSupabaseOrigin(value) {
  let url; try { url = new URL(value); } catch (_) { fail('ADMIN_DATABASE_CONFIGURATION_INVALID', 503); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || (url.port && url.port !== '443') || url.pathname !== '/') fail('ADMIN_DATABASE_CONFIGURATION_INVALID', 503);
}
function tableFromPath(path) {
  const match = /^\/rest\/v1\/([^?\/]+)/.exec(String(path || ''));
  if (!match || match[1] === 'rpc') return '';
  try { return decodeURIComponent(match[1]); } catch (_) { return ''; }
}
async function dbFetch(path, options = {}, target = '') {
  const cleanPath = String(path || '');
  const method = String(options.method || 'GET').toUpperCase();
  if (!cleanPath.startsWith('/rest/v1/') || cleanPath.startsWith('//') || cleanPath.includes('\\') || /[\r\n\0]/.test(cleanPath) || !['GET', 'POST', 'PATCH'].includes(method)) fail('ADMIN_DATABASE_REQUEST_INVALID', 503);
  let creds;
  if (target === 'security' || cleanPath.startsWith('/rest/v1/rpc/') || ['dirac_s2s_security', 'dirac_persistent_bans'].includes(tableFromPath(cleanPath))) creds = securityCredentials();
  else creds = businessTarget(tableFromPath(cleanPath));
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 12000);
  try {
    const headers = { apikey: creds.service, Authorization: 'Bearer ' + creds.service, Accept: 'application/json' };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (options.prefer) headers.Prefer = options.prefer;
    const response = await fetch(creds.url + cleanPath, { method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body), redirect: 'error', signal: controller.signal });
    const raw = await response.text();
    if (Buffer.byteLength(raw, 'utf8') > MAX_RESPONSE_BYTES) fail('ADMIN_DATABASE_RESPONSE_INVALID', 503);
    let data = null; if (raw) { try { data = JSON.parse(raw); } catch (_) { fail('ADMIN_DATABASE_RESPONSE_INVALID', 503); } }
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    if (error && /^ADMIN_/.test(String(error.code || ''))) throw error;
    return { ok: false, status: 0, data: null };
  } finally { clearTimeout(timer); }
}
async function securityRead(key) {
  if (!/^[A-Za-z0-9:._-]{1,500}$/.test(String(key || ''))) fail('ADMIN_STORAGE_KEY_INVALID', 503);
  const result = await dbFetch('/rest/v1/dirac_s2s_security?select=security_key,record_json,expires_at&security_key=eq.' + encodeURIComponent(key) + '&limit=1', { method: 'GET' }, 'security');
  if (!result.ok || !Array.isArray(result.data) || result.data.length > 1) return { ok: false };
  if (!result.data.length) return { ok: true, found: false };
  const row = result.data[0], expires = Date.parse(String(row && row.expires_at || ''));
  if (!row || row.security_key !== key || !Number.isFinite(expires) || !row.record_json || typeof row.record_json !== 'object' || Array.isArray(row.record_json)) return { ok: false };
  return expires <= Date.now() ? { ok: true, found: false } : { ok: true, found: true, record: row.record_json, expiresAt: row.expires_at };
}
async function securityClaim(key, record, ttl) {
  if (!/^[A-Za-z0-9:._-]{1,500}$/.test(String(key || '')) || !record || typeof record !== 'object' || Array.isArray(record) || !Number.isSafeInteger(ttl) || ttl < 60 || ttl > ENROLLMENT_SECONDS) fail('ADMIN_STORAGE_CLAIM_INVALID', 503);
  const result = await dbFetch('/rest/v1/rpc/dirac_central_atomic_claim_record_v230', { method: 'POST', body: { p_table_name: 'dirac_s2s_security', p_security_key: key, p_record_json: record, p_expires_at: new Date(Date.now() + ttl * 1000).toISOString() } }, 'security');
  return !!(result.ok && result.data === true);
}
async function atomicRate(key, limit, seconds) {
  if (!/^[A-Za-z0-9:._-]{1,500}$/.test(String(key || '')) || !Number.isSafeInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger(seconds) || seconds < 1 || seconds > 86400) fail('ADMIN_RATE_CONTRACT_INVALID', 503);
  const result = await dbFetch('/rest/v1/rpc/dirac_central_atomic_rate_limit_v230', { method: 'POST', body: { p_security_key: key, p_limit: limit, p_window_seconds: seconds, p_block_seconds: seconds } }, 'security');
  const row = result.ok && Array.isArray(result.data) && result.data.length === 1 ? result.data[0] : null;
  if (!row || typeof row.allowed !== 'boolean') fail('ADMIN_RATE_STORE_UNAVAILABLE', 503);
  return row.allowed === true;
}

function passwordProofKey(token) { return PASSWORD_PREFIX + digest(token); }
function pageNonceKey(token) { return PAGE_NONCE_PREFIX + digest(token); }
function scopeBinding(origin, device, secret) {
  const key = deriveSecret('admin-request-binding-v411');
  try { return crypto.createHmac('sha256', key).update([ADMIN_USER_ID, ADMIN_EMAIL, origin, device, secretBinding(secret)].join('\0')).digest('hex'); }
  finally { key.fill(0); }
}
async function publishPasswordProof(req, res, origin, device, secret) {
  const token = randomToken(), now = Date.now();
  const record = { version: PASSWORD_VERSION, userId: ADMIN_USER_ID, email: ADMIN_EMAIL, origin, device, secretBinding: secretBinding(secret), createdAt: now, expiresAt: now + PASSWORD_SECONDS * 1000 };
  if (await securityClaim(passwordProofKey(token), record, PASSWORD_SECONDS) !== true) fail('ADMIN_PROOF_STORE_UNAVAILABLE', 503);
  appendCookie(res, PASSWORD_COOKIE + '=' + token + '; Path=/; Secure; HttpOnly; SameSite=Strict');
  appendCookie(res, SESSION_COOKIE + '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0');
  return record;
}
async function verifyPasswordProof(req, origin, device, factorFresh) {
  const secretState = adminSecretState(); if (!secretState.configured) fail('ADMIN_CREDENTIAL_NOT_CONFIGURED', 503);
  const token = cookieToken(req, PASSWORD_COOKIE); if (!token) fail('ADMIN_PASSWORD_REQUIRED', 401);
  const key = passwordProofKey(token), [entry, used] = await Promise.all([securityRead(key), securityRead(key + ':used')]);
  if (!entry.ok || !entry.found || !used.ok || used.found) fail('ADMIN_PASSWORD_REQUIRED', 401);
  const proof = entry.record, now = Date.now();
  if (!proof || proof.version !== PASSWORD_VERSION || proof.userId !== ADMIN_USER_ID || proof.email !== ADMIN_EMAIL || proof.origin !== origin || proof.device !== device || proof.secretBinding !== secretBinding(secretState.secret)
      || !Number.isSafeInteger(proof.createdAt) || !Number.isSafeInteger(proof.expiresAt) || proof.createdAt > now || proof.expiresAt !== proof.createdAt + PASSWORD_SECONDS * 1000 || proof.expiresAt <= now || (factorFresh && now - proof.createdAt >= FACTOR_SECONDS * 1000)) fail('ADMIN_PASSWORD_REQUIRED', 401);
  return { token, key, proof };
}
async function revokePasswordProof(authority) {
  if (!authority || !authority.key || !authority.proof) return false;
  const ttl = Math.max(60, Math.ceil((authority.proof.expiresAt - Date.now()) / 1000));
  if (await securityClaim(authority.key + ':used', { version: PASSWORD_VERSION, usedAt: Date.now() }, ttl)) return true;
  const existing = await securityRead(authority.key + ':used'); return !!(existing.ok && existing.found && existing.record.version === PASSWORD_VERSION);
}

function nonceSigningKey() { return deriveSecret('admin-page-nonce-v411'); }
function issuePageNonce(action, origin, device) {
  const csrf = crypto.randomBytes(32).toString('base64url'), now = Date.now();
  const payload = { v: 411, a: action, o: digest(origin), d: device, c: digest(csrf), i: now, e: now + 120000, r: randomToken() };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url'), key = nonceSigningKey();
  try { return { csrf, nonce: encoded + '.' + crypto.createHmac('sha256', key).update(encoded).digest('base64url') }; }
  finally { key.fill(0); }
}
async function verifyPageNonce(req, action, origin, device) {
  const csrfA = String(req.headers && req.headers['x-csrf-token'] || ''), csrfB = String(req.headers && req.headers['x-dirac-csrf-token'] || ''), token = String(req.headers && req.headers['x-dirac-page-nonce'] || '');
  if (!/^[A-Za-z0-9_-]{43}$/.test(csrfA) || csrfA !== csrfB || token.length > 4096 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(token)) fail('ADMIN_PROOF_INVALID', 403);
  const dot = token.lastIndexOf('.'), encoded = token.slice(0, dot), signature = token.slice(dot + 1), key = nonceSigningKey();
  let expected; try { expected = crypto.createHmac('sha256', key).update(encoded).digest('base64url'); } finally { key.fill(0); }
  if (!safeEqual(signature, expected)) fail('ADMIN_PROOF_INVALID', 403);
  let payload; try { payload = JSON.parse(decodeB64url(encoded, 3072).toString('utf8')); } catch (_) { fail('ADMIN_PROOF_INVALID', 403); }
  const now = Date.now();
  if (!payload || Object.keys(payload).sort().join(',') !== 'a,c,d,e,i,o,r,v' || payload.v !== 411 || payload.a !== action || payload.o !== digest(origin) || payload.d !== device || payload.c !== digest(csrfA)
      || !Number.isSafeInteger(payload.i) || !Number.isSafeInteger(payload.e) || payload.i > now || payload.e !== payload.i + 120000 || payload.e <= now || !exactToken(payload.r)) fail('ADMIN_PROOF_INVALID', 403);
  if (await securityClaim(pageNonceKey(token), { version: VERSION, action, usedAt: now }, 180) !== true) fail('ADMIN_PROOF_REPLAYED', 409);
  return true;
}

function securityBlockKey(origin, device) { return SECURITY_BLOCK_PREFIX + digest(String(origin) + '\0' + String(device)); }
function validSecurityBlock(record, origin, device) {
  return !!(record && record.version === VERSION && record.schema === 'dirac.admin_security_block.v411' && record.reason === 'html_detected_attack'
    && record.originHash === digest(origin) && record.device === device && Number.isSafeInteger(record.createdAt) && Number.isSafeInteger(record.blockedUntil)
    && record.blockedUntil === record.createdAt + SECURITY_BLOCK_SECONDS * 1000 && record.blockedUntil > Date.now());
}
async function activeSecurityBlock(origin, device) {
  const result = await securityRead(securityBlockKey(origin, device));
  if (!result.ok) fail('ADMIN_SECURITY_STORE_UNAVAILABLE', 503);
  if (!result.found) return null;
  if (!validSecurityBlock(result.record, origin, device)) fail('ADMIN_SECURITY_STATE_INVALID', 503);
  return result.record;
}
function validateSecurityReport(body) {
  if (!body || body.reason !== 'html_detected_attack' || body.page !== 'admin.html' || body.version !== 'dirac-html-shell-v1') fail('ADMIN_SECURITY_REPORT_INVALID', 400);
  const type = String(body.type || ''), event = String(body.event || ''), evidence = String(body.evidence || '');
  if (!['url_guard', 'input_guard'].includes(type) || !['forbidden_html_url_suffix', 'high_confidence_input_violation'].includes(event)) fail('ADMIN_SECURITY_REPORT_INVALID', 400);
  const match = /^family=([a-z0-9_-]{1,64});field=([a-z0-9_-]{1,64});source=html_boundary(?:;sample=([\s\S]{1,768}))?$/.exec(evidence);
  if (!match || (type === 'url_guard') !== (event === 'forbidden_html_url_suffix') || (type === 'url_guard') !== (match[1] === 'forbidden_html_suffix')) fail('ADMIN_SECURITY_REPORT_INVALID', 400);
  return Object.freeze({ type, event, family: match[1], field: match[2], evidenceHash: digest512(evidence) });
}
async function persistSecurityReport(origin, device, report) {
  const now = Date.now(), blockedUntil = now + SECURITY_BLOCK_SECONDS * 1000;
  const blockRecord = { version: VERSION, schema: 'dirac.admin_security_block.v411', reason: 'html_detected_attack', originHash: digest(origin), device, createdAt: now, blockedUntil };
  const blockKey = securityBlockKey(origin, device), claimed = await securityClaim(blockKey, blockRecord, SECURITY_BLOCK_SECONDS);
  if (!claimed) {
    const existing = await securityRead(blockKey);
    if (!existing.ok || !existing.found || !validSecurityBlock(existing.record, origin, device)) fail('ADMIN_SECURITY_STORE_UNAVAILABLE', 503);
  }
  const reportKey = SECURITY_REPORT_PREFIX + digest(randomToken()), reportRecord = { version: VERSION, schema: 'dirac.admin_security_report.v411', reason: 'html_detected_attack', type: report.type, event: report.event, family: report.family, field: report.field, evidenceHash: report.evidenceHash, originHash: digest(origin), device, createdAt: now };
  if (await securityClaim(reportKey, reportRecord, SECURITY_BLOCK_SECONDS) !== true) fail('ADMIN_SECURITY_STORE_UNAVAILABLE', 503);
  return { blockedUntil };
}

function decodeB64url(value, maximum, minimum = 0) {
  if (typeof value !== 'string' || !value || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(maximum * 4 / 3) + 4) fail('ADMIN_ENCODING_INVALID', 400);
  let bytes; try { bytes = Buffer.from(value, 'base64url'); } catch (_) { fail('ADMIN_ENCODING_INVALID', 400); }
  if (bytes.length < minimum || bytes.length > maximum || bytes.toString('base64url') !== value) fail('ADMIN_ENCODING_INVALID', 400);
  return bytes;
}
function readCbor(buffer, start = 0, depth = 0) {
  if (!Buffer.isBuffer(buffer) || depth > 12 || start < 0 || start >= buffer.length) fail('ADMIN_PASSKEY_CBOR_INVALID', 400);
  let offset = start;
  const first = buffer[offset++], major = first >>> 5, add = first & 31;
  function length() {
    if (add < 24) return add;
    if (add === 24) { if (offset + 1 > buffer.length) fail('ADMIN_PASSKEY_CBOR_INVALID', 400); return buffer[offset++]; }
    if (add === 25) { if (offset + 2 > buffer.length) fail('ADMIN_PASSKEY_CBOR_INVALID', 400); const v = buffer.readUInt16BE(offset); offset += 2; return v; }
    if (add === 26) { if (offset + 4 > buffer.length) fail('ADMIN_PASSKEY_CBOR_INVALID', 400); const v = buffer.readUInt32BE(offset); offset += 4; return v; }
    if (add === 27) { if (offset + 8 > buffer.length) fail('ADMIN_PASSKEY_CBOR_INVALID', 400); const v = buffer.readBigUInt64BE(offset); offset += 8; if (v > BigInt(Number.MAX_SAFE_INTEGER)) fail('ADMIN_PASSKEY_CBOR_INVALID', 400); return Number(v); }
    fail('ADMIN_PASSKEY_CBOR_INVALID', 400);
  }
  if (major === 0 || major === 1) { const n = length(); return { value: major === 0 ? n : -1 - n, offset }; }
  if (major === 2 || major === 3) { const n = length(); if (n > 131072 || offset + n > buffer.length) fail('ADMIN_PASSKEY_CBOR_INVALID', 400); const part = buffer.subarray(offset, offset + n); offset += n; return { value: major === 2 ? Buffer.from(part) : part.toString('utf8'), offset }; }
  if (major === 4) {
    const n = length(); if (n > 128) fail('ADMIN_PASSKEY_CBOR_INVALID', 400); const out = [];
    const readArrayItem = remaining => { if (!remaining) return; const item = readCbor(buffer, offset, depth + 1); out.push(item.value); offset = item.offset; readArrayItem(remaining - 1); };
    readArrayItem(n); return { value: out, offset };
  }
  if (major === 5) {
    const n = length(); if (n > 128) fail('ADMIN_PASSKEY_CBOR_INVALID', 400); const out = new Map();
    const readMapItem = remaining => { if (!remaining) return; const key = readCbor(buffer, offset, depth + 1); offset = key.offset; const item = readCbor(buffer, offset, depth + 1); offset = item.offset; if (out.has(key.value)) fail('ADMIN_PASSKEY_CBOR_INVALID', 400); out.set(key.value, item.value); readMapItem(remaining - 1); };
    readMapItem(n); return { value: out, offset };
  }
  if (major === 6) { length(); return readCbor(buffer, offset, depth + 1); }
  if (major === 7) { if (add === 20) return { value: false, offset }; if (add === 21) return { value: true, offset }; if (add === 22) return { value: null, offset }; fail('ADMIN_PASSKEY_CBOR_INVALID', 400); }
  fail('ADMIN_PASSKEY_CBOR_INVALID', 400);
}
function coseToJwk(map) {
  if (!(map instanceof Map)) fail('ADMIN_PASSKEY_KEY_INVALID', 400);
  const kty = map.get(1), alg = map.get(3);
  let jwk;
  if (kty === 2 && alg === -7 && map.get(-1) === 1) {
    const x = map.get(-2), y = map.get(-3);
    if (!Buffer.isBuffer(x) || x.length !== 32 || !Buffer.isBuffer(y) || y.length !== 32) fail('ADMIN_PASSKEY_KEY_INVALID', 400);
    jwk = { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url'), alg: 'ES256', ext: true, key_ops: ['verify'] };
  } else if (kty === 3 && alg === -257) {
    const n = map.get(-1), e = map.get(-2);
    if (!Buffer.isBuffer(n) || n.length < 64 || n.length > 1024 || !Buffer.isBuffer(e) || e.length < 1 || e.length > 8) fail('ADMIN_PASSKEY_KEY_INVALID', 400);
    jwk = { kty: 'RSA', n: n.toString('base64url'), e: e.toString('base64url'), alg: 'RS256', ext: true, key_ops: ['verify'] };
  } else fail('ADMIN_PASSKEY_ALGORITHM_INVALID', 403);
  try { crypto.createPublicKey({ key: jwk, format: 'jwk' }); } catch (_) { fail('ADMIN_PASSKEY_KEY_INVALID', 400); }
  return jwk;
}
function parseAuthData(bytes, rpId, registration) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 37 || bytes.length > 8192) fail('ADMIN_PASSKEY_AUTHDATA_INVALID', 400);
  const expectedRp = crypto.createHash('sha256').update(rpId).digest();
  if (!crypto.timingSafeEqual(bytes.subarray(0, 32), expectedRp)) fail('ADMIN_PASSKEY_RPID_MISMATCH', 403);
  const flags = bytes[32], signCount = bytes.readUInt32BE(33);
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0 || ((flags & 0x10) && !(flags & 0x08))) fail('ADMIN_PASSKEY_UV_REQUIRED', 403);
  const result = { flags, signCount, backupEligible: !!(flags & 0x08), backupState: !!(flags & 0x10), credentialId: '', publicKeyJwk: null };
  let offset = 37;
  if (registration) {
    if ((flags & 0x40) === 0 || bytes.length < offset + 18) fail('ADMIN_PASSKEY_ATTESTED_DATA_REQUIRED', 403);
    offset += 16; const idLength = bytes.readUInt16BE(offset); offset += 2;
    if (idLength < 16 || idLength > 1024 || offset + idLength > bytes.length) fail('ADMIN_PASSKEY_CREDENTIAL_INVALID', 400);
    result.credentialId = bytes.subarray(offset, offset + idLength).toString('base64url'); offset += idLength;
    const decoded = readCbor(bytes, offset); result.publicKeyJwk = coseToJwk(decoded.value); offset = decoded.offset;
  } else if (flags & 0x40) fail('ADMIN_PASSKEY_AUTHDATA_INVALID', 400);
  if (flags & 0x80) { const extension = readCbor(bytes, offset); offset = extension.offset; }
  if (offset !== bytes.length) fail('ADMIN_PASSKEY_AUTHDATA_INVALID', 400);
  return result;
}
function verifyRegistration({ credential, rpId }) {
  const attestationBytes = decodeB64url(credential.response.attestationObject, 98304, 1);
  const decoded = readCbor(attestationBytes, 0); if (decoded.offset !== attestationBytes.length || !(decoded.value instanceof Map)) fail('ADMIN_PASSKEY_ATTESTATION_INVALID', 400);
  const object = decoded.value, fmt = object.get('fmt'), authData = object.get('authData'), attStmt = object.get('attStmt');
  if (fmt !== 'none' || !(attStmt instanceof Map) || attStmt.size !== 0 || !Buffer.isBuffer(authData)) fail('ADMIN_PASSKEY_ATTESTATION_INVALID', 403);
  const parsed = parseAuthData(authData, rpId, true);
  if (parsed.credentialId !== credential.id) fail('ADMIN_PASSKEY_CREDENTIAL_MISMATCH', 403);
  return { ok: true, credentialId: parsed.credentialId, publicKeyJwk: parsed.publicKeyJwk, signCount: parsed.signCount, backupEligible: parsed.backupEligible };
}
function verifyAssertion({ credential, rpId, passkey }) {
  const authData = decodeB64url(credential.response.authenticatorData, 8192, 37), signature = decodeB64url(credential.response.signature, 8192, 8);
  const parsed = parseAuthData(authData, rpId, false);
  if (parsed.backupEligible !== !!passkey.backupEligible) fail('ADMIN_PASSKEY_BACKUP_STATE_INVALID', 403);
  const client = decodeB64url(credential.response.clientDataJSON, 8192, 1), signed = Buffer.concat([authData, crypto.createHash('sha256').update(client).digest()]);
  let key; try { key = crypto.createPublicKey({ key: passkey.publicKeyJwk, format: 'jwk' }); } catch (_) { fail('ADMIN_PASSKEY_KEY_INVALID', 503); }
  let ok = false; try { ok = crypto.verify('sha256', signed, key, signature); } catch (_) { ok = false; }
  if (!ok) fail('ADMIN_PASSKEY_SIGNATURE_INVALID', 403);
  const previous = Number(passkey.signCount || 0), current = parsed.signCount;
  if (previous > 0 && current > 0 && current <= previous) fail('ADMIN_PASSKEY_COUNTER_REPLAY', 409);
  return { ok: true, signCount: current };
}

function approvalPayload(action, body) {
  const value = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  if (action === 'admin_shipment_update') return { action, kind: value.kind, order_id: value.order_id, expected_revision: value.expected_revision, tracking_number: value.tracking_number, courier: value.courier, status: value.status, location: value.location || '', origin: value.origin || '', destination: value.destination || '', estimated_delivery: value.estimated_delivery || '', description: value.description || '' };
  if (action === 'admin_shipment_cancel') return { action, kind: value.kind, order_id: value.order_id, expected_revision: value.expected_revision, description: value.description || '' };
  if (action === 'admin_unban') return { action, block_id: value.block_id };
  fail('ADMIN_ACTION_APPROVAL_OPERATION_INVALID', 400);
}
function approvalPayloadHash(action, body) { return digest(stableJson(approvalPayload(action, body))); }
function actionLabel(action) {
  if (action === 'admin_shipment_update') return 'Simpan pembaruan pengiriman';
  if (action === 'admin_shipment_cancel') return 'Batalkan resi pengiriman';
  if (action === 'admin_unban') return 'Pulihkan akses akun';
  return 'Aksi administrator';
}
function mailEscape(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])); }
function mailOriginParts(origin) {
  let url; try { url = new URL(String(origin || '')); } catch (_) { return { actionUrl: '', bannerUrl: '', supportEmail: '' }; }
  const host = String(url.hostname || '').toLowerCase(), base = host.startsWith('pt.') ? host.slice(3) : host;
  if (url.protocol !== 'https:' || !base || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(base)) return { actionUrl: '', bannerUrl: '', supportEmail: '' };
  return { actionUrl: 'https://pt.' + base + '/admin.html', bannerUrl: 'https://' + base + '/headerstp.webp', supportEmail: 'support@' + base };
}

function adminSocialGridHtml() {
  return `<tr><td style="padding:16px 18px 13px;border-left:4px solid #148ba4"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">PLATFORM SOSIAL</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;margin-top:12px;border-collapse:collapse;table-layout:fixed"><tr><td width="33.33%" align="center" valign="top" style="padding:0 4px 12px"><a href="https://x.com/achzaenuddin?s=11" rel="noopener noreferrer" target="_blank" aria-label="X" style="display:block;text-align:center;text-decoration:none"><span style="display:inline-block;width:42px;height:42px;line-height:42px;border:1px solid #465a73;border-radius:50%;font-size:16px;font-weight:900;text-align:center;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">X</span><span style="display:block;margin-top:6px;font-size:10px;line-height:1.2;font-weight:800;color:#c8d2df!important;-webkit-text-fill-color:#c8d2df!important;mso-color-alt:#c8d2df">X</span></a></td><td width="33.33%" align="center" valign="top" style="padding:0 4px 12px"><a href="https://www.facebook.com/share/1J3EEbguNX/?mibextid=wwXIfr" rel="noopener noreferrer" target="_blank" aria-label="Facebook" style="display:block;text-align:center;text-decoration:none"><span style="display:inline-block;width:42px;height:42px;line-height:42px;border:1px solid #465a73;border-radius:50%;font-size:20px;font-weight:900;text-align:center;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">f</span><span style="display:block;margin-top:6px;font-size:10px;line-height:1.2;font-weight:800;color:#c8d2df!important;-webkit-text-fill-color:#c8d2df!important;mso-color-alt:#c8d2df">Facebook</span></a></td><td width="33.33%" align="center" valign="top" style="padding:0 4px 12px"><a href="https://www.instagram.com/achzaenuddin15?stkn=MW4zc3FldjAzb21wNg%3D%3D&utm_source=qr" rel="noopener noreferrer" target="_blank" aria-label="Instagram" style="display:block;text-align:center;text-decoration:none"><table role="presentation" width="42" height="42" cellspacing="0" cellpadding="0" border="0" align="center" style="width:42px;height:42px;border-collapse:separate;border-spacing:0;border:1px solid #465a73;border-radius:50%"><tr><td align="center" valign="middle"><table role="presentation" width="20" height="20" cellspacing="0" cellpadding="0" border="0" align="center" style="width:20px;height:20px;border-collapse:separate;border-spacing:0;border:2px solid #f4f6f9;border-radius:6px"><tr><td align="center" valign="middle"><table role="presentation" width="14" height="14" cellspacing="0" cellpadding="0" border="0" align="center" style="width:14px;height:14px;border-collapse:collapse"><tr><td width="10" height="4" style="font-size:0;line-height:0">&nbsp;</td><td width="4" height="4" align="right" valign="top" style="font-size:0;line-height:0"><span style="display:inline-block;width:3px;height:3px;border-radius:50%;background:#f4f6f9;background-color:#f4f6f9;font-size:0;line-height:0">&nbsp;</span></td></tr><tr><td colspan="2" height="10" align="center" valign="top"><span style="display:inline-block;width:8px;height:8px;border:2px solid #f4f6f9;border-radius:50%;box-sizing:border-box;font-size:0;line-height:0">&nbsp;</span></td></tr></table></td></tr></table></td></tr></table><span style="display:block;margin-top:6px;font-size:10px;line-height:1.2;font-weight:800;color:#c8d2df!important;-webkit-text-fill-color:#c8d2df!important;mso-color-alt:#c8d2df">Instagram</span></a></td></tr><tr><td width="33.33%" align="center" valign="top" style="padding:0 4px 4px"><a href="https://www.threads.com/@achzaenuddin15?igshid=NTc4MTIwNjQ2YQ==" rel="noopener noreferrer" target="_blank" aria-label="Threads" style="display:block;text-align:center;text-decoration:none"><span style="display:inline-block;width:42px;height:42px;line-height:42px;border:1px solid #465a73;border-radius:50%;font-size:18px;font-weight:900;text-align:center;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">@</span><span style="display:block;margin-top:6px;font-size:10px;line-height:1.2;font-weight:800;color:#c8d2df!important;-webkit-text-fill-color:#c8d2df!important;mso-color-alt:#c8d2df">Threads</span></a></td><td width="33.33%" align="center" valign="top" style="padding:0 4px 4px"><a href="https://www.linkedin.com/in/pt-dirac-inovasi-nusantara" rel="noopener noreferrer" target="_blank" aria-label="LinkedIn" style="display:block;text-align:center;text-decoration:none"><span style="display:inline-block;width:42px;height:42px;line-height:42px;border:1px solid #465a73;border-radius:50%;font-size:14px;font-weight:900;text-align:center;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">in</span><span style="display:block;margin-top:6px;font-size:10px;line-height:1.2;font-weight:800;color:#c8d2df!important;-webkit-text-fill-color:#c8d2df!important;mso-color-alt:#c8d2df">LinkedIn</span></a></td><td width="33.33%" align="center" valign="top" style="padding:0 4px 4px"><a href="https://www.tiktok.com/@achzaenuddin" rel="noopener noreferrer" target="_blank" aria-label="TikTok" style="display:block;text-align:center;text-decoration:none"><span style="display:inline-block;width:42px;height:42px;line-height:42px;border:1px solid #465a73;border-radius:50%;font-size:19px;font-weight:900;text-align:center;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">♪</span><span style="display:block;margin-top:6px;font-size:10px;line-height:1.2;font-weight:800;color:#c8d2df!important;-webkit-text-fill-color:#c8d2df!important;mso-color-alt:#c8d2df">TikTok</span></a></td></tr></table></div></div></td></tr>`;
}
function adminExecutiveEscalationHtml() {
  return '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" data-dirac-executive-report="v380" style="width:100%;margin:18px 0 0;border-collapse:collapse"><tr><td align="center" style="padding:0 12px"><table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" bgcolor="#F7F9FC" style="width:100%;max-width:600px;border-collapse:separate;border-spacing:0;border:1px solid #CBD5E1;border-radius:16px;overflow:hidden;background-color:#F7F9FC"><tr><td style="padding:0"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td width="42%" bgcolor="#27B3CB" style="height:4px;line-height:4px;font-size:0;background-color:#27B3CB">&nbsp;</td><td width="34%" bgcolor="#2D6FAD" style="height:4px;line-height:4px;font-size:0;background-color:#2D6FAD">&nbsp;</td><td width="24%" bgcolor="#C69A32" style="height:4px;line-height:4px;font-size:0;background-color:#C69A32">&nbsp;</td></tr></table></td></tr><tr><td bgcolor="#F7F9FC" style="padding:18px 18px 17px;font-family:Arial,Helvetica,sans-serif;background-color:#F7F9FC;color:#172033"><div style="font-size:10px;line-height:1.4;font-weight:800;letter-spacing:.15em;color:#087A8F">JALUR PRIVAT PELANGGAN</div><div style="margin-top:5px;font-size:20px;line-height:1.28;font-weight:800;color:#0F172A">Lapor ke Direktur &amp; Founder</div><p style="margin:8px 0 14px;font-size:13px;line-height:1.55;color:#475569">Dugaan penyalahgunaan, penipuan, manipulasi, pemaksaan, atau pelanggaran oleh staf/mitra dapat dilaporkan langsung kepada Achmad Zaenuddin, Direktur &amp; Founder PT Dirac Inovasi Nusantara.</p><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td bgcolor="#0B6F88" style="padding:0;border-radius:10px;background-color:#0B6F88"><a href="mailto:supportdirac@gmail.com?subject=Laporan%20Pelanggan%20ke%20Direktur%20%26%20Founder&amp;body=Halo%20Direktur%20%26%20Founder%20PT%20Dirac%20Inovasi%20Nusantara%2C%0D%0A%0D%0ASaya%20ingin%20menyampaikan%20laporan%20pelanggan.%0D%0A%0D%0ANama%3A%20%0D%0AEmail%20akun%3A%20%0D%0ANomor%20pesanan%2Ftiket%20%28jika%20ada%29%3A%20%0D%0ATanggal%20%26%20waktu%20kejadian%3A%20%0D%0ARingkasan%3A%20%0D%0ABukti%20pendukung%20%28tanpa%20data%20rahasia%29%3A%20%0D%0A%0D%0ATerima%20kasih." style="display:block;padding:12px 14px;font-size:13px;line-height:1.35;font-weight:800;text-align:center;color:#FFFFFF;text-decoration:none"><font color="#FFFFFF" style="color:#FFFFFF">EMAIL&nbsp;&nbsp;•&nbsp;&nbsp;SIAPKAN LAPORAN</font></a></td></tr><tr><td style="height:9px;line-height:9px;font-size:0">&nbsp;</td></tr><tr><td bgcolor="#18794E" style="padding:0;border-radius:10px;background-color:#18794E"><a href="https://wa.me/62882009257589?text=Halo%20Direktur%20%26%20Founder%20PT%20Dirac%20Inovasi%20Nusantara%2C%0A%0ASaya%20ingin%20menyampaikan%20laporan%20pelanggan.%0A%0ANama%3A%20%0AEmail%20akun%3A%20%0ANomor%20pesanan%2Ftiket%20%28jika%20ada%29%3A%20%0ATanggal%20%26%20waktu%20kejadian%3A%20%0ARingkasan%3A%20%0ABukti%20pendukung%20%28tanpa%20data%20rahasia%29%3A%20%0A%0ATerima%20kasih." style="display:block;padding:12px 14px;font-size:13px;line-height:1.35;font-weight:800;text-align:center;color:#FFFFFF;text-decoration:none"><font color="#FFFFFF" style="color:#FFFFFF">WHATSAPP&nbsp;&nbsp;•&nbsp;&nbsp;+62 882-0092-57589</font></a></td></tr></table><p style="margin:12px 0 0;font-size:11px;line-height:1.5;color:#64748B">Template laporan sudah disiapkan. Lengkapi bagian yang kosong dan jangan sertakan password, OTP, PIN, CVV, passkey, cookie, token, atau secret.</p></td></tr></table></td></tr></table>';
}

function adminMailHtml(message) {
  const code = mailEscape(message.code), reference = mailEscape(message.reference), parts = mailOriginParts(message.origin), operation = message.kind === 'action' ? actionLabel(message.operation) : 'Verifikasi masuk administrator';
  const title = message.kind === 'action' ? 'Konfirmasi Aksi<br>Administrator' : 'Verifikasi Akses<br>Administrator';
  const summary = message.kind === 'action' ? 'Kode ini diminta untuk mengonfirmasi satu aksi administrator. Aksi tidak akan dijalankan sebelum kode berhasil diverifikasi.' : 'Kode ini digunakan sebagai faktor email pada proses masuk administrator. Gunakan hanya pada halaman administrasi resmi yang sedang Anda buka.';
  const destination = parts.actionUrl ? mailEscape(new URL(parts.actionUrl).hostname) : '', supportEmail = mailEscape(parts.supportEmail || 'companydirac@gmail.com'), socialSupportRowHtml = adminSocialGridHtml(), executiveHtml = adminExecutiveEscalationHtml();
  const banner = parts.bannerUrl ? '<tr><td bgcolor="#10151e" style="padding:0;line-height:0;font-size:0;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)"><img src="' + mailEscape(parts.bannerUrl) + '" width="600" alt="PT Dirac Inovasi Nusantara Secure Security" style="display:block;width:100%;max-width:600px;height:auto;border:0;outline:none;text-decoration:none;background:#10151e;background-color:#10151e"></td></tr>' : '';
  const button = parts.actionUrl ? '<table class="dirac-button" role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;margin:0 0 9px;border-collapse:separate"><tr><td align="center" bgcolor="#5276e8" style="border-radius:10px;background:#5276e8;background-color:#5276e8"><a href="' + mailEscape(parts.actionUrl) + '" style="display:block;padding:17px 18px;font-size:15px;line-height:1.2;font-weight:800;letter-spacing:.04em;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;text-decoration:none;border-radius:10px">BUKA ADMINISTRASI</a></td></tr></table>' : '';
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>PT Dirac Inovasi Nusantara Secure Security Notification</title>
  <style>
    :root { color-scheme:dark; supported-color-schemes:dark; }
    body { margin:0!important; padding:0!important; }
    .dirac-preheader { display:none!important; max-height:0!important; max-width:0!important; opacity:0!important; overflow:hidden!important; mso-hide:all!important; }
    u + .body .gmail-blend-screen { background:#000; mix-blend-mode:screen; }
    u + .body .gmail-blend-difference { background:#000; mix-blend-mode:difference; }
    a[x-apple-data-detectors], .x-gmail-data-detectors, .ii a[href] { text-decoration:none!important; }
    @keyframes dirac-code-glow { 0%,100% { box-shadow:0 0 0 0 rgba(117,199,255,0); } 50% { box-shadow:0 0 0 4px rgba(117,199,255,.14); } }
    @keyframes dirac-code-pill { 0%,100% { transform:translateY(0); } 50% { transform:translateY(-1px); } }
    .dirac-code-card { animation:dirac-code-glow 2.2s ease-in-out 2; }
    .dirac-code-copy-pill { animation:dirac-code-pill 1.6s ease-in-out 2; }
    @media (prefers-reduced-motion:reduce) { .dirac-code-card, .dirac-code-copy-pill { animation:none!important; } }
    @media only screen and (max-width:620px) {
      .dirac-outer-pad { padding:0!important; }
      .dirac-shell { width:100%!important; max-width:100%!important; }
      .dirac-pad { padding-left:24px!important; padding-right:24px!important; }
      .dirac-title { font-size:32px!important; line-height:1.18!important; }
      .dirac-button a { display:block!important; padding:17px 14px!important; }
      .dirac-footer-pad { padding-left:18px!important; padding-right:18px!important; }
    }
  </style>
</head>
<body class="body" bgcolor="#090c12" style="margin:0!important;padding:0!important;background:#090c12;background-color:#090c12;background-image:linear-gradient(#090c12,#090c12);font-family:Arial,Helvetica,sans-serif;color:#f4f6f9">
  <div class="dirac-preheader">Verifikasi keamanan administrator PT Dirac Inovasi Nusantara.</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#090c12" style="width:100%;margin:0;padding:0;background:#090c12;background-color:#090c12;background-image:linear-gradient(#090c12,#090c12)">
    <tr><td class="dirac-outer-pad" align="center" bgcolor="#090c12" style="padding:18px 12px;background:#090c12;background-color:#090c12;background-image:linear-gradient(#090c12,#090c12)">
      <table class="dirac-shell" role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" bgcolor="#141820" style="width:100%;max-width:600px;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:18px;overflow:hidden;box-shadow:0 18px 48px rgba(0,0,0,.24);background:#141820;background-color:#141820;background-image:linear-gradient(#141820,#141820)">
        <tr><td style="padding:0;line-height:0;font-size:0"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td width="50%" height="4" bgcolor="#5276e8" style="height:4px;line-height:4px;font-size:0;background:#5276e8;background-color:#5276e8">&nbsp;</td><td width="30%" height="4" bgcolor="#148ba4" style="height:4px;line-height:4px;font-size:0;background:#148ba4;background-color:#148ba4">&nbsp;</td><td width="20%" height="4" bgcolor="#9a741f" style="height:4px;line-height:4px;font-size:0;background:#9a741f;background-color:#9a741f">&nbsp;</td></tr></table></td></tr>
        ${banner}
        <tr><td class="dirac-pad" bgcolor="#141820" style="padding:27px 32px 13px;background:#141820;background-color:#141820;background-image:linear-gradient(#141820,#141820)"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:21px;line-height:1.2;font-weight:800;letter-spacing:.14em;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">PT Dirac Inovasi Nusantara</div><div style="margin-top:7px;font-size:11px;line-height:1.4;font-weight:700;letter-spacing:.2em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">SECURE ACCOUNT RECOVERY</div></div></div></td></tr>
        <tr><td class="dirac-pad" bgcolor="#141820" style="padding:24px 32px 32px;background:#141820;background-color:#141820;background-image:linear-gradient(#141820,#141820)">
          <div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#9eb6ff!important;-webkit-text-fill-color:#9eb6ff!important;mso-color-alt:#9eb6ff">SECURITY ACTIVITY NOTICE</div><div class="dirac-title" style="margin-top:13px;font-size:38px;line-height:1.16;font-weight:800;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">${title}</div><p style="margin:25px 0 0;font-size:17px;line-height:1.55;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">Yth. Administrator PT Dirac Inovasi Nusantara,</p><p style="margin:12px 0 0;font-size:16px;line-height:1.65;color:#c5ccd6!important;-webkit-text-fill-color:#c5ccd6!important;mso-color-alt:#c5ccd6">${mailEscape(summary)}</p></div></div>
          <table class="dirac-code-card" role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#101b2b" style="width:100%;margin:20px 0 18px;border-collapse:separate;border-spacing:0;border:1px solid #3d5f92;border-radius:16px;overflow:hidden;background:#101b2b;background-color:#101b2b;background-image:linear-gradient(#101b2b,#101b2b)"><tr><td style="padding:20px;border-left:4px solid #6fb8ff"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.15em;color:#9fc9ff!important;-webkit-text-fill-color:#9fc9ff!important;mso-color-alt:#9fc9ff">KODE DIMINTA</div><div class="dirac-code-value" aria-label="Kode verifikasi" style="margin-top:12px;font-family:SFMono-Regular,Consolas,Liberation Mono,Menlo,monospace;font-size:15px;line-height:1.55;font-weight:800;letter-spacing:.055em;word-break:break-all;overflow-wrap:anywhere;white-space:normal;-webkit-user-select:all;user-select:all;cursor:text;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;mso-color-alt:#ffffff">${code}</div><div style="margin-top:14px;padding-top:12px;border-top:1px solid #2b4160;font-size:11px;line-height:1.55;color:#9fb0c5!important;-webkit-text-fill-color:#9fb0c5!important;mso-color-alt:#9fb0c5"><b class="dirac-code-copy-pill" style="color:#cfe5ff!important;-webkit-text-fill-color:#cfe5ff!important;mso-color-alt:#cfe5ff">SALIN KODE</b><br>Untuk kode panjang, ketuk area kode lalu tekan dan tahan untuk memilih dan menyalin.</div></div></div></td></tr></table>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#1a1f29" style="width:100%;margin:24px 0 18px;border-collapse:separate;border-spacing:0;border:1px solid #303a49;border-radius:14px;overflow:hidden;box-shadow:0 8px 22px rgba(0,0,0,.12);background:#1a1f29;background-color:#1a1f29;background-image:linear-gradient(#1a1f29,#1a1f29)"><tr><td style="padding:18px 20px;border-left:4px solid #5276e8"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#9eb6ff!important;-webkit-text-fill-color:#9eb6ff!important;mso-color-alt:#9eb6ff">STATUS KEAMANAN</div><div style="margin-top:8px;font-size:19px;line-height:1.45;font-weight:800;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">MENUNGGU KONFIRMASI</div><div style="margin-top:7px;font-size:13px;line-height:1.55;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">Kode berlaku 5 menit dan hanya dapat digunakan satu kali.</div></div></div></td></tr></table>
          ${button}
          ${destination ? '<div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="margin:0 0 25px;text-align:center;font-size:12px;line-height:1.5;color:#8f99a7!important;-webkit-text-fill-color:#8f99a7!important;mso-color-alt:#8f99a7">Tujuan resmi: ' + destination + '</div><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">DETAIL AKTIVITAS</div></div></div>' : '<div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4">DETAIL AKTIVITAS</div>'}
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10151e" style="width:100%;margin:13px 0 0;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:14px;overflow:hidden;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)"><tr><td style="padding:16px 20px;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">AKSI</div><div style="margin-top:6px;font-size:15px;line-height:1.55;font-weight:700;word-break:break-word;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">${mailEscape(operation)}</div></div></div></td></tr><tr><td style="padding:16px 20px;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">REFERENSI</div><div style="margin-top:6px;font-size:15px;line-height:1.55;font-weight:700;word-break:break-word;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">${reference}</div></div></div></td></tr><tr><td style="padding:16px 20px"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">KETENTUAN</div><div style="margin-top:6px;font-size:15px;line-height:1.55;font-weight:700;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">5 menit &middot; sekali pakai</div></div></div></td></tr></table>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#1d1b17" style="width:100%;margin:28px 0;border-collapse:separate;border-spacing:0;border:1px solid #4a4030;border-radius:14px;overflow:hidden;background:#1d1b17;background-color:#1d1b17;background-image:linear-gradient(#1d1b17,#1d1b17)"><tr><td style="padding:18px 20px;border-left:4px solid #9a741f"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.14em;color:#f0c86c!important;-webkit-text-fill-color:#f0c86c!important;mso-color-alt:#f0c86c">PERINGATAN KEAMANAN</div><p style="margin:10px 0 0;font-size:14px;line-height:1.65;color:#e8ebef!important;-webkit-text-fill-color:#e8ebef!important;mso-color-alt:#e8ebef">Jika Anda tidak meminta verifikasi ini, jangan gunakan kode. Kode, password, passkey, cookie, token, dan secret tidak boleh diberikan kepada pihak lain.</p></div></div></td></tr></table>
          <div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">BANTUAN RESMI PT Dirac Inovasi Nusantara</div><p style="margin:9px 0 13px;font-size:14px;line-height:1.6;color:#9aa4b2!important;-webkit-text-fill-color:#9aa4b2!important;mso-color-alt:#9aa4b2">Butuh bantuan untuk memeriksa aktivitas keamanan? Gunakan kanal resmi perusahaan.</p></div></div>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10151e" style="width:100%;margin:0 0 13px;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:14px;overflow:hidden;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)">
            <tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">WHATSAPP</div><a href="https://wa.me/6287892523968" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">0878 9252 3968</a></div></div></td></tr>
            <tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">EMAIL SUPPORT</div><a href="mailto:${supportEmail}" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;word-break:break-all;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">${supportEmail}</a></div></div></td></tr>
            <tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">EMAIL PERUSAHAAN</div><a href="mailto:companydirac@gmail.com" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;word-break:break-all;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">companydirac@gmail.com</a></div></div></td></tr>
            ${socialSupportRowHtml}
          </table>
          <div class="gmail-blend-screen"><div class="gmail-blend-difference"><p style="margin:0;font-size:12px;line-height:1.65;color:#8f99a7!important;-webkit-text-fill-color:#8f99a7!important;mso-color-alt:#8f99a7">Tim PT Dirac Inovasi Nusantara tidak pernah meminta password, OTP, PIN, CVV, cookie, token, atau material keamanan melalui WhatsApp, Instagram, telepon, maupun balasan email.</p></div></div>
        </td></tr>
        <tr><td class="dirac-footer-pad" bgcolor="#b9dcff" style="padding:24px 26px 26px;border-top:1px solid #79aee5;background:#b9dcff;background-color:#b9dcff;background-image:linear-gradient(#b9dcff,#b9dcff)"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10213a" style="width:100%;border-collapse:separate;border-spacing:0;border:1px solid #24466c;border-radius:16px;overflow:hidden;box-shadow:0 10px 24px rgba(14,42,72,.18);background:#10213a;background-color:#10213a;background-image:linear-gradient(#10213a,#10213a)"><tr><td style="padding:22px 24px 23px;border-left:4px solid #27a2bd"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:18px;line-height:1.3;font-weight:800;letter-spacing:.14em;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;mso-color-alt:#ffffff">PT Dirac Inovasi Nusantara</div><div style="margin-top:7px;font-size:11px;line-height:1.5;font-weight:700;letter-spacing:.13em;color:#d9e8ff!important;-webkit-text-fill-color:#d9e8ff!important;mso-color-alt:#d9e8ff">RECOVERY &bull; PRIVACY &bull; SECURITY</div><div style="margin-top:14px;font-size:13px;line-height:1.55;color:#d7e7f8!important;-webkit-text-fill-color:#d7e7f8!important;mso-color-alt:#d7e7f8">Secure Recovery &middot; Protected Delivery</div><p style="margin:17px 0 0;font-size:11px;line-height:1.65;color:#bfd0e3!important;-webkit-text-fill-color:#bfd0e3!important;mso-color-alt:#bfd0e3">Email ini dibuat otomatis oleh sistem PT Dirac Inovasi Nusantara. Mohon tidak membalas dan jangan meneruskan material keamanan kepada pihak lain.</p></div></div></td></tr></table></td></tr>
        <tr><td style="padding:0 0 18px">${executiveHtml}</td></tr>
        <tr><td style="padding:0;line-height:0;font-size:0"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td width="50%" height="4" bgcolor="#5276e8" style="height:4px;line-height:4px;font-size:0;background:#5276e8;background-color:#5276e8">&nbsp;</td><td width="30%" height="4" bgcolor="#148ba4" style="height:4px;line-height:4px;font-size:0;background:#148ba4;background-color:#148ba4">&nbsp;</td><td width="20%" height="4" bgcolor="#9a741f" style="height:4px;line-height:4px;font-size:0;background:#9a741f;background-color:#9a741f">&nbsp;</td></tr></table></td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}
function smtpConfig() {
  if (String(process.env.DIRAC_SECURITY_ALERT_ENABLED || '').trim().toLowerCase() !== 'true') return null;
  const host = String(process.env.DIRAC_SECURITY_ALERT_SMTP_HOST || '').trim().toLowerCase();
  const port = Number(process.env.DIRAC_SECURITY_ALERT_SMTP_PORT || 0), secure = String(process.env.DIRAC_SECURITY_ALERT_SMTP_SECURE || '').trim().toLowerCase() === 'true';
  const user = String(process.env.DIRAC_SECURITY_ALERT_SMTP_USER || '').trim().toLowerCase(), password = String(process.env.DIRAC_SECURITY_ALERT_SMTP_APP_PASSWORD || '').replace(/\s+/g, '');
  if (host !== 'smtp.gmail.com' || port !== 465 || !secure || !isEmail(user) || !/^[A-Za-z0-9]{16,128}$/.test(password)) return null;
  return { host, port, user, password, timeout: Math.max(3000, Math.min(15000, Number(process.env.DIRAC_SECURITY_ALERT_TIMEOUT_MS || 12000) || 12000)) };
}
function smtpReader(socket) {
  let buffer = '', closed = false, pending = null;
  const onData = chunk => { buffer += chunk.toString('utf8'); if (buffer.length > 65536) { if (pending) pending.reject(Object.assign(new Error('SMTP_RESPONSE_TOO_LARGE'), { code: 'SMTP_RESPONSE_TOO_LARGE' })); pending = null; socket.destroy(); return; } drain(); };
  const onError = error => { if (pending) pending.reject(error); pending = null; };
  const onClose = () => { closed = true; if (pending) pending.reject(Object.assign(new Error('SMTP_CLOSED'), { code: 'SMTP_CLOSED' })); pending = null; };
  function drain() {
    if (!pending) return;
    const lines = buffer.split('\r\n'); if (lines.length < 2) return;
    let used = 0, code = 0, done = false;
    lines.slice(0, -1).some(line => { used += Buffer.byteLength(line, 'utf8') + 2; const match = /^(\d{3})([ -])/.exec(line); if (!match) return false; code = Number(match[1]); done = match[2] === ' '; return done; });
    if (!done) return;
    buffer = buffer.slice(used); const active = pending; pending = null; active.resolve(code);
  }
  socket.on('data', onData); socket.on('error', onError); socket.on('close', onClose);
  return { read(timeout) { if (closed || pending) return Promise.reject(Object.assign(new Error('SMTP_STATE_INVALID'), { code: 'SMTP_STATE_INVALID' })); return new Promise((resolve, reject) => { let timer; pending = { resolve: code => { clearTimeout(timer); resolve(code); }, reject: error => { clearTimeout(timer); reject(error); } }; timer = setTimeout(() => { const active = pending; pending = null; if (active) active.reject(Object.assign(new Error('SMTP_TIMEOUT'), { code: 'SMTP_TIMEOUT' })); socket.destroy(); }, timeout); drain(); }); }, close() { socket.off('data', onData); socket.off('error', onError); socket.off('close', onClose); pending = null; } };
}
async function smtpCommand(socket, reader, command, expected, timeout) {
  if (command !== null) socket.write(command + '\r\n');
  const code = await reader.read(timeout), allowed = Array.isArray(expected) ? expected : [expected];
  if (!allowed.includes(code)) throw Object.assign(new Error('SMTP_REJECTED'), { code: 'SMTP_REJECTED', smtpCode: code });
}
function dotStuff(value) { return String(value || '').replace(/^\./gm, '..'); }
function mimeMessage(config, message) {
  const boundary = 'dirac-admin-' + crypto.randomBytes(16).toString('hex');
  const purpose = message.kind === 'action' ? actionLabel(message.operation) : 'Verifikasi masuk administrator';
  const subject = 'PT Dirac Inovasi Nusantara Security - ' + purpose + ' [' + message.reference + ']';
  const text = 'PT Dirac Inovasi Nusantara\n\n' + purpose + '\n\nKode administrator satu kali. Berlaku 5 menit dan hanya dapat digunakan satu kali setelah verifikasi berhasil. Jangan bagikan kode ini.\n\n' + message.code + '\n\nReferensi: ' + message.reference;
  const html = adminMailHtml(message);
  const b64 = value => Buffer.from(value, 'utf8').toString('base64').match(/.{1,76}/g).join('\r\n');
  return ['From: PT Dirac Inovasi Nusantara <' + config.user + '>', 'To: ' + ADMIN_EMAIL, 'Subject: =?UTF-8?B?' + Buffer.from(subject).toString('base64') + '?=', 'Date: ' + new Date().toUTCString(), 'Auto-Submitted: auto-generated', 'MIME-Version: 1.0', 'Content-Type: multipart/alternative; boundary="' + boundary + '"', '', '--' + boundary, 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', b64(text), '--' + boundary, 'Content-Type: text/html; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', b64(html), '--' + boundary + '--', ''].join('\r\n');
}

async function sendAdminMail(message) {
  const config = smtpConfig(); if (!config) return { ok: false };
  let socket = null, reader = null, auth = null;
  try {
    socket = tls.connect({ host: config.host, port: config.port, servername: config.host, rejectUnauthorized: true });
    await new Promise((resolve, reject) => { const timer = setTimeout(() => { socket.destroy(); reject(Object.assign(new Error('SMTP_TIMEOUT'), { code: 'SMTP_TIMEOUT' })); }, config.timeout); socket.once('secureConnect', () => { clearTimeout(timer); resolve(); }); socket.once('error', error => { clearTimeout(timer); reject(error); }); });
    reader = smtpReader(socket); await smtpCommand(socket, reader, null, 220, config.timeout);
    const ehlo = message && message.origin ? new URL(message.origin).hostname : 'localhost'; await smtpCommand(socket, reader, 'EHLO ' + ehlo, 250, config.timeout);
    auth = Buffer.from('\0' + config.user + '\0' + config.password, 'utf8'); await smtpCommand(socket, reader, 'AUTH PLAIN ' + auth.toString('base64'), 235, config.timeout);
    await smtpCommand(socket, reader, 'MAIL FROM:<' + config.user + '>', 250, config.timeout); await smtpCommand(socket, reader, 'RCPT TO:<' + ADMIN_EMAIL + '>', [250, 251], config.timeout); await smtpCommand(socket, reader, 'DATA', 354, config.timeout); await smtpCommand(socket, reader, dotStuff(mimeMessage(config, message)) + '\r\n.', 250, config.timeout);
    try { socket.write('QUIT\r\n'); } catch (_) {} return { ok: true };
  } catch (_) { return { ok: false }; }
  finally { if (auth) auth.fill(0); if (reader) reader.close(); try { if (socket) socket.destroy(); } catch (_) {} }
}

function checkOperations(ops) {
  if (!ops || !Object.isFrozen(ops) || ops.version !== VERSION || typeof ops.assertFullGuard !== 'function') fail('ADMIN_FULL_GUARD_REQUIRED', 503);
  ops.assertFullGuard();
  const identity = ops.identity;
  if (!identity || !Object.isFrozen(identity) || identity.email !== ADMIN_EMAIL || identity.active !== true || identity.role !== 'owner' || identity.userId !== ADMIN_USER_ID || !/^[a-f0-9]{64}$/.test(String(identity.binding || ''))) fail('ADMIN_FIXED_OWNER_REQUIRED', 403);
  let origin; try { origin = new URL(identity.origin); } catch (_) { fail('ADMIN_ORIGIN_INVALID', 403); }
  if (origin.origin !== identity.origin || origin.username || origin.password || (origin.protocol !== 'https:' && !loopbackHost(origin.hostname))) fail('ADMIN_ORIGIN_INVALID', 403);
  if (!ACTIONS.includes(ops.action) || !CONTRACTS[ops.action].methods.includes(ops.method)) fail('ADMIN_ACTION_INVALID', 400);
  if (['read', 'claim', 'replace', 'takeRate', 'deriveKey', 'mail', 'verifyRegistration', 'verifyAssertion', 'readSession', 'setSession', 'clearSession', 'verifySecret', 'publishPassword', 'securityReport', 'business'].some(name => typeof ops[name] !== 'function')) fail('ADMIN_OPERATION_UNAVAILABLE', 503);
  return { owner: digest(ADMIN_EMAIL + ':' + identity.userId), binding: identity.binding, origin: identity.origin, rpId: origin.hostname };
}
function configKey(scope) { return PREFIX + 'enrollment:' + digest(scope.owner + ':' + scope.origin); }
async function stored(ops, key) { ops.assertFullGuard(); const result = await ops.read(key); ops.assertFullGuard(); if (!result || result.ok !== true) fail('ADMIN_STORE_UNAVAILABLE', 503); return result.found === true ? result.record : null; }
async function config(ops, scope) {
  const value = await stored(ops, configKey(scope)); if (!value) return null;
  const enrollmentState = value.enrollmentState === undefined ? 'active' : value.enrollmentState;
  if (value.version !== VERSION || value.owner !== scope.owner || value.origin !== scope.origin || !exactToken(value.revision) || !value.passkey || !exactToken(value.userHandle) || !Number.isSafeInteger(value.passkey.signCount) || value.passkey.signCount < 0 || typeof value.totp !== 'string' || !['active', 'pending_totp'].includes(enrollmentState)) fail('ADMIN_ENROLLMENT_INVALID', 503);
  return value.enrollmentState === enrollmentState ? value : { ...value, enrollmentState };
}
async function issue(ops, scope, stage, values = {}, seconds = FACTOR_SECONDS) {
  const token = randomToken(), now = Date.now(); const record = { version: VERSION, owner: scope.owner, binding: scope.binding, origin: scope.origin, stage, ...values, expiresAt: now + seconds * 1000 };
  if (await ops.claim(PREFIX + 'ticket:' + digest(token), record, seconds) !== true) fail('ADMIN_STORE_UNAVAILABLE', 503); return token;
}
async function ticket(ops, scope, token, stage) {
  if (!exactToken(token)) fail('ADMIN_TICKET_INVALID', 401); const key = PREFIX + 'ticket:' + digest(token), value = await stored(ops, key);
  if (!value || value.version !== VERSION || value.owner !== scope.owner || value.origin !== scope.origin || value.binding !== scope.binding || value.stage !== stage || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()) fail('ADMIN_TICKET_EXPIRED', 401);
  if (await stored(ops, key + ':used')) fail('ADMIN_TICKET_ALREADY_USED', 409); return { key, value };
}
async function consume(ops, entry) { const remaining = Math.max(60, Math.ceil((entry.value.expiresAt - Date.now()) / 1000)); if (await ops.claim(entry.key + ':used', { version: VERSION, usedAt: Date.now() }, remaining) !== true) fail('ADMIN_TICKET_ALREADY_USED', 409); }
async function throttle(ops, scope, name, limit, seconds) { if (await ops.takeRate(PREFIX + 'rate:' + digest(scope.owner + ':' + scope.origin + ':' + name), limit, seconds) !== true) fail('ADMIN_RATE_LIMITED', 429); }
async function session(ops, scope, must = true) {
  const raw = ops.readSession(); if (!exactToken(raw)) { if (must) fail('ADMIN_THREE_FACTORS_REQUIRED', 401); return null; }
  try { const entry = await ticket(ops, scope, raw, 'session'); if (entry.value.factors !== 'email+passkey+totp') fail('ADMIN_THREE_FACTORS_REQUIRED', 401); return entry; }
  catch (error) { if (!must && [401, 409].includes(error.status)) return null; throw error; }
}
function validateClientData(credential, proof, scope) {
  if (!credential || typeof credential !== 'object' || Array.isArray(credential) || credential.type !== 'public-key' || typeof credential.id !== 'string' || typeof credential.rawId !== 'string' || credential.id !== credential.rawId || !/^[A-Za-z0-9_-]{22,1364}$/.test(credential.id) || !credential.response || typeof credential.response !== 'object' || Array.isArray(credential.response)) fail('ADMIN_PASSKEY_INVALID', 400);
  const encoded = credential.response.clientDataJSON; if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{1,8192}$/.test(encoded)) fail('ADMIN_PASSKEY_CLIENT_INVALID', 400);
  const bytes = decodeB64url(encoded, 8192, 1); let data; try { data = JSON.parse(bytes.toString('utf8')); } catch (_) { fail('ADMIN_PASSKEY_CLIENT_INVALID', 400); }
  if (!data || data.type !== (proof.mode === 'registration' ? 'webauthn.create' : 'webauthn.get') || data.challenge !== proof.challenge || data.origin !== scope.origin || (data.crossOrigin !== undefined && data.crossOrigin !== false) || data.topOrigin !== undefined) fail('ADMIN_PASSKEY_CLIENT_MISMATCH', 403);
  return data;
}
async function execute(ops) {
  const scope = checkOperations(ops), body = ops.body || {}, action = ops.action;
  if (ops.method === 'HEAD') return { ok: true };
  if (action === 'admin_entry') {
    const configured = adminSecretState().configured;
    return { ok: true, email: ADMIN_EMAIL, credentials_required: true, credentials_configured: configured, factor_count: 3, email_code_min: EMAIL_CODE_MIN, email_code_max: EMAIL_CODE_MAX, email_code_seconds: EMAIL_CODE_SECONDS, totp_period: 30 };
  }
  if (action === 'admin_security_report') {
    await throttle(ops, scope, 'security-report', 3, 60);
    const report = validateSecurityReport(body), result = await ops.securityReport(report);
    if (!result || !Number.isSafeInteger(result.blockedUntil) || result.blockedUntil <= Date.now()) fail('ADMIN_SECURITY_STORE_UNAVAILABLE', 503);
    fail('ADMIN_SECURITY_BLOCKED', 403);
  }
  if (action === 'admin_login') {
    await throttle(ops, scope, 'password-login', 5, FACTOR_SECONDS);
    if (String(body.email || '').trim().toLowerCase() !== ADMIN_EMAIL || typeof body.password !== 'string' || body.password.length > 4096 || !ops.verifySecret(body.password)) fail('ADMIN_CREDENTIALS_INVALID', 401);
    await ops.publishPassword();
    return { ok: true, stage: 'email', credentials_verified: true, email: ADMIN_EMAIL };
  }
  if (action === 'admin_status') {
    const nonceTarget = body._dirac_page_nonce_for;
    if (typeof nonceTarget === 'string' && Object.prototype.hasOwnProperty.call(CONTRACTS, nonceTarget) && CONTRACTS[nonceTarget].methods.includes('POST')) return { ok: true };
    const [enrolled, active] = await Promise.all([config(ops, scope), session(ops, scope, false)]);
    return { ok: true, email: ADMIN_EMAIL, enrolled: !!enrolled, authenticated: !!active, factor_count: 3, email_code_min: EMAIL_CODE_MIN, email_code_max: EMAIL_CODE_MAX, email_code_seconds: EMAIL_CODE_SECONDS, totp_period: 30, expires_at: null, persistent_session: !!active, action_email_required: true };
  }
  if (action === 'admin_email_start') {
    await throttle(ops, scope, 'email-start-minute', 1, 60); await throttle(ops, scope, 'email-start-hour', 5, 3600);
    const code = adminEmailCode(), codeLength = code.length, salt = randomToken(), reference = crypto.randomBytes(12).toString('hex');
    const token = await issue(ops, scope, 'email', { salt, codeHash: digest(salt + ':' + code), reference, codeLength }, EMAIL_CODE_SECONDS); const delivered = await ops.mail({ to: ADMIN_EMAIL, code, reference, expiresAt: Date.now() + EMAIL_CODE_SECONDS * 1000, kind: 'login', operation: '' });
    if (!delivered || delivered.ok !== true) fail('ADMIN_EMAIL_DELIVERY_UNCONFIRMED', 503); return { ok: true, ticket: token, stage: 'email', email: ADMIN_EMAIL, code_length: codeLength, min_chars: EMAIL_CODE_MIN, max_chars: EMAIL_CODE_MAX, expires_in: EMAIL_CODE_SECONDS, one_time: true };
  }
  if (action === 'admin_email_verify') {
    const entry = await ticket(ops, scope, body.ticket, 'email'); await throttle(ops, scope, 'email-verify:' + digest(body.ticket), 5, FACTOR_SECONDS);
    if (!Number.isInteger(entry.value.codeLength) || entry.value.codeLength < EMAIL_CODE_MIN || entry.value.codeLength > EMAIL_CODE_MAX || !validAdminEmailCode(body.code) || body.code.length !== entry.value.codeLength || !safeEqual(digest(entry.value.salt + ':' + body.code), entry.value.codeHash)) fail('ADMIN_EMAIL_CODE_INVALID', 401);
    await consume(ops, entry); return { ok: true, ticket: await issue(ops, scope, 'passkey-start'), stage: 'passkey' };
  }
  if (action === 'admin_action_email_start') {
    await session(ops, scope); const operation = String(body.operation || ''), payload = body.payload;
    if (!Object.prototype.hasOwnProperty.call(ADMIN_APPROVAL_MUTATIONS, operation)) fail('ADMIN_ACTION_APPROVAL_OPERATION_INVALID', 400);
    const payloadHash = approvalPayloadHash(operation, payload); await throttle(ops, scope, 'action-email-start-minute', 5, 60); await throttle(ops, scope, 'action-email-start-hour', 30, 3600);
    const code = adminEmailCode(), codeLength = code.length, salt = randomToken(), reference = crypto.randomBytes(12).toString('hex');
    const token = await issue(ops, scope, 'action-email', { salt, codeHash: digest(salt + ':' + code), reference, codeLength, operation, payloadHash }, EMAIL_CODE_SECONDS);
    const delivered = await ops.mail({ to: ADMIN_EMAIL, code, reference, expiresAt: Date.now() + EMAIL_CODE_SECONDS * 1000, kind: 'action', operation });
    if (!delivered || delivered.ok !== true) fail('ADMIN_EMAIL_DELIVERY_UNCONFIRMED', 503);
    return { ok: true, ticket: token, stage: 'action-email', operation, code_length: codeLength, min_chars: EMAIL_CODE_MIN, max_chars: EMAIL_CODE_MAX, expires_in: EMAIL_CODE_SECONDS, one_time: true };
  }
  if (action === 'admin_action_email_verify') {
    await session(ops, scope); const entry = await ticket(ops, scope, body.ticket, 'action-email'); await throttle(ops, scope, 'action-email-verify:' + digest(body.ticket), 5, FACTOR_SECONDS);
    if (!Number.isInteger(entry.value.codeLength) || entry.value.codeLength < EMAIL_CODE_MIN || entry.value.codeLength > EMAIL_CODE_MAX || !validAdminEmailCode(body.code) || body.code.length !== entry.value.codeLength || !safeEqual(digest(entry.value.salt + ':' + body.code), entry.value.codeHash)) fail('ADMIN_ACTION_EMAIL_CODE_INVALID', 401);
    await consume(ops, entry); const approval = await issue(ops, scope, 'action-approval', { operation: entry.value.operation, payloadHash: entry.value.payloadHash }, EMAIL_CODE_SECONDS);
    return { ok: true, approval, operation: entry.value.operation, expires_in: EMAIL_CODE_SECONDS, one_time: true };
  }
  if (action === 'admin_passkey_start') {
    const entry = await ticket(ops, scope, body.ticket, 'passkey-start'), enrolled = await config(ops, scope); await consume(ops, entry);
    const challenge = randomToken(), userHandle = enrolled ? enrolled.userHandle : randomToken(), mode = enrolled ? 'authentication' : 'registration';
    const token = await issue(ops, scope, 'passkey', { challenge, mode, userHandle, revision: enrolled ? enrolled.revision : null });
    const publicKey = mode === 'registration' ? { challenge, rp: { id: scope.rpId, name: 'PT DIRAC INOVASI NUSANTARA' }, user: { id: userHandle, name: ADMIN_EMAIL, displayName: 'Administrator DIRAC' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' }, timeout: 60000, attestation: 'none' } : { challenge, rpId: scope.rpId, userVerification: 'required', timeout: 60000, allowCredentials: [{ id: enrolled.passkey.credentialId, type: 'public-key' }] };
    return { ok: true, ticket: token, stage: 'passkey', mode, publicKey };
  }
  if (action === 'admin_passkey_verify') {
    const entry = await ticket(ops, scope, body.ticket, 'passkey'); await throttle(ops, scope, 'passkey-verify:' + digest(body.ticket), 5, FACTOR_SECONDS);
    const proof = entry.value, credential = body.credential, clientData = validateClientData(credential, proof, scope); let enrolled = await config(ops, scope), passkey, provisioning = null;
    if (proof.mode === 'registration') {
      if (enrolled) fail('ADMIN_ALREADY_ENROLLED', 409); const verified = await ops.verifyRegistration({ credential, clientData, rpId: scope.rpId });
      if (!verified || verified.ok !== true || verified.credentialId !== credential.id || !verified.publicKeyJwk) fail('ADMIN_PASSKEY_INVALID', 403); passkey = { credentialId: verified.credentialId, publicKeyJwk: verified.publicKeyJwk, signCount: verified.signCount, backupEligible: verified.backupEligible };
      const secret = crypto.randomBytes(32);
      try {
        const encrypted = seal(ops, secret, configKey(scope)), manualKey = base32(secret), label = 'DIRAC ' + scope.rpId + ':' + ADMIN_EMAIL;
        provisioning = { secret: manualKey, uri: 'otpauth://totp/' + encodeURIComponent(label) + '?secret=' + manualKey + '&issuer=' + encodeURIComponent('DIRAC ' + scope.rpId) + '&algorithm=SHA1&digits=6&period=30' };
        const pending = { version: VERSION, owner: scope.owner, origin: scope.origin, enrollmentState: 'pending_totp', revision: randomToken(), passkey, userHandle: proof.userHandle, totp: encrypted, createdAt: Date.now() };
        if (await ops.claim(configKey(scope), pending, PENDING_ENROLLMENT_SECONDS) !== true) fail('ADMIN_ALREADY_ENROLLED', 409); enrolled = pending;
      } finally { secret.fill(0); }
    } else {
      if (!enrolled || proof.revision !== enrolled.revision || credential.id !== enrolled.passkey.credentialId) fail('ADMIN_PASSKEY_STATE_CHANGED', 409); const handle = credential.response.userHandle;
      if (handle !== null && handle !== undefined && handle !== '' && handle !== enrolled.userHandle) fail('ADMIN_PASSKEY_USER_MISMATCH', 403); const verified = await ops.verifyAssertion({ credential, clientData, rpId: scope.rpId, passkey: enrolled.passkey });
      if (!verified || verified.ok !== true) fail('ADMIN_PASSKEY_INVALID', 403); passkey = { ...enrolled.passkey, signCount: verified.signCount }; const next = { ...enrolled, passkey, revision: randomToken() };
      if (await ops.replace(configKey(scope), enrolled.revision, next, next.enrollmentState === 'pending_totp' ? PENDING_ENROLLMENT_SECONDS : ENROLLMENT_SECONDS) !== true) fail('ADMIN_PASSKEY_STATE_CHANGED', 409); enrolled = next;
      if (enrolled.enrollmentState === 'pending_totp') { const secret = open(ops, enrolled.totp, configKey(scope)); try { const manualKey = base32(secret), label = 'DIRAC ' + scope.rpId + ':' + ADMIN_EMAIL; provisioning = { secret: manualKey, uri: 'otpauth://totp/' + encodeURIComponent(label) + '?secret=' + manualKey + '&issuer=' + encodeURIComponent('DIRAC ' + scope.rpId) + '&algorithm=SHA1&digits=6&period=30' }; } finally { secret.fill(0); } }
    }
    await consume(ops, entry); const pending = enrolled.enrollmentState === 'pending_totp';
    const token = await issue(ops, scope, 'totp', { enroll: pending, totp: enrolled.totp, revision: enrolled.revision }); return { ok: true, ticket: token, stage: 'totp', enrollment: pending ? provisioning : null, period: 30 };
  }
  if (action === 'admin_totp_verify') {
    const entry = await ticket(ops, scope, body.ticket, 'totp'); await throttle(ops, scope, 'totp-verify', 5, FACTOR_SECONDS);
    if (typeof body.code !== 'string' || !/^[0-9]{6}$/.test(body.code)) fail('ADMIN_TOTP_INVALID', 401); const proof = entry.value, enrolled = await config(ops, scope);
    if (!enrolled || enrolled.revision !== proof.revision || enrolled.totp !== proof.totp || (proof.enroll ? enrolled.enrollmentState !== 'pending_totp' : enrolled.enrollmentState !== 'active')) fail('ADMIN_ENROLLMENT_STATE_CHANGED', 409);
    const secret = open(ops, proof.totp, configKey(scope)); let accepted = null;
    try { const current = Math.floor(Date.now() / 30000), match = [current, current - 1, current + 1].find(counter => safeEqual(totp(secret, counter), body.code)); accepted = Number.isSafeInteger(match) ? match : null; } finally { secret.fill(0); }
    if (accepted === null) fail('ADMIN_TOTP_INVALID', 401); if (await ops.claim(PREFIX + 'totp-used:' + digest(scope.owner + ':' + scope.origin + ':' + proof.totp + ':' + accepted), { version: VERSION }, 120) !== true) fail('ADMIN_TOTP_ALREADY_USED', 409); await consume(ops, entry);
    if (proof.enroll) { const active = { ...enrolled, enrollmentState: 'active', revision: randomToken(), activatedAt: Date.now() }; if (await ops.replace(configKey(scope), enrolled.revision, active, ENROLLMENT_SECONDS) !== true) fail('ADMIN_ENROLLMENT_STATE_CHANGED', 409); }
    const token = await issue(ops, scope, 'session', { factors: 'email+passkey+totp' }, SESSION_SECONDS); ops.setSession(token, SESSION_SECONDS); return { ok: true, stage: 'complete', authenticated: true, expires_in: null, persistent_session: true, action_email_required: true };
  }
  if (action === 'admin_logout') { const active = await session(ops, scope, false); if (active) await consume(ops, active); await ops.clearSession(); return { ok: true }; }
  await session(ops, scope); const operation = { admin_orders: 'orders', admin_shipment_update: 'shipment_update', admin_shipment_cancel: 'shipment_cancel', admin_blocks: 'blocks', admin_unban: 'unban', admin_monitor: 'monitor' }[action];
  if (!operation) fail('ADMIN_ACTION_INVALID', 400);
  if (Object.prototype.hasOwnProperty.call(ADMIN_APPROVAL_MUTATIONS, action)) { const approval = await ticket(ops, scope, body.approval, 'action-approval'); if (approval.value.operation !== action || approval.value.payloadHash !== approvalPayloadHash(action, body)) fail('ADMIN_ACTION_APPROVAL_MISMATCH', 403); await consume(ops, approval); }
  ops.assertFullGuard(); return ops.business(operation, body);
}

function shipmentKey(kind, id) { if (!Object.prototype.hasOwnProperty.call(ORDER_SELECT, kind) || !isUuid(id)) fail('ADMIN_ORDER_ID_INVALID', 400); return SHIPMENT_PREFIX + kind + ':' + String(id).toLowerCase(); }
function shipmentTimestamp(value) {
  if (typeof value !== 'string') return null; const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(?:Z|\+00:00)$/.exec(value); if (!match) return null;
  const ms = Date.parse(match[1] + 'Z'); if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== match[1]) return null; return BigInt(ms) * 1000n + BigInt((match[2] || '').padEnd(6, '0'));
}
function businessText(value, maximum, required = false) { if (typeof value !== 'string' || value.length > maximum || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(value) || (required && !value.trim())) fail('ADMIN_SHIPMENT_TEXT_INVALID', 400); return value.trim(); }
function validateShipmentRow(row, key) {
  if (!row || typeof row !== 'object' || Array.isArray(row) || row.security_key !== key || Number(row.blocked_until_ms) !== 0 || shipmentTimestamp(row.updated_at) === null || !Number.isFinite(Date.parse(row.expires_at)) || Date.parse(row.expires_at) <= Date.now()) return null;
  const value = row.record_json;
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schema !== 'dirac.admin_shipment.v406' || !['active', 'cancelled'].includes(value.state) || !isUuid(value.customer_id) || !isUuid(value.updated_by) || !Number.isSafeInteger(value.revision) || value.revision < 1 || !['prepared', 'shipped', 'in_transit', 'delivered', 'cancelled'].includes(value.status) || (value.state === 'cancelled') !== (value.status === 'cancelled') || shipmentTimestamp(value.updated_at) === null || shipmentTimestamp(value.updated_at) !== shipmentTimestamp(row.updated_at) || !Array.isArray(value.events) || value.events.length < 1 || value.events.length > 50) return null;
  try { if (shipmentKey(value.order_kind, value.order_id) !== key || !/^[A-Za-z0-9][A-Za-z0-9 ._-]{2,99}$/.test(value.tracking_number)) return null; businessText(value.courier, 80, true); businessText(value.location, 160); businessText(value.origin, 600); businessText(value.destination, 600); if (value.estimated_delivery !== '' && (!/^\d{4}-\d{2}-\d{2}$/.test(value.estimated_delivery) || !Number.isFinite(Date.parse(value.estimated_delivery)))) return null; const invalidEvent = value.events.some(event => { if (!event || typeof event !== 'object' || Array.isArray(event) || !Number.isFinite(Date.parse(event.timestamp)) || typeof event.status !== 'string') return true; businessText(event.description, 300, true); businessText(event.location, 160); return false; }); if (invalidEvent) return null; } catch (_) { return null; }
  return value;
}
function shipmentPublic(value) { return value ? { tracking_number: value.tracking_number, courier: value.courier, state: value.state, status: value.status, location: value.location, origin: value.origin, destination: value.destination, estimated_delivery: value.estimated_delivery, updated_at: value.updated_at, revision: value.revision, events: value.events.map(event => ({ timestamp: event.timestamp, status: event.status, description: event.description, location: event.location })) } : null; }
function orderPublic(row, kind) {
  if (!row || !isUuid(row.id) || !isUuid(row.customer_id)) fail('ADMIN_ORDER_RECORD_INVALID', 503);
  const total = Number(row.total === undefined ? row.total_price : row.total); if (!Number.isFinite(total)) fail('ADMIN_ORDER_RECORD_INVALID', 503);
  return { id: row.id, kind, order_id: String(row.order_id || (kind === 'domain' ? 'DOM-' + row.id.slice(0, 8).toUpperCase() : row.id)), customer_id: row.customer_id, customer_name: String(row.customer_name || '').slice(0, 160), customer_email: String(row.customer_email || '').slice(0, 254), customer_phone: String(row.customer_phone || row.customer_whatsapp || '').slice(0, 40), shipping_address: String(row.shipping_address || '').slice(0, 600), service_type: kind === 'domain' ? 'domain' : String(row.service_type || '').slice(0, 60), domain_name: String(row.domain_name || '').slice(0, 254), total, currency: String(row.currency || 'IDR').slice(0, 8), payment_method: String(row.payment_method || '').slice(0, 80), payment_status: String(row.payment_status || '').slice(0, 40), order_status: String(row.order_status || '').slice(0, 40), created_at: row.created_at };
}
async function businessOrders(body) {
  const kind = String(body.kind || 'regular'), offsetRaw = String(body.offset || '0'); if (!Object.prototype.hasOwnProperty.call(ORDER_SELECT, kind) || !/^(0|[1-9][0-9]{0,4})$/.test(offsetRaw) || Number(offsetRaw) > 50000) fail('ADMIN_PAGE_INVALID', 400);
  const table = kind === 'domain' ? 'domain_orders' : 'orders', path = '/rest/v1/' + table + '?select=' + encodeURIComponent(ORDER_SELECT[kind]) + '&order=created_at.desc,id.desc&limit=41&offset=' + Number(offsetRaw), result = await dbFetch(path, { method: 'GET' });
  if (!result.ok || !Array.isArray(result.data) || result.data.length > 41) fail('ADMIN_DATA_UNAVAILABLE', 503); const rows = result.data, orders = rows.slice(0, 40).map(row => orderPublic(row, kind)), keys = orders.map(row => shipmentKey(kind, row.id));
  let shipments = []; if (keys.length) { const shipped = await dbFetch('/rest/v1/dirac_s2s_security?select=' + encodeURIComponent(SHIPMENT_SELECT) + '&security_key=in.(' + keys.map(encodeURIComponent).join(',') + ')&limit=' + keys.length, { method: 'GET' }, 'security'); if (!shipped.ok || !Array.isArray(shipped.data) || shipped.data.length > keys.length) fail('ADMIN_SHIPMENT_RECORD_INVALID', 503); shipments = shipped.data; }
  const map = new Map(); shipments.forEach(row => { if (!keys.includes(row && row.security_key) || map.has(row.security_key)) fail('ADMIN_SHIPMENT_RECORD_INVALID', 503); const value = validateShipmentRow(row, row.security_key), order = orders.find(item => item.id === (value && value.order_id)); if (!value || !order || order.customer_id !== value.customer_id) fail('ADMIN_SHIPMENT_OWNER_MISMATCH', 503); map.set(row.security_key, value); });
  return { ok: true, kind, offset: Number(offsetRaw), has_more: rows.length === 41, orders: orders.map(row => ({ ...row, shipment: shipmentPublic(map.get(shipmentKey(kind, row.id))) })), time: new Date().toISOString() };
}
async function loadOrder(kind, id) {
  const table = kind === 'domain' ? 'domain_orders' : 'orders', path = '/rest/v1/' + table + '?select=' + encodeURIComponent(ORDER_SELECT[kind]) + '&id=eq.' + encodeURIComponent(id) + '&limit=2', result = await dbFetch(path, { method: 'GET' });
  if (!result.ok || !Array.isArray(result.data)) fail('ADMIN_DATA_UNAVAILABLE', 503); if (result.data.length !== 1 || result.data[0].id !== id) fail('ADMIN_ORDER_NOT_FOUND', 404); return orderPublic(result.data[0], kind);
}
async function loadShipment(key) {
  const result = await dbFetch('/rest/v1/dirac_s2s_security?select=' + encodeURIComponent(SHIPMENT_SELECT) + '&security_key=eq.' + encodeURIComponent(key) + '&limit=2', { method: 'GET' }, 'security');
  if (!result.ok || !Array.isArray(result.data) || result.data.length > 1) fail('ADMIN_DATA_UNAVAILABLE', 503); if (!result.data.length) return { row: null, value: null }; const value = validateShipmentRow(result.data[0], key); if (!value) fail('ADMIN_SHIPMENT_RECORD_INVALID', 503); return { row: result.data[0], value };
}
async function businessShipment(body, cancel) {
  const kind = String(body.kind || ''), id = String(body.order_id || ''), key = shipmentKey(kind, id), revision = body.expected_revision; if (!Number.isSafeInteger(revision) || revision < 0 || revision >= Number.MAX_SAFE_INTEGER) fail('ADMIN_REVISION_INVALID', 400);
  const order = await loadOrder(kind, id), current = await loadShipment(key); if (current.value && current.value.customer_id !== order.customer_id) fail('ADMIN_SHIPMENT_OWNER_MISMATCH', 503); if (revision !== (current.value ? current.value.revision : 0)) fail('ADMIN_VERSION_CONFLICT', 409); if (cancel && (!current.value || current.value.state === 'cancelled')) fail('ADMIN_SHIPMENT_NOT_ACTIVE', 409);
  const description = businessText(body.description || (cancel ? 'Resi dibatalkan oleh admin.' : 'Informasi pengiriman diperbarui oleh admin.'), 300, true), status = cancel ? 'cancelled' : String(body.status || ''); if (!['prepared', 'shipped', 'in_transit', 'delivered', 'cancelled'].includes(status) || (!cancel && status === 'cancelled')) fail('ADMIN_SHIPMENT_STATUS_INVALID', 400);
  const tracking = cancel ? current.value.tracking_number : String(body.tracking_number || '').trim(); if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{2,99}$/.test(tracking)) fail('ADMIN_TRACKING_NUMBER_INVALID', 400);
  const now = Math.max(Date.now(), current.row ? Date.parse(current.row.updated_at) + 1 : 0), timestamp = new Date(now).toISOString(), value = { schema: 'dirac.admin_shipment.v406', order_kind: kind, order_id: id, customer_id: order.customer_id, revision: revision + 1, state: cancel ? 'cancelled' : 'active', tracking_number: tracking, courier: cancel ? current.value.courier : businessText(body.courier, 80, true), status, location: cancel ? current.value.location : businessText(body.location || '', 160), origin: cancel ? current.value.origin : businessText(body.origin || '', 600), destination: cancel ? current.value.destination : businessText(body.destination || order.shipping_address || '', 600), estimated_delivery: cancel ? current.value.estimated_delivery : String(body.estimated_delivery || ''), events: (current.value ? current.value.events : []).slice(-49), updated_at: timestamp, updated_by: ADMIN_USER_ID };
  value.events.push({ timestamp, status, description, location: value.location }); const row = { security_key: key, record_json: value, blocked_until_ms: 0, expires_at: new Date(now + ENROLLMENT_SECONDS * 1000).toISOString(), updated_at: timestamp }; if (!validateShipmentRow(row, key)) fail('ADMIN_SHIPMENT_RECORD_INVALID', 400);
  let path, method, bodyValue; if (!current.row) { path = '/rest/v1/dirac_s2s_security?select=' + encodeURIComponent(SHIPMENT_SELECT); method = 'POST'; bodyValue = [row]; } else { path = '/rest/v1/dirac_s2s_security?select=' + encodeURIComponent(SHIPMENT_SELECT) + '&security_key=eq.' + encodeURIComponent(key) + '&updated_at=eq.' + encodeURIComponent(current.row.updated_at); method = 'PATCH'; bodyValue = row; }
  const result = await dbFetch(path, { method, prefer: 'return=representation', body: bodyValue }, 'security'); if (!result.ok || !Array.isArray(result.data) || result.data.length !== 1) fail('ADMIN_VERSION_CONFLICT', 409); const confirmed = validateShipmentRow(result.data[0], key); if (!confirmed || stableJson(confirmed) !== stableJson(value)) fail('ADMIN_SHIPMENT_WRITE_UNVERIFIED', 503); return { ok: true, shipment: shipmentPublic(confirmed) };
}
function accessBlockKey(blockId) { return isUuid(blockId) ? 'customer-access-block-v325:event:' + String(blockId).toLowerCase() : ''; }
function accessBlockDigest(scope, value) { const cleanScope = String(scope || '').toLowerCase(), clean = String(value || '').trim().toLowerCase(); if (cleanScope === 'account' ? !isUuid(clean) : !['ip', 'device'].includes(cleanScope) || !/^[a-f0-9]{64}$/.test(clean)) return ''; const key = deriveSecret('customer-access-block-v325-key'); try { return crypto.createHmac('sha256', key).update(['v325', cleanScope, clean].join('\0')).digest('hex'); } finally { key.fill(0); } }
function accessBlockStorageKeys(record) {
  const id = String(record.block_id || '').toLowerCase(), event = accessBlockKey(id), ip = accessBlockDigest('ip', record.ip_hash), device = accessBlockDigest('device', record.device_hash), account = record.customer_id ? accessBlockDigest('account', record.customer_id) : '';
  const keys = [event, account && 'customer-access-block-v325:account:' + account + ':' + id, ip && 'customer-access-block-v325:ip:' + ip + ':' + id, device && 'customer-access-block-v325:device:' + device + ':' + id].filter(Boolean).sort(); return event && ip && device && keys.length === (record.customer_id ? 4 : 3) ? keys : [];
}
function validateAccessBlock(row, canonicalOnly = false) {
  if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).sort().join(',') !== 'blocked_until_ms,expires_at,record_json,security_key') return null; const record = row.record_json;
  if (!record || typeof record !== 'object' || Array.isArray(record) || Object.keys(record).sort().join(',') !== ACCESS_BLOCK_RECORD_KEYS.join(',')) return null;
  const id = String(record.block_id || '').trim().toLowerCase(), customer = record.customer_id === null ? null : String(record.customer_id || '').trim().toLowerCase(), ip = String(record.ip_hash || '').toLowerCase(), device = String(record.device_hash || '').toLowerCase(), blocked = Number(row.blocked_until_ms), expires = Date.parse(String(row.expires_at || ''));
  if (record.schema !== 'dirac.customer_access_block' || record.version !== 325 || !isUuid(id) || record.block_id !== id || (customer !== null && (!isUuid(customer) || record.customer_id !== customer)) || !/^[a-f0-9]{64}$/.test(ip) || !/^[a-f0-9]{64}$/.test(device) || record.ip_hash !== ip || record.device_hash !== device || !Number.isSafeInteger(blocked) || record.blocked_until_ms !== blocked || !Number.isSafeInteger(record.created_at_ms) || !Number.isSafeInteger(record.updated_at_ms) || record.created_at_ms <= 0 || record.updated_at_ms < record.created_at_ms || !Number.isFinite(expires) || expires < blocked || expires < record.updated_at_ms || record.fail_count !== 1 || !/^[a-z0-9_:-]{1,120}$/i.test(String(record.action || '')) || typeof record.reason !== 'string' || !record.reason.trim() || record.reason.length > 500 || /[\u0000-\u001f\u007f]/.test(record.reason) || !['active', 'revoked'].includes(record.state)) return null;
  const meta = record.metadata, metaKeys = meta && typeof meta === 'object' && !Array.isArray(meta) ? Object.keys(meta).sort().join(',') : ''; if (!meta || !['origin,source,user_agent_hash', 'identity_email,identity_email_source,identity_email_verified,origin,source,user_agent_hash'].includes(metaKeys) || meta.source !== 'customer_security_gate' || !/^[a-f0-9]{64}$/.test(String(meta.user_agent_hash || '')) || (Object.prototype.hasOwnProperty.call(meta, 'identity_email') && meta.identity_email !== null && !isEmail(meta.identity_email)) || (Object.prototype.hasOwnProperty.call(meta, 'identity_email_verified') && typeof meta.identity_email_verified !== 'boolean') || (Object.prototype.hasOwnProperty.call(meta, 'identity_email_source') && !/^[a-z_]{3,64}$/.test(String(meta.identity_email_source || ''))) || (meta.origin !== null && (typeof meta.origin !== 'string' || meta.origin.length > 320 || /[\u0000-\u001f\u007f]/.test(meta.origin)))) return null;
  if (record.state === 'active' && record.revocation !== null) return null; if (record.state === 'revoked') { const rev = record.revocation; if (!rev || typeof rev !== 'object' || Array.isArray(rev) || Object.keys(rev).sort().join(',') !== 'admin_email,admin_role,admin_user_id,revoked_at_ms,source' || rev.source !== 'admin_security_center_supabase' || !isEmail(rev.admin_email) || !/^[A-Za-z0-9._:@-]{1,160}$/.test(String(rev.admin_user_id || '')) || !/^[A-Za-z0-9._:@-]{1,80}$/.test(String(rev.admin_role || '')) || !Number.isSafeInteger(rev.revoked_at_ms) || rev.revoked_at_ms !== blocked || record.updated_at_ms !== blocked) return null; }
  const expected = accessBlockStorageKeys(record), stored = Array.isArray(record.storage_keys) ? record.storage_keys.slice() : []; if (!expected.length || stored.length !== expected.length || new Set(stored).size !== stored.length || stored.some((key, index) => key !== expected[index]) || !expected.includes(row.security_key) || (canonicalOnly && row.security_key !== accessBlockKey(id))) return null;
  return { ...record, security_key: row.security_key, storage_keys: expected };
}

function persistentBanRecord(record, securityKey) {
  const source = record && typeof record === 'object' && !Array.isArray(record) ? record : {}, type = String(source.type || '').trim(), eventType = String(source.event_type || '').trim(), key = String(securityKey || '').trim(), blocked = Number(source.blocked_until_ms || source.blockedUntilMs || 0);
  const loginBan = /^domain-login-(?:account|ip|device):[a-f0-9]{64}$/i.test(key) && (source.permanent === true || (Number.isSafeInteger(blocked) && blocked > 0));
  return loginBan || (source.schema === 'dirac.customer_access_block' && source.state === 'active') || ['central_guard_transient_lockout_v335', 'global_hard_ban_v107', 'xss_one_strike_permanent_block_v3', 'global_api_threat_ban_v143', 'recovery_one_strike_persistent_ban_v201', 'central_guard_global_ban_v146', 'central_guard_transient_persistent_ban_v284', 'central_external_ban_v354', 'dirac_s2s_key_revocation_v206'].includes(type) || ['bola_idor_global_hard_ban', 'sqlmap_or_sqli_block'].includes(eventType);
}

async function businessBlocks(body) {
  const raw = String(body.offset || '0'); if (!/^(0|[1-9][0-9]{0,4})$/.test(raw) || Number(raw) > 50000) fail('ADMIN_PAGE_INVALID', 400); const result = await dbFetch('/rest/v1/dirac_persistent_bans?select=' + encodeURIComponent(ACCESS_BLOCK_SELECT) + '&blocked_until_ms=gt.0&order=security_key.asc&limit=41&offset=' + Number(raw), { method: 'GET' }, 'security'); if (!result.ok || !Array.isArray(result.data) || result.data.length > 41) fail('ADMIN_DATA_UNAVAILABLE', 503);
  const blocks = [], seen = new Set(); result.data.slice(0, 40).forEach(row => {
    const value = validateAccessBlock(row, false);
    if (value) {
      if (seen.has(value.block_id) || value.state !== 'active' || value.blocked_until_ms <= Date.now()) return;
      seen.add(value.block_id); const meta = value.metadata || {}, mirrored = /^(central_guard_|wrong_password_rate_limit_)/.test(value.reason);
      blocks.push({ id: value.block_id, customer_email: isEmail(meta.identity_email) ? String(meta.identity_email).toLowerCase() : '', email_verified: meta.identity_email_verified === true, family: 'customer_access', reason: value.reason.slice(0, 300), created_at: new Date(value.created_at_ms).toISOString(), active: true, can_unban: !mirrored, review_note: mirrored ? 'Blokir ini terkait otoritas guard asal. Membuka salinan akses saja tidak memulihkan akses akun.' : 'Membuka catatan akses ini; blokir lain tetap diperiksa.' });
      return;
    }
    const record = row && row.record_json;
    if (!persistentBanRecord(record, row && row.security_key)) return;
    const id = digest(String(row.security_key || '')); if (seen.has(id)) return; seen.add(id);
    const email = String(record.identity_email || record.identityEmail || record.email || '').trim().toLowerCase();
    blocks.push({ id, customer_email: isEmail(email) ? email : '', email_verified: record.identity_email_verified === true, family: String(record.type || record.event_type || 'persistent').slice(0, 80), reason: String(record.reason || record.ban_reason || record.reason_code || '').slice(0, 300), created_at: String(record.created_at || record.createdAt || '').slice(0, 48), active: true, can_unban: false, review_note: 'Blokir ini terkait otoritas guard asal dan hanya ditampilkan sebagai baca-saja.' });
  });
  return { ok: true, blocks, offset: Number(raw), has_more: result.data.length === 41, time: new Date().toISOString() };
}
async function businessUnban(body) {
  const id = String(body.block_id || '').toLowerCase(), key = accessBlockKey(id); if (!key) fail('ADMIN_BLOCK_ID_INVALID', 400); const read = await dbFetch('/rest/v1/dirac_persistent_bans?select=' + encodeURIComponent(ACCESS_BLOCK_SELECT) + '&security_key=eq.' + encodeURIComponent(key) + '&limit=2', { method: 'GET' }, 'security'); if (!read.ok || !Array.isArray(read.data) || read.data.length > 1) fail('ADMIN_BLOCK_STORE_UNAVAILABLE', 503); if (!read.data.length) fail('ADMIN_BLOCK_NOT_FOUND', 404); const row = validateAccessBlock(read.data[0], true); if (!row) fail('ADMIN_BLOCK_RECORD_INVALID', 503); if (/^(central_guard_|wrong_password_rate_limit_)/.test(row.reason)) fail('ADMIN_ORIGINAL_BAN_AUTHORITY_REQUIRED', 409); if (row.state !== 'active' || row.blocked_until_ms <= Date.now()) return { ok: true, affected_rows: 0, time: new Date().toISOString() };
  const now = Date.now(), next = { ...row }; delete next.security_key; next.reason = 'manual_unblock_from_admin_security_center'; next.blocked_until_ms = now; next.updated_at_ms = now; next.state = 'revoked'; next.revocation = { source: 'admin_security_center_supabase', admin_user_id: ADMIN_USER_ID, admin_email: ADMIN_EMAIL, admin_role: 'owner', revoked_at_ms: now };
  const path = '/rest/v1/dirac_persistent_bans?security_key=in.(' + row.storage_keys.map(encodeURIComponent).join(',') + ')&blocked_until_ms=gt.' + now + '&select=' + encodeURIComponent(ACCESS_BLOCK_SELECT), patched = await dbFetch(path, { method: 'PATCH', prefer: 'return=representation', body: { record_json: next, blocked_until_ms: now } }, 'security'); if (!patched.ok || !Array.isArray(patched.data) || patched.data.length !== row.storage_keys.length) fail('ADMIN_BLOCK_REVOCATION_UNVERIFIED', 503); const returned = patched.data.map(item => validateAccessBlock(item, false)); if (returned.some(item => !item || item.block_id !== id || item.state !== 'revoked') || returned.map(item => item.security_key).sort().some((item, index) => item !== row.storage_keys[index])) fail('ADMIN_BLOCK_REVOCATION_UNVERIFIED', 503); return { ok: true, affected_rows: 1, time: new Date().toISOString() };
}
function adminGuardSelfTest() {
  try {
    const expected = ['admin_entry','admin_security_report','admin_login','admin_status','admin_email_start','admin_email_verify','admin_action_email_start','admin_action_email_verify','admin_passkey_start','admin_passkey_verify','admin_totp_verify','admin_logout','admin_orders','admin_shipment_update','admin_shipment_cancel','admin_blocks','admin_unban','admin_monitor'];
    return Object.isFrozen(CONTRACTS) && Object.isFrozen(ACTIONS) && ACTIONS.length === expected.length && expected.every((name, index) => ACTIONS[index] === name && Object.isFrozen(CONTRACTS[name]) && Object.isFrozen(CONTRACTS[name].methods) && Object.isFrozen(CONTRACTS[name].allowed) && Object.isFrozen(CONTRACTS[name].required))
      && exactToken(randomToken()) && PASSWORD_COOKIE.startsWith('__Host-') && SESSION_COOKIE.startsWith('__Host-') && adminSecretState().configured === true;
  } catch (_) { return false; }
}
const ADMIN_STATIC_GATE = Object.freeze({ ok: Object.isFrozen(CONTRACTS) && Object.isFrozen(ACTIONS) && !ACTIONS.includes('__proto__') && !ACTIONS.includes('constructor') });

async function businessMonitor() {
  let rows = [], ready = false; try { const result = await dbFetch('/rest/v1/security_customer_events?select=id,event_type,status,risk_level,description,created_at&order=created_at.desc&limit=20', { method: 'GET' }); if (result.ok && Array.isArray(result.data) && result.data.length <= 20) { rows = result.data; ready = true; } } catch (_) { ready = false; }
  const memory = process.memoryUsage(); return { ok: true, time: new Date().toISOString(), guard: { self_test_ok: adminGuardSelfTest(), static_gate_ok: ADMIN_STATIC_GATE.ok, scope: 'Guard internal handler admin mandiri yang menangani permintaan ini.' }, runtime: { uptime_seconds: Math.floor(process.uptime()), rss_bytes: memory.rss, heap_used_bytes: memory.heapUsed, heap_total_bytes: memory.heapTotal }, events_ready: ready, events: ready ? rows.map(row => ({ event_type: String(row && row.event_type || '').slice(0, 100), status: String(row && row.status || '').slice(0, 40), risk_level: String(row && row.risk_level || '').slice(0, 40), description: String(row && row.description || '').slice(0, 240), created_at: String(row && row.created_at || '').slice(0, 48) })) : [] };
}
async function business(operation, body) { if (operation === 'orders') return businessOrders(body); if (operation === 'shipment_update') return businessShipment(body, false); if (operation === 'shipment_cancel') return businessShipment(body, true); if (operation === 'blocks') return businessBlocks(body); if (operation === 'unban') return businessUnban(body); if (operation === 'monitor') return businessMonitor(); fail('ADMIN_OPERATION_INVALID', 400); }

function allowedAdminKey(key) { return typeof key === 'string' && /^s2s-admin-v405:(?:ticket:[a-f0-9]{64}(?::used)?|enrollment:[a-f0-9]{64}|totp-used:[a-f0-9]{64}|rate:[a-f0-9]{64})$/.test(key); }
async function replaceEnrollment(records, key, expectedRevision, record, ttl) {
  const previous = records.get(key), expectedTtl = record && record.enrollmentState === 'pending_totp' ? PENDING_ENROLLMENT_SECONDS : ENROLLMENT_SECONDS; if (!allowedAdminKey(key) || !key.startsWith(PREFIX + 'enrollment:') || !previous || previous.revision !== expectedRevision || !record || record.version !== VERSION || record.revision === expectedRevision || ttl !== expectedTtl) fail('ADMIN_STORAGE_COMPARE_INVALID', 503);
  const expiresAt = new Date(Math.max(Date.now() + ttl * 1000, Date.parse(previous.expiresAt) + 1)).toISOString(), path = '/rest/v1/dirac_s2s_security?security_key=eq.' + encodeURIComponent(key) + '&expires_at=eq.' + encodeURIComponent(previous.expiresAt) + '&select=security_key,expires_at'; const result = await dbFetch(path, { method: 'PATCH', prefer: 'return=representation', body: { record_json: record, expires_at: expiresAt } }, 'security'); return !!(result.ok && Array.isArray(result.data) && result.data.length === 1 && result.data[0].security_key === key && Date.parse(result.data[0].expires_at) === Date.parse(expiresAt));
}
function buildOps(req, res, state) {
  const records = new Map(), secretState = adminSecretState(), identity = Object.freeze({ email: ADMIN_EMAIL, userId: ADMIN_USER_ID, active: true, role: 'owner', origin: state.origin, binding: secretState.configured ? scopeBinding(state.origin, state.device, secretState.secret) : digest('unconfigured:' + state.origin + ':' + state.device) });
  let active = true; const assertFullGuard = () => { if (!active || state.req !== req || state.method !== String(req.method || '').toUpperCase() || state.action !== state.currentAction || state.origin !== sourceOrigin(req) || state.device !== deviceFingerprint(req, state.origin)) fail('ADMIN_FULL_GUARD_REQUIRED', 503); };
  const ops = Object.freeze({
    version: VERSION, action: state.action, method: state.method, identity, body: state.body, assertFullGuard,
    deriveKey: purpose => { assertFullGuard(); if (purpose !== 'totp-storage') fail('ADMIN_KEY_PURPOSE_INVALID', 503); const key = deriveSecret('admin-v405-totp-storage'); try { return crypto.createHmac('sha256', key).update(ADMIN_USER_ID).digest(); } finally { key.fill(0); } },
    read: async key => { assertFullGuard(); if (!allowedAdminKey(key)) fail('ADMIN_STORAGE_KEY_INVALID', 503); const result = await securityRead(key); assertFullGuard(); if (result.ok && result.found) records.set(key, { revision: result.record.revision, expiresAt: result.expiresAt }); return result; },
    claim: async (key, record, ttl) => { assertFullGuard(); if (!allowedAdminKey(key) || !record || record.version !== VERSION) fail('ADMIN_STORAGE_CLAIM_INVALID', 503); const result = await securityClaim(key, record, ttl); assertFullGuard(); return result; },
    replace: async (key, expectedRevision, record, ttl) => { assertFullGuard(); const result = await replaceEnrollment(records, key, expectedRevision, record, ttl); assertFullGuard(); return result; },
    takeRate: async (key, limit, seconds) => { assertFullGuard(); const actionMailHourly = state.action === 'admin_action_email_start' && limit === 30 && seconds === 3600; if (!allowedAdminKey(key) || !key.startsWith(PREFIX + 'rate:') || !Number.isInteger(limit) || limit < 1 || (limit > 5 && !actionMailHourly) || ![60, 600, 3600].includes(seconds)) fail('ADMIN_RATE_CONTRACT_INVALID', 503); const result = await atomicRate(key, limit, seconds); assertFullGuard(); return result; },
    mail: async message => { assertFullGuard(); const loginMail = state.action === 'admin_email_start' && message && message.kind === 'login' && message.operation === '', actionMail = state.action === 'admin_action_email_start' && message && message.kind === 'action' && Object.prototype.hasOwnProperty.call(ADMIN_APPROVAL_MUTATIONS, message.operation); if ((!loginMail && !actionMail) || message.to !== ADMIN_EMAIL || !validAdminEmailCode(message.code) || !/^[a-f0-9]{24}$/.test(message.reference) || !Number.isSafeInteger(message.expiresAt) || message.expiresAt <= Date.now() || message.expiresAt > Date.now() + EMAIL_CODE_SECONDS * 1000 + 5000) fail('ADMIN_MAIL_CONTRACT_INVALID', 503); const result = await sendAdminMail({ ...message, origin: state.origin }); assertFullGuard(); return result; },
    verifyRegistration: input => { assertFullGuard(); if (state.action !== 'admin_passkey_verify' || input.rpId !== new URL(state.origin).hostname) fail('ADMIN_PASSKEY_SCOPE_INVALID', 403); return verifyRegistration(input); },
    verifyAssertion: input => { assertFullGuard(); if (state.action !== 'admin_passkey_verify' || input.rpId !== new URL(state.origin).hostname) fail('ADMIN_PASSKEY_SCOPE_INVALID', 403); return verifyAssertion(input); },
    readSession: () => { assertFullGuard(); return cookieToken(req, SESSION_COOKIE); },
    setSession: (token, seconds) => { assertFullGuard(); if (state.action !== 'admin_totp_verify' || !exactToken(token) || seconds !== SESSION_SECONDS) fail('ADMIN_SESSION_PUBLICATION_INVALID', 503); appendCookie(res, SESSION_COOKIE + '=' + token + '; Path=/; Secure; HttpOnly; SameSite=Strict'); },
    clearSession: async () => { assertFullGuard(); if (state.action !== 'admin_logout') fail('ADMIN_SESSION_CLEAR_INVALID', 503); await revokePasswordProof(state.passwordAuthority); appendCookie(res, SESSION_COOKIE + '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'); appendCookie(res, PASSWORD_COOKIE + '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'); },
    verifySecret: value => { assertFullGuard(); const current = adminSecretState(); return current.configured && typeof value === 'string' && safeEqual(digest(value), digest(current.secret)); },
    publishPassword: async () => { assertFullGuard(); const current = adminSecretState(); if (!current.configured) fail('ADMIN_CREDENTIAL_NOT_CONFIGURED', 503); await publishPasswordProof(req, res, state.origin, state.device, current.secret); },
    securityReport: async report => { assertFullGuard(); if (state.action !== 'admin_security_report' || !report || report.evidenceHash === undefined) fail('ADMIN_SECURITY_REPORT_INVALID', 400); const result = await persistSecurityReport(state.origin, state.device, report); assertFullGuard(); res.setHeader('Retry-After', String(SECURITY_BLOCK_SECONDS)); return result; },
    business: async (operation, body) => { assertFullGuard(); if (!state.passwordAuthority || !['orders', 'shipment_update', 'shipment_cancel', 'blocks', 'unban', 'monitor'].includes(operation)) fail('ADMIN_THREE_FACTORS_REQUIRED', 403); const result = await business(operation, body); assertFullGuard(); return result; }
  });
  state.deactivate = () => { active = false; records.clear(); };
  return ops;
}

function setCommonHeaders(res, origin) {
  res.setHeader('Cache-Control', 'no-store, max-age=0'); res.setHeader('Pragma', 'no-cache'); res.setHeader('Expires', '0'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin'); res.setHeader('Vary', 'Origin'); res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Access-Control-Allow-Credentials', 'true'); res.setHeader('Access-Control-Expose-Headers', 'X-Dirac-CSRF-Token, X-Dirac-Page-Nonce'); res.setHeader('Content-Type', 'application/json; charset=utf-8');
}
function queryObject(query) { const out = {}; query.forEach((value, key) => { if (Object.prototype.hasOwnProperty.call(out, key)) fail('ADMIN_QUERY_DUPLICATE', 400); out[key] = value; }); return out; }
async function readJsonBody(req, maximum) {
  const contentType = String(req.headers && req.headers['content-type'] || '').split(';')[0].trim().toLowerCase(); if (contentType !== 'application/json') fail('ADMIN_CONTENT_TYPE_INVALID', 415);
  const declared = Number(req.headers && req.headers['content-length'] || 0); if (Number.isFinite(declared) && declared > maximum) fail('ADMIN_BODY_TOO_LARGE', 413);
  const chunks = []; let size = 0;
  await new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => { req.off('data', onData); req.off('end', onEnd); req.off('error', onError); req.off('aborted', onAborted); };
    const finish = callback => { if (settled) return; settled = true; cleanup(); callback(); };
    const rejectCode = (code, status) => finish(() => reject(Object.assign(new Error(code), { code, status, statusCode: status })));
    const onData = chunk => { if (settled) return; const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); size += bytes.length; if (size > maximum) { if (typeof req.pause === 'function') req.pause(); rejectCode('ADMIN_BODY_TOO_LARGE', 413); return; } chunks.push(bytes); };
    const onEnd = () => finish(resolve);
    const onError = () => rejectCode('ADMIN_BODY_INVALID', 400);
    const onAborted = () => rejectCode('ADMIN_BODY_INVALID', 400);
    req.on('data', onData); req.on('end', onEnd); req.on('error', onError); req.on('aborted', onAborted);
  });
  let data; try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (_) { fail('ADMIN_BODY_INVALID', 400); } if (!data || typeof data !== 'object' || Array.isArray(data)) fail('ADMIN_BODY_INVALID', 400); return data;
}
function validateShape(action, method, query, body) {
  const contract = CONTRACTS[action]; if (!contract || !contract.methods.includes(method)) fail('ADMIN_METHOD_NOT_ALLOWED', 405); const allowed = new Set(contract.allowed);
  if (Object.keys(query).some(key => !allowed.has(key))) fail('ADMIN_QUERY_FIELD_INVALID', 400);
  if (method === 'POST') { if (Object.keys(body).some(key => !allowed.has(key))) fail('ADMIN_BODY_FIELD_INVALID', 400); if (contract.required.some(key => !Object.prototype.hasOwnProperty.call(body, key))) fail('ADMIN_BODY_REQUIRED_FIELD', 400); if (body.action !== undefined && body.action !== action) fail('ADMIN_ACTION_MISMATCH', 400); }
  const source = method === 'POST' ? body : query; if (Object.entries(source).some(([key, value]) => Array.isArray(value) && !(contract.allowArrayItems && key === 'transports'))) fail('ADMIN_BODY_FIELD_INVALID', 400); if (Object.values(source).some(value => typeof value === 'string' && Buffer.byteLength(value, 'utf8') > contract.maxFieldBytes)) fail('ADMIN_FIELD_TOO_LARGE', 413);
}
function errorPayload(error) {
  const known = error && /^ADMIN_[A-Z0-9_]{1,90}$/.test(String(error.code || '')), supplied = Number(error && (error.status || error.statusCode) || 503), status = known && ALLOWED_RESPONSE_STATUSES.has(supplied) ? supplied : 503;
  return { status, body: { ok: false, code: known ? error.code : 'ADMIN_OPERATION_UNAVAILABLE', message: status === 503 ? 'Layanan admin belum dapat diverifikasi. Periksa konfigurasi yang diwajibkan lalu coba kembali.' : status === 429 ? 'Batas percobaan tercapai. Tunggu sebelum mencoba lagi.' : 'Verifikasi admin belum valid atau sudah kedaluwarsa.' } };
}
async function adminBusiness(req, res, operations) {
  try { return res.status(200).json(await execute(operations)); }
  catch (error) { const result = errorPayload(error); return res.status(result.status).json(result.body); }
}
async function adminHandler(req, res) {
  let origin = '';
  try {
    const raw = String(req && req.url || ''), split = raw.indexOf('?'), path = split < 0 ? raw : raw.slice(0, split);
    if (path !== '/api/admin' || raw.length > 8192 || /[\u0000-\u0020\u007f]/.test(raw)) fail('ADMIN_REQUEST_INVALID', 400);
    const queryParams = new URLSearchParams(split < 0 ? '' : raw.slice(split + 1)), actions = queryParams.getAll('action'), action = actions.length === 1 ? String(actions[0] || '') : ''; if (!ACTIONS.includes(action)) fail('ADMIN_ACTION_INVALID', 400);
    origin = sourceOrigin(req); validateReferer(req, origin, String(req.method || '').toUpperCase() === 'OPTIONS'); setCommonHeaders(res, origin);
    const method = String(req.method || '').toUpperCase();
    if (method === 'OPTIONS') {
      const requested = String(req.headers && req.headers['access-control-request-method'] || '').toUpperCase(), headers = String(req.headers && req.headers['access-control-request-headers'] || '').toLowerCase().split(',').map(item => item.trim()).filter(Boolean), allowedHeaders = new Set(['content-type', 'x-csrf-token', 'x-dirac-csrf-token', 'x-dirac-page-nonce']);
      if (requested !== 'POST' || !CONTRACTS[action].methods.includes('POST') || headers.some(header => !allowedHeaders.has(header))) fail('ADMIN_PREFLIGHT_INVALID', 403);
      res.setHeader('Access-Control-Allow-Methods', 'POST'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token, X-Dirac-CSRF-Token, X-Dirac-Page-Nonce'); res.setHeader('Access-Control-Max-Age', '600'); return res.status(204).end();
    }
    const device = deviceFingerprint(req, origin);
    if (adminSecretState().configured && !['admin_entry', 'admin_security_report', 'admin_logout'].includes(action)) {
      const blocked = await activeSecurityBlock(origin, device);
      if (blocked) { res.setHeader('Retry-After', String(Math.max(1, Math.ceil((blocked.blockedUntil - Date.now()) / 1000)))); fail('ADMIN_SECURITY_BLOCKED', 403); }
    }
    const contract = CONTRACTS[action], query = queryObject(queryParams), body = method === 'POST' ? await readJsonBody(req, contract.maxBodyBytes) : query; validateShape(action, method, query, body);
    const currentAction = action, state = { req, action, currentAction, method, origin, device, body, passwordAuthority: null, deactivate: null };
    if (method === 'POST') await verifyPageNonce(req, action, origin, device);
    if (!['admin_entry', 'admin_security_report', 'admin_login'].includes(action)) state.passwordAuthority = await verifyPasswordProof(req, origin, device, ['admin_email_start', 'admin_email_verify', 'admin_passkey_start', 'admin_passkey_verify', 'admin_totp_verify'].includes(action));
    if (action === 'admin_entry') {
      const target = String(query._dirac_page_nonce_for || ''); if (target) { if (!CONTRACTS[target] || !CONTRACTS[target].methods.includes('POST')) fail('ADMIN_NONCE_TARGET_INVALID', 400); const proof = issuePageNonce(target, origin, device); res.setHeader('X-Dirac-CSRF-Token', proof.csrf); res.setHeader('X-Dirac-Page-Nonce', proof.nonce); }
    }
    const ops = buildOps(req, res, state);
    try { const payload = await execute(ops); if (method === 'HEAD') return res.status(200).end(); return res.status(200).json(payload); }
    finally { if (state.deactivate) state.deactivate(); }
  } catch (error) {
    try { if (origin) setCommonHeaders(res, origin); else { res.setHeader('Cache-Control', 'no-store'); res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('X-Content-Type-Options', 'nosniff'); } } catch (_) {}
    const result = errorPayload(error); return res.status(result.status).json(result.body);
  }
}
Object.defineProperties(adminHandler, {
  config: { value: Object.freeze({ api: Object.freeze({ bodyParser: false }) }), enumerable: true },
  __diracAdminBusinessV405: { value: adminBusiness },
  __diracAdminContractsV405: { value: CONTRACTS },
  __diracAdminActionsV405: { value: ACTIONS },
  __diracAdminEmailV405: { value: ADMIN_EMAIL },
  __diracAdminVersionV405: { value: VERSION },
  __diracAdminStandaloneV411: { value: true },
  __diracAdminSelfTestV411: { value: Object.freeze({ ok: true, healthDependency: false, adminTableDependency: false, newEnvironmentNames: false }) }
});
module.exports = Object.freeze(adminHandler);

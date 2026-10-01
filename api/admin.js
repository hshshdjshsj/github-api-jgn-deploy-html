'use strict';

// Standalone administrator endpoint. The browser page is handled entirely by this module.
const crypto = require('node:crypto');
const tls = require('node:tls');
const ADMIN_STANDALONE_FETCH = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null;
if (!ADMIN_STANDALONE_FETCH) throw new Error('ADMIN_FETCH_UNAVAILABLE');

const ADMIN_EMAIL = 'dinzganteng888999@gmail.com';
const VERSION = 'dirac-admin-v405';
const PREFIX = 's2s-admin-v405:';
// v449: durable enrollment is separate from expiring authentication tickets.
const ADMIN_PASSKEY_TABLE = 'dirac_admin_passkeys';
const ADMIN_PASSKEY_SELECT = 'security_key,revision,record_json';
const ADMIN_BAN_OUTCOMES = new WeakMap();
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
const ADMIN_SMTP_RECIPIENT_MAX = 50;
const ADMIN_SMTP_ATTACHMENT_MAX_BYTES = 2 * 1024 * 1024;
const ADMIN_SMTP_BODY_MAX_BYTES = 3500000;
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
  admin_action_passkey_start: post(['operation', 'payload'], ['operation', 'payload']),
  admin_action_passkey_verify: post(['ticket', ...PASSKEY_FIELDS], ['ticket', 'credential'], 98304),
  admin_passkey_start: post(['ticket'], ['ticket']),
  admin_passkey_verify: post(['ticket', ...PASSKEY_FIELDS], ['ticket', 'credential'], 98304),
  admin_passkey_recovery_start: post(['ticket', 'recovery_secret', 'totp_code'], ['ticket', 'recovery_secret', 'totp_code']),
  admin_passkey_recovery_verify: post(['ticket', ...PASSKEY_FIELDS], ['ticket', 'credential'], 98304),
  admin_totp_verify: post(['ticket', 'code'], ['ticket', 'code']),
  admin_logout: post([]),
  admin_orders: get(['kind', 'offset']),
  admin_shipment_update: post(['kind', 'order_id', 'expected_revision', 'tracking_number', 'courier', 'status', 'location', 'origin', 'destination', 'estimated_delivery', 'description', 'tracking_options', 'review_ack', 'review_reason', 'approval'], ['kind', 'order_id', 'expected_revision', 'tracking_number', 'courier', 'status', 'approval']),
  admin_shipment_cancel: post(['kind', 'order_id', 'expected_revision', 'description', 'review_ack', 'review_reason', 'approval'], ['kind', 'order_id', 'expected_revision', 'approval']),
  admin_blocks: get(['offset']),
  admin_unban: post(['block_id', 'approval'], ['block_id', 'approval']),
  admin_smtp_send: Object.freeze({ methods: Object.freeze(['POST']), allowed: Object.freeze(['action', ...COMMON_PROOF, 'provider', 'recipients', 'recipient_count', 'recipients_sha256', 'subject', 'subject_sha256', 'body_text', 'body_sha256', 'document_kind', 'attachment_name', 'attachment_type', 'attachment_base64', 'attachment_sha256', 'legal_confirm', 'approval']), required: Object.freeze(['provider', 'recipients', 'recipient_count', 'recipients_sha256', 'subject', 'subject_sha256', 'body_text', 'body_sha256', 'document_kind', 'attachment_name', 'attachment_type', 'attachment_base64', 'attachment_sha256', 'legal_confirm', 'approval']), maxBodyBytes: ADMIN_SMTP_BODY_MAX_BYTES, maxFieldBytes: ADMIN_SMTP_BODY_MAX_BYTES, mutation: true, allowArrayItems: false }),
  admin_local_authorize: post(['purpose', 'content_sha256', 'approval'], ['purpose', 'content_sha256', 'approval']),
  admin_monitor: get()
});
const ACTIONS = Object.freeze(Object.keys(CONTRACTS));
const ADMIN_APPROVAL_MUTATIONS = Object.freeze({ admin_shipment_update: 'shipment_update', admin_shipment_cancel: 'shipment_cancel', admin_unban: 'unban', admin_smtp_send: 'smtp_send', admin_local_authorize: 'local_authorize' });
const ORDER_SELECT = Object.freeze({
  regular: 'id,order_id,customer_id,customer_name,customer_email,customer_phone,shipping_address,service_type,total,payment_method,payment_status,order_status,created_at',
  laboratorium: 'id,order_id,customer_id,customer_name,customer_email,customer_phone,shipping_address,service_type,total,payment_method,payment_status,order_status,created_at',
  domain: 'id,customer_id,customer_name,customer_email,customer_whatsapp,domain_name,total_price,currency,payment_status,order_status,created_at'
});
const DOMAIN_ORDER_COMPAT_SELECT = 'id,customer_id,domain_name,total_price,payment_status,order_status,created_at';
const SHIPMENT_PREFIX = 's2s-admin-shipment-v406:';
const SHIPMENT_SELECT = 'security_key,record_json,blocked_until_ms,expires_at,updated_at';
const ACCESS_BLOCK_SELECT = 'security_key,record_json,blocked_until_ms,expires_at';
const ACCESS_BLOCK_RECORD_KEYS = Object.freeze(['action', 'block_id', 'blocked_until_ms', 'created_at_ms', 'customer_id', 'device_hash', 'fail_count', 'ip_hash', 'metadata', 'reason', 'revocation', 'schema', 'state', 'storage_keys', 'updated_at_ms', 'version'].sort());
const ALLOWED_RESPONSE_STATUSES = new Set([400, 401, 403, 404, 405, 408, 409, 413, 415, 429, 503]);

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
function adminPasskeyRecoverySecretState() {
  const secret = String(process.env.DIRAC_ADMIN_PASSKEY_RECOVERY_SECRET || '');
  const minimum = isProduction() ? 64 : 32;
  if (!secret || Buffer.byteLength(secret, 'utf8') < minimum || Buffer.byteLength(secret, 'utf8') > 4096 || /[\u0000\r\n]/.test(secret)) return { configured: false, secret: '' };
  return { configured: true, secret };
}
function verifyAdminPasskeyRecoverySecret(value) {
  const current = adminPasskeyRecoverySecretState();
  return current.configured && typeof value === 'string' && value.length <= 4096 && safeEqual(digest(value), digest(current.secret));
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
    const response = await ADMIN_STANDALONE_FETCH(creds.url + cleanPath, { method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body), redirect: 'error', signal: controller.signal });
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

function enrollmentKey(key) { return typeof key === 'string' && /^s2s-admin-v405:enrollment:[a-f0-9]{64}$/.test(key); }
function validateDurableEnrollment(key, value) {
  if (!enrollmentKey(key) || !value || typeof value !== 'object' || Array.isArray(value)) fail('ADMIN_ENROLLMENT_INVALID', 503);
  const state = value.enrollmentState === undefined ? 'active' : value.enrollmentState, passkey = value.passkey;
  if (value.version !== VERSION || value.owner !== digest(ADMIN_EMAIL + ':' + ADMIN_USER_ID) || typeof value.origin !== 'string'
      || key !== configKey({ owner: value.owner, origin: value.origin }) || !exactToken(value.revision) || !exactToken(value.userHandle)
      || !['active', 'pending_totp'].includes(state) || !passkey || typeof passkey !== 'object' || Array.isArray(passkey)
      || typeof passkey.credentialId !== 'string' || !/^[A-Za-z0-9_-]{22,1364}$/.test(passkey.credentialId)
      || !Number.isSafeInteger(passkey.signCount) || passkey.signCount < 0 || passkey.signCount > 4294967295
      || typeof value.totp !== 'string' || !/^[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{22}$/.test(value.totp)
      || Buffer.byteLength(JSON.stringify(value), 'utf8') > 16384) fail('ADMIN_ENROLLMENT_INVALID', 503);
  let origin; try { origin = new URL(value.origin); } catch (_) { fail('ADMIN_ENROLLMENT_INVALID', 503); }
  if (origin.origin !== value.origin || origin.username || origin.password || (origin.protocol !== 'https:' && !loopbackHost(origin.hostname))) fail('ADMIN_ENROLLMENT_INVALID', 503);
  const jwk = passkey.publicKeyJwk;
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk) || !['EC', 'RSA'].includes(jwk.kty)
      || ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(name => Object.prototype.hasOwnProperty.call(jwk, name))) fail('ADMIN_ENROLLMENT_INVALID', 503);
  try { crypto.createPublicKey({ key: jwk, format: 'jwk' }); } catch (_) { fail('ADMIN_ENROLLMENT_INVALID', 503); }
  return value.enrollmentState === state ? value : { ...value, enrollmentState: state };
}
// v454: keep the same fail-closed storage contract; log only non-secret DB diagnostics.
function assertPasskeyStoreResultV454(result, operation) {
  if (result.ok && Array.isArray(result.data) && result.data.length <= 1) return;
  const value = result.data && !Array.isArray(result.data) && typeof result.data === 'object' ? result.data.code : null;
  const databaseCode = typeof value === 'string' && (value.length === 5 || value.length === 8) && /^(?:[0-9A-Z]{5}|PGRST[0-9]{3})$/.test(value) ? value : 'UNAVAILABLE';
  try {
    console.error('[dirac-admin-passkey-store-v454]', JSON.stringify({
      event: 'admin_passkey_store_failed',
      operation: ['read', 'claim', 'replace'].includes(operation) ? operation : 'unknown',
      http_status: Number.isInteger(result.status) && result.status >= 0 && result.status <= 599 ? result.status : 0,
      database_code: databaseCode
    }));
  } catch (_) {}
  fail('ADMIN_PASSKEY_STORE_UNAVAILABLE', 503);
}
async function durableEnrollmentRead(key, migrate = true) {
  if (!enrollmentKey(key)) fail('ADMIN_STORAGE_KEY_INVALID', 503);
  const result = await dbFetch('/rest/v1/' + ADMIN_PASSKEY_TABLE + '?select=' + ADMIN_PASSKEY_SELECT + '&security_key=eq.' + encodeURIComponent(key) + '&limit=2', { method: 'GET' }, 'security');
  // Never turn a missing table, failed query, or damaged row into "register a new passkey".
  assertPasskeyStoreResultV454(result, 'read');
  if (result.data.length) {
    const row = result.data[0];
    if (!row || row.security_key !== key || !row.record_json || row.revision !== row.record_json.revision) fail('ADMIN_ENROLLMENT_INVALID', 503);
    return { ok: true, found: true, record: validateDurableEnrollment(key, row.record_json) };
  }
  if (migrate) {
    // One-time, same-origin import; never overwrite a newer durable enrollment.
    // Expired/deleted legacy rows are NOT silently resurrected.
    const legacy = await securityRead(key);
    if (!legacy || legacy.ok !== true) fail('ADMIN_PASSKEY_MIGRATION_UNAVAILABLE', 503);
    if (legacy.found === true) {
      const record = validateDurableEnrollment(key, legacy.record);
      if (await durableEnrollmentClaim(key, record)) return { ok: true, found: true, record };
      return durableEnrollmentRead(key, false);
    }
  }
  return { ok: true, found: false };
}
async function durableEnrollmentClaim(key, value) {
  const record = validateDurableEnrollment(key, value);
  const result = await dbFetch('/rest/v1/' + ADMIN_PASSKEY_TABLE + '?on_conflict=security_key&select=security_key,revision', {
    method: 'POST', prefer: 'resolution=ignore-duplicates,return=representation',
    body: { security_key: key, revision: record.revision, record_json: record, updated_at: new Date().toISOString() }
  }, 'security');
  assertPasskeyStoreResultV454(result, 'claim');
  if (!result.data.length) return false;
  if (result.data[0].security_key !== key || result.data[0].revision !== record.revision) fail('ADMIN_PASSKEY_WRITE_UNVERIFIED', 503);
  return true;
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

const DIRAC_ADMIN_BLOCK_DIAGNOSTIC_V446 = 'dirac-admin-security-block-diagnostic-v446';
function adminBlockDiagnosticLogV446(event, detail) {
  try {
    console.info('[' + DIRAC_ADMIN_BLOCK_DIAGNOSTIC_V446 + '] ' + JSON.stringify({
      patch: DIRAC_ADMIN_BLOCK_DIAGNOSTIC_V446,
      event: String(event || 'unknown').slice(0, 80),
      ...(detail && typeof detail === 'object' && !Array.isArray(detail) ? detail : {})
    }));
  } catch (_) {}
}
const DIRAC_ADMIN_RETIRED_FALSE_BLOCK_V447 = Object.freeze({
  blockKeyHash: '890e88cc44d2d2cf7098d039',
  createdAt: 1790661016889,
  blockedUntil: 1790747416889
});
const DIRAC_ADMIN_RETIRED_FALSE_BLOCK_V448 = Object.freeze({
  blockKeyHash: '890e88cc44d2d2cf7098d039',
  createdAtMin: 1790688236000,
  createdAtMax: 1790688239300
});
function securityBlockKey(origin, device) { return SECURITY_BLOCK_PREFIX + digest(String(origin) + '\0' + String(device)); }
function validSecurityBlock(record, origin, device) {
  return !!(record && record.version === VERSION && record.schema === 'dirac.admin_security_block.v411' && record.reason === 'html_detected_attack'
    && record.originHash === digest(origin) && record.device === device && Number.isSafeInteger(record.createdAt) && Number.isSafeInteger(record.blockedUntil)
    && record.blockedUntil === record.createdAt + SECURITY_BLOCK_SECONDS * 1000 && record.blockedUntil > Date.now());
}
async function activeSecurityBlock(origin, device) {
  const keyV446 = securityBlockKey(origin, device);
  const result = await securityRead(keyV446);
  if (!result.ok) fail('ADMIN_SECURITY_STORE_UNAVAILABLE', 503);
  if (!result.found) return null;
  if (!validSecurityBlock(result.record, origin, device)) fail('ADMIN_SECURITY_STATE_INVALID', 503);
  const retiredV447 = DIRAC_ADMIN_RETIRED_FALSE_BLOCK_V447;
  const retiredV448 = DIRAC_ADMIN_RETIRED_FALSE_BLOCK_V448;
  const blockKeyHashV448 = digest(keyV446).slice(0, 24);
  const retiredFalseBlockV448 = blockKeyHashV448 === retiredV448.blockKeyHash
    && result.record.createdAt >= retiredV448.createdAtMin
    && result.record.createdAt <= retiredV448.createdAtMax
    && result.record.blockedUntil === result.record.createdAt + SECURITY_BLOCK_SECONDS * 1000;
  if ((blockKeyHashV448 === retiredV447.blockKeyHash
      && result.record.createdAt === retiredV447.createdAt
      && result.record.blockedUntil === retiredV447.blockedUntil) || retiredFalseBlockV448) {
    adminBlockDiagnosticLogV446('legacy_false_block_retire_attempt', {
      block_key_hash: retiredV447.blockKeyHash,
      created_at: result.record.createdAt,
      blocked_until: result.record.blockedUntil,
      reason: result.record.reason,
      schema: result.record.schema
    });
    const expiredAtV447 = new Date(Math.max(0, Date.now() - 1000)).toISOString();
    const retiredResultV447 = await dbFetch('/rest/v1/dirac_s2s_security?security_key=eq.' + encodeURIComponent(keyV446),
      { method: 'PATCH', body: { expires_at: expiredAtV447 } }, 'security');
    if (!retiredResultV447.ok) fail('ADMIN_SECURITY_STORE_UNAVAILABLE', 503);
    const retiredReadbackV447 = await securityRead(keyV446);
    if (!retiredReadbackV447.ok || retiredReadbackV447.found) fail('ADMIN_SECURITY_STORE_UNAVAILABLE', 503);
    adminBlockDiagnosticLogV446('legacy_false_block_retired', {
      block_key_hash: retiredV447.blockKeyHash,
      created_at: result.record.createdAt,
      reason: result.record.reason,
      readback_found: false
    });
    return null;
  }
  adminBlockDiagnosticLogV446('active_block', {
    block_key_hash: digest(keyV446).slice(0, 24),
    origin_hash: digest(origin).slice(0, 24),
    device_hash: digest(device).slice(0, 24),
    created_age_ms: Math.max(0, Date.now() - result.record.createdAt),
    remaining_ms: Math.max(0, result.record.blockedUntil - Date.now()),
    reason: result.record.reason,
    schema: result.record.schema
  });
  return result.record;
}
function validateSecurityReport(body) {
  if (!body || body.reason !== 'html_detected_attack' || body.page !== 'admin.html' || body.version !== 'dirac-html-shell-v1') fail('ADMIN_SECURITY_REPORT_INVALID', 400);
  const type = String(body.type || ''), event = String(body.event || ''), evidence = String(body.evidence || '');
  if (!['url_guard', 'input_guard'].includes(type) || !['forbidden_html_url_suffix', 'high_confidence_input_violation'].includes(event)) fail('ADMIN_SECURITY_REPORT_INVALID', 400);
  const match = /^family=([a-z0-9_-]{1,64});field=([a-z0-9_-]{1,64});source=html_boundary(?:;sample=([\s\S]{1,768}))?$/.exec(evidence);
  if (!match || (type === 'url_guard') !== (event === 'forbidden_html_url_suffix') || (type === 'url_guard') !== (match[1] === 'forbidden_html_suffix')) fail('ADMIN_SECURITY_REPORT_INVALID', 400);
  if (type === 'input_guard' && match[1] === 'frontend_threat' && match[2] === 'admin_failure') fail('SECURITY_REPORT_EVIDENCE_REJECTED', 403);
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
  adminBlockDiagnosticLogV446('security_report_committed', {
    block_claim_new: claimed === true,
    block_key_hash: digest(blockKey).slice(0, 24),
    report_key_hash: digest(reportKey).slice(0, 24),
    origin_hash: digest(origin).slice(0, 24),
    device_hash: digest(device).slice(0, 24),
    report_type: report.type,
    report_event: report.event,
    report_family: report.family,
    report_field: report.field,
    evidence_hash_prefix: String(report.evidenceHash || '').slice(0, 24),
    blocked_for_ms: blockedUntil - now
  });
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
  if (previous > 0 && current <= previous) fail('ADMIN_PASSKEY_COUNTER_REPLAY', 409);
  return { ok: true, signCount: current };
}

function approvalPayload(action, body) {
  const value = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  if (action === 'admin_local_authorize') {
    if (!['document_preview', 'document_pdf', 'document_png', 'document_print', 'theme_save'].includes(value.purpose) || typeof value.content_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.content_sha256)) fail('ADMIN_LOCAL_AUTHORIZATION_INVALID', 400);
    return { action, purpose: value.purpose, content_sha256: value.content_sha256 };
  }
  if (action === 'admin_shipment_update') return { action, review_ack: value.review_ack || '', review_reason: value.review_reason || '', kind: value.kind, order_id: value.order_id, expected_revision: value.expected_revision, tracking_number: value.tracking_number, courier: value.courier, status: value.status, location: value.location || '', origin: value.origin || '', destination: value.destination || '', estimated_delivery: value.estimated_delivery || '', description: value.description || '', ...(value.tracking_options === undefined ? {} : { tracking_options: shipmentOptionsV450(value.tracking_options) }) };
  if (action === 'admin_shipment_cancel') return { action, review_ack: value.review_ack || '', review_reason: value.review_reason || '', kind: value.kind, order_id: value.order_id, expected_revision: value.expected_revision, description: value.description || '' };
  if (action === 'admin_unban') return { action, block_id: value.block_id };
  if (action === 'admin_smtp_send') return { action, provider: value.provider, recipient_count: value.recipient_count, recipients_sha256: value.recipients_sha256, subject_sha256: value.subject_sha256, body_sha256: value.body_sha256, document_kind: value.document_kind, attachment_name: value.attachment_name || '', attachment_type: value.attachment_type || '', attachment_sha256: value.attachment_sha256 || '', legal_confirm: value.legal_confirm === true };
  fail('ADMIN_ACTION_APPROVAL_OPERATION_INVALID', 400);
}
function approvalPayloadHash(action, body) { return digest(stableJson(approvalPayload(action, body))); }
function mailEscape(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])); }
function mailOriginParts(origin) {
  const configured = String(process.env.DIRAC_BASE_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  const validDomain = value => /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(String(value || ''));
  if (configured && !validDomain(configured)) return { actionUrl: '', bannerUrl: '', supportEmail: '', careEmail: '', siteUrl: '' };
  let base = configured;
  if (!base) {
    let url; try { url = new URL(String(origin || '')); } catch (_) { return { actionUrl: '', bannerUrl: '', supportEmail: '', careEmail: '', siteUrl: '' }; }
    const host = String(url.hostname || '').toLowerCase(); base = host.startsWith('pt.') ? host.slice(3) : host;
    if (url.protocol !== 'https:' || !base || !validDomain(base)) return { actionUrl: '', bannerUrl: '', supportEmail: '', careEmail: '', siteUrl: '' };
  }
  return { actionUrl: 'https://pt.' + base + '/admin.html', bannerUrl: 'https://' + base + '/headerstp.webp', supportEmail: 'support@' + base, careEmail: 'care@' + base, siteUrl: 'https://' + base + '/' };
}

function adminSocialGridHtml() {
  return '<tr><td style="padding:18px 24px 8px"><div style="font-size:10px;line-height:1.4;font-weight:800;letter-spacing:.14em;color:#7dd3fc">IKUTI KANAL RESMI</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;margin-top:10px;border-collapse:collapse"><tr><td style="padding:0 8px 8px 0;font-size:12px;line-height:1.6"><a href="https://x.com/achzaenuddin?s=11" rel="noopener noreferrer" target="_blank" style="color:#d7e3f4;text-decoration:none">X</a></td><td style="padding:0 8px 8px 0;font-size:12px;line-height:1.6"><a href="https://www.facebook.com/share/1J3EEbguNX/?mibextid=wwXIfr" rel="noopener noreferrer" target="_blank" style="color:#d7e3f4;text-decoration:none">Facebook</a></td><td style="padding:0 0 8px;font-size:12px;line-height:1.6"><a href="https://www.instagram.com/achzaenuddin15?stkn=MW4zc3FldjAzb21wNg%3D%3D&utm_source=qr" rel="noopener noreferrer" target="_blank" style="color:#d7e3f4;text-decoration:none">Instagram</a></td></tr><tr><td style="padding:0 8px 0 0;font-size:12px;line-height:1.6"><a href="https://www.threads.com/@achzaenuddin15?igshid=NTc4MTIwNjQ2YQ==" rel="noopener noreferrer" target="_blank" style="color:#d7e3f4;text-decoration:none">Threads</a></td><td style="padding:0 8px 0 0;font-size:12px;line-height:1.6"><a href="https://www.linkedin.com/in/pt-dirac-inovasi-nusantara" rel="noopener noreferrer" target="_blank" style="color:#d7e3f4;text-decoration:none">LinkedIn</a></td><td style="padding:0;font-size:12px;line-height:1.6"><a href="https://www.tiktok.com/@achzaenuddin" rel="noopener noreferrer" target="_blank" style="color:#d7e3f4;text-decoration:none">TikTok</a></td></tr></table></td></tr>';
}
function adminExecutiveEscalationHtml(supportEmail) {
  return '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" data-dirac-executive-report="v380" style="width:100%;margin:18px 0 0;border-collapse:collapse"><tr><td align="center" style="padding:0 12px"><table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" bgcolor="#F7F9FC" style="width:100%;max-width:600px;border-collapse:separate;border-spacing:0;border:1px solid #CBD5E1;border-radius:16px;overflow:hidden;background-color:#F7F9FC"><tr><td style="padding:0"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td width="42%" bgcolor="#27B3CB" style="height:4px;line-height:4px;font-size:0;background-color:#27B3CB">&nbsp;</td><td width="34%" bgcolor="#2D6FAD" style="height:4px;line-height:4px;font-size:0;background-color:#2D6FAD">&nbsp;</td><td width="24%" bgcolor="#C69A32" style="height:4px;line-height:4px;font-size:0;background-color:#C69A32">&nbsp;</td></tr></table></td></tr><tr><td bgcolor="#F7F9FC" style="padding:18px 18px 17px;font-family:Arial,Helvetica,sans-serif;background-color:#F7F9FC;color:#172033"><div style="font-size:10px;line-height:1.4;font-weight:800;letter-spacing:.15em;color:#087A8F">JALUR PRIVAT PELANGGAN</div><div style="margin-top:5px;font-size:20px;line-height:1.28;font-weight:800;color:#0F172A">Lapor ke Direktur &amp; Founder</div><p style="margin:8px 0 14px;font-size:13px;line-height:1.55;color:#475569">Dugaan penyalahgunaan, penipuan, manipulasi, pemaksaan, atau pelanggaran oleh staf/mitra dapat dilaporkan langsung kepada Achmad Zaenuddin, Direktur &amp; Founder PT Dirac Inovasi Nusantara.</p><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td bgcolor="#0B6F88" style="padding:0;border-radius:10px;background-color:#0B6F88"><a href="mailto:' + supportEmail + '?subject=Laporan%20Pelanggan%20ke%20Direktur%20%26%20Founder&amp;body=Halo%20Direktur%20%26%20Founder%20PT%20Dirac%20Inovasi%20Nusantara%2C%0D%0A%0D%0ASaya%20ingin%20menyampaikan%20laporan%20pelanggan.%0D%0A%0D%0ANama%3A%20%0D%0AEmail%20akun%3A%20%0D%0ANomor%20pesanan%2Ftiket%20%28jika%20ada%29%3A%20%0D%0ATanggal%20%26%20waktu%20kejadian%3A%20%0D%0ARingkasan%3A%20%0D%0ABukti%20pendukung%20%28tanpa%20data%20rahasia%29%3A%20%0D%0A%0D%0ATerima%20kasih." style="display:block;padding:12px 14px;font-size:13px;line-height:1.35;font-weight:800;text-align:center;color:#FFFFFF;text-decoration:none"><font color="#FFFFFF" style="color:#FFFFFF">EMAIL&nbsp;&nbsp;•&nbsp;&nbsp;SIAPKAN LAPORAN</font></a></td></tr><tr><td style="height:9px;line-height:9px;font-size:0">&nbsp;</td></tr><tr><td bgcolor="#18794E" style="padding:0;border-radius:10px;background-color:#18794E"><a href="https://wa.me/62882009257589?text=Halo%20Direktur%20%26%20Founder%20PT%20Dirac%20Inovasi%20Nusantara%2C%0A%0ASaya%20ingin%20menyampaikan%20laporan%20pelanggan.%0A%0ANama%3A%20%0AEmail%20akun%3A%20%0ANomor%20pesanan%2Ftiket%20%28jika%20ada%29%3A%20%0ATanggal%20%26%20waktu%20kejadian%3A%20%0ARingkasan%3A%20%0ABukti%20pendukung%20%28tanpa%20data%20rahasia%29%3A%20%0A%0ATerima%20kasih." style="display:block;padding:12px 14px;font-size:13px;line-height:1.35;font-weight:800;text-align:center;color:#FFFFFF;text-decoration:none"><font color="#FFFFFF" style="color:#FFFFFF">WHATSAPP&nbsp;&nbsp;•&nbsp;&nbsp;+62 882-0092-57589</font></a></td></tr></table><p style="margin:12px 0 0;font-size:11px;line-height:1.5;color:#64748B">Template laporan sudah disiapkan. Lengkapi bagian yang kosong dan jangan sertakan password, OTP, PIN, CVV, passkey, cookie, token, atau secret.</p></td></tr></table></td></tr></table>';
}

function adminMailHtml(message) {
  const code = mailEscape(message.code), reference = mailEscape(message.reference), parts = mailOriginParts(message.origin), operation = 'Verifikasi masuk administrator';
  const title = 'Verifikasi Akses<br>Administrator';
  const summary = 'Kode ini digunakan sebagai faktor email pada proses masuk administrator. Gunakan hanya pada halaman administrasi resmi yang sedang Anda buka.';
  const destination = parts.actionUrl ? mailEscape(new URL(parts.actionUrl).hostname) : '', supportEmail = mailEscape(parts.supportEmail || ''), careEmail = mailEscape(parts.careEmail || ''), socialSupportRowHtml = adminSocialGridHtml(), executiveHtml = adminExecutiveEscalationHtml(supportEmail);
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
            <tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">EMAIL PERUSAHAAN</div><a href="mailto:${careEmail}" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;word-break:break-all;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">${careEmail}</a></div></div></td></tr>
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
function adminPasskeyRecoveryAlertHtml(message) {
  const parts = mailOriginParts(message.origin), reference = mailEscape(message.reference || ''), actionUrl = mailEscape(parts.actionUrl || '');
  return '<!doctype html><html lang="id"><head><meta charset="utf-8"></head><body style="margin:0;padding:24px;background:#0b1220;color:#eef4ff;font-family:Arial,Helvetica,sans-serif"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr><td align="center"><table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:600px;background:#121d2d;border:1px solid #33465f;border-radius:16px"><tr><td style="padding:24px"><div style="font-size:12px;font-weight:800;letter-spacing:.12em;color:#75d7ee">ALERT KEAMANAN ADMIN</div><h1 style="margin:10px 0 16px;font-size:24px;color:#ffffff">Pemulihan passkey dimulai</h1><p style="font-size:15px;line-height:1.7;color:#cbd6e5">Permintaan pemulihan passkey administrator telah melewati secret admin, verifikasi email, secret recovery server, dan kode Authenticator. Jika ini bukan Anda, segera kunci akses dan rotasi secret recovery server.</p><p style="font-size:13px;color:#9fb0c4">Referensi: '+reference+'</p>'+(actionUrl?'<p style="margin:20px 0 0"><a href="'+actionUrl+'" style="display:inline-block;padding:12px 16px;border-radius:10px;background:#2fc3e8;color:#07111d;font-weight:800;text-decoration:none">Buka administrasi</a></p>':'')+'</td></tr></table></td></tr></table></body></html>';
}
function adminPasskeyRecoveryAlertMime(config, message) {
  const boundary = 'dirac-admin-recovery-' + crypto.randomBytes(16).toString('hex');
  const subject = 'PT Dirac Inovasi Nusantara Security - Pemulihan passkey admin [' + message.reference + ']';
  const text = 'PT Dirac Inovasi Nusantara\n\nALERT KEAMANAN ADMIN\n\nPemulihan passkey administrator dimulai setelah verifikasi berlapis. Jika ini bukan Anda, segera kunci akses dan rotasi secret recovery server.\n\nReferensi: ' + message.reference;
  const html = adminPasskeyRecoveryAlertHtml(message), b64 = value => (Buffer.from(value, 'utf8').toString('base64').match(/.{1,76}/g) || ['']).join('\r\n');
  return ['From: PT Dirac Inovasi Nusantara <' + config.user + '>', 'To: ' + ADMIN_EMAIL, 'Subject: =?UTF-8?B?' + Buffer.from(subject).toString('base64') + '?=', 'Date: ' + new Date().toUTCString(), 'Auto-Submitted: auto-generated', 'MIME-Version: 1.0', 'Content-Type: multipart/alternative; boundary="' + boundary + '"', '', '--' + boundary, 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', b64(text), '--' + boundary, 'Content-Type: text/html; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', b64(html), '--' + boundary + '--', ''].join('\r\n');
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
  const purpose = 'Verifikasi masuk administrator';
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
    await smtpCommand(socket, reader, 'MAIL FROM:<' + config.user + '>', 250, config.timeout); await smtpCommand(socket, reader, 'RCPT TO:<' + ADMIN_EMAIL + '>', [250, 251], config.timeout); await smtpCommand(socket, reader, 'DATA', 354, config.timeout); const mime = message && message.kind === 'recovery' ? adminPasskeyRecoveryAlertMime(config, message) : mimeMessage(config, message); await smtpCommand(socket, reader, dotStuff(mime) + '\r\n.', 250, config.timeout);
    try { socket.write('QUIT\r\n'); } catch (_) {} return { ok: true };
  } catch (_) { return { ok: false }; }
  finally { if (auth) auth.fill(0); if (reader) reader.close(); try { if (socket) socket.destroy(); } catch (_) {} }
}

function adminSmtpDocumentKind(value) {
  const kind = String(value || '').trim().toLowerCase();
  if (!['offer', 'announcement', 'invoice', 'proforma', 'quotation', 'receipt', 'delivery', 'document'].includes(kind)) fail('ADMIN_SMTP_DOCUMENT_KIND_INVALID', 400);
  return kind;
}
function adminSmtpProvider(value) {
  const provider = String(value || '').trim().toLowerCase();
  if (!['auto', 'google', 'mailjet', 'brevo', 'resend'].includes(provider)) fail('ADMIN_SMTP_PROVIDER_INVALID', 400);
  return provider;
}
function customerMailProviderConfig(provider) {
  const timeout = 12000;
  if (provider === 'google') {
    const user = String(process.env.DIRAC_ADMIN_CUSTOMER_GOOGLE_SMTP_USER || '').trim().toLowerCase();
    const password = String(process.env.DIRAC_ADMIN_CUSTOMER_GOOGLE_SMTP_APP_PASSWORD || '').replace(/\s+/g, '');
    if (!isEmail(user) || !/^[A-Za-z0-9]{16,128}$/.test(password)) return null;
    return Object.freeze({ provider, transport: 'smtp', host: 'smtp.gmail.com', port: 465, user, password, from: user, timeout });
  }
  if (provider === 'mailjet') {
    const user = String(process.env.DIRAC_ADMIN_CUSTOMER_MAILJET_API_KEY || '').trim();
    const password = String(process.env.DIRAC_ADMIN_CUSTOMER_MAILJET_SECRET_KEY || '').trim();
    const from = String(process.env.DIRAC_ADMIN_CUSTOMER_MAILJET_FROM_EMAIL || '').trim().toLowerCase();
    if (!/^[A-Za-z0-9._~-]{16,256}$/.test(user) || !/^[A-Za-z0-9._~-]{16,256}$/.test(password) || !isEmail(from)) return null;
    return Object.freeze({ provider, transport: 'smtp', host: 'in-v3.mailjet.com', port: 465, user, password, from, timeout });
  }
  if (provider === 'brevo') {
    const apiKey = String(process.env.DIRAC_USER_SECURITY_BREVO_API_KEY || '').trim();
    const from = String(process.env.DIRAC_USER_SECURITY_BREVO_FROM_EMAIL || '').trim().toLowerCase();
    if (!/^[A-Za-z0-9._~+\-]{24,2048}$/.test(apiKey) || !isEmail(from)) return null;
    return Object.freeze({ provider, transport: 'api', apiKey, from, timeout });
  }
  if (provider === 'resend') {
    const apiKey = String(process.env.DIRAC_USER_SECURITY_RESEND_API_KEY || '').trim();
    const from = String(process.env.DIRAC_USER_SECURITY_RESEND_FROM_EMAIL || '').trim().toLowerCase();
    if (!/^re_[A-Za-z0-9_-]{16,252}$/.test(apiKey) || !isEmail(from)) return null;
    return Object.freeze({ provider, transport: 'api', apiKey, from, timeout });
  }
  return null;
}
function adminSmtpHash(value) { return digest(String(value == null ? '' : value)); }
function adminSmtpRecipients(value, count, expectedHash, kind) {
  const text = String(value || '');
  if (!text || text.length > ADMIN_SMTP_RECIPIENT_MAX * 255 || /[\r\u0000-\u001f\u007f]/.test(text.replace(/\n/g, ''))) fail('ADMIN_SMTP_RECIPIENTS_INVALID', 400);
  const rows = text.split('\n');
  if (!Number.isInteger(count) || count !== rows.length || count < 1 || count > ADMIN_SMTP_RECIPIENT_MAX || rows.some(item => item !== item.trim().toLowerCase() || !isEmail(item)) || new Set(rows).size !== rows.length || !/^[a-f0-9]{64}$/.test(String(expectedHash || '')) || !safeEqual(adminSmtpHash(text), expectedHash)) fail('ADMIN_SMTP_RECIPIENTS_INVALID', 400);
  if (['invoice', 'proforma', 'receipt', 'delivery'].includes(kind) && count !== 1) fail('ADMIN_SMTP_PRIVATE_DOCUMENT_RECIPIENT_INVALID', 400);
  return rows;
}
function adminSmtpSubject(value, expectedHash) {
  const subject = String(value || '').trim();
  if (!subject || subject.length > 180 || /[\r\n\u0000-\u001f\u007f]/.test(subject) || !/^[a-f0-9]{64}$/.test(String(expectedHash || '')) || !safeEqual(adminSmtpHash(subject), expectedHash)) fail('ADMIN_SMTP_SUBJECT_INVALID', 400);
  return subject;
}
function adminSmtpBody(value, expectedHash) {
  const body = String(value || '').replace(/\r\n?/g, '\n').trim();
  if (!body || body.length > 12000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(body) || !/^[a-f0-9]{64}$/.test(String(expectedHash || '')) || !safeEqual(adminSmtpHash(body), expectedHash)) fail('ADMIN_SMTP_BODY_INVALID', 400);
  return body;
}
function adminSmtpAttachment(body) {
  const name = String(body.attachment_name || '').trim(), type = String(body.attachment_type || '').trim().toLowerCase(), encoded = String(body.attachment_base64 || ''), expected = String(body.attachment_sha256 || '');
  if (!name && !type && !encoded && !expected) return null;
  if (!name || name.length > 180 || /[\u0000-\u001f\u007f\/\\]/.test(name) || !type || type.length > 120 || !/^[a-z0-9][a-z0-9.+-]{0,63}\/[a-z0-9][a-z0-9.+-]{0,63}$/.test(type) || !encoded || encoded.length > Math.ceil(ADMIN_SMTP_ATTACHMENT_MAX_BYTES / 3) * 4 + 8 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || !/^[a-f0-9]{64}$/.test(expected)) fail('ADMIN_SMTP_ATTACHMENT_INVALID', 400);
  let bytes; try { bytes = Buffer.from(encoded, 'base64'); } catch (_) { fail('ADMIN_SMTP_ATTACHMENT_INVALID', 400); }
  if (!bytes.length || bytes.length > ADMIN_SMTP_ATTACHMENT_MAX_BYTES || !safeEqual(bytes.toString('base64'), encoded) || !safeEqual(crypto.createHash('sha256').update(bytes).digest('hex'), expected)) { bytes.fill(0); fail('ADMIN_SMTP_ATTACHMENT_INVALID', 400); }
  return { name, type, bytes, sha256: expected };
}
function customerMailKindLabel(kind) {
  if (kind === 'offer') return 'Penawaran umum';
  if (kind === 'announcement') return 'Informasi perusahaan';
  if (kind === 'quotation') return 'Penawaran harga';
  if (kind === 'invoice') return 'Invoice pelanggan';
  if (kind === 'proforma') return 'Proforma invoice';
  if (kind === 'receipt') return 'Kuitansi';
  if (kind === 'delivery') return 'Surat jalan';
  return 'Dokumen perusahaan';
}
function customerMailText(message) {
  if (message.shipmentNotice === true) return String(message.body || '');
  const parts = mailOriginParts(message.origin), rows = [String(message.body || ''), '', '---', 'PT Dirac Inovasi Nusantara', customerMailKindLabel(message.kind)];
  if (parts.siteUrl) rows.push('Website: ' + parts.siteUrl);
  if (parts.supportEmail) rows.push('Email: ' + parts.supportEmail);
  rows.push('WhatsApp: +62 878-9252-3968');
  if (message.attachment) rows.push('Lampiran: ' + message.attachment.name);
  rows.push('', 'Pesan ini dikirim melalui kanal resmi perusahaan. Balas email ini bila Anda memerlukan klarifikasi atau ingin menghentikan komunikasi penawaran serupa.');
  return rows.join('\n');
}
function customerMailHtml(message) {
  if (message.shipmentNotice === true) return '<!doctype html><html lang="id"><head><meta charset="utf-8"></head><body style="font-family:Arial,Helvetica,sans-serif;line-height:1.65;color:#182230;background:#f7f9fc;padding:24px"><main style="max-width:640px;margin:auto;background:#fff;padding:28px;border:1px solid #dce3eb;border-radius:12px"><h1 style="font-size:22px">' + mailEscape(message.subject) + '</h1><p>' + mailEscape(message.body).replace(/\n/g, '<br>') + '</p><p><a href="' + mailEscape(shipmentCustomerOriginV450(message.origin) + '/cekresi.html') + '">Lihat pengiriman melalui akun Anda</a></p></main></body></html>';
  const parts = mailOriginParts(message.origin), subject = mailEscape(message.subject), body = mailEscape(message.body).replace(/\n/g, '<br>'), kind = mailEscape(customerMailKindLabel(message.kind));
  const siteUrl = mailEscape(parts.siteUrl || ''), supportEmail = mailEscape(parts.supportEmail || ''), attachment = message.attachment ? mailEscape(message.attachment.name) : '';
  const siteBlock = siteUrl ? '<tr><td style="padding:0 28px 24px"><a href="' + siteUrl + '" style="display:inline-block;padding:12px 18px;border-radius:9px;background:#7dd3fc;color:#082032;text-decoration:none;font-size:13px;font-weight:800">Buka situs resmi</a></td></tr>' : '';
  const supportBlock = supportEmail ? '<a href="mailto:' + supportEmail + '" style="color:#9bdcff;text-decoration:none">' + supportEmail + '</a>' : 'Kanal kontak resmi perusahaan';
  const attachmentBlock = attachment ? '<tr><td style="padding:0 28px 22px"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#162235" style="width:100%;border-collapse:separate;border-spacing:0;background:#162235;border:1px solid #2a3b54;border-radius:10px"><tr><td style="padding:14px 16px;font-size:12px;line-height:1.6;color:#b9c8dc"><span style="display:block;font-size:10px;font-weight:800;letter-spacing:.12em;color:#7dd3fc">LAMPIRAN</span><strong style="display:block;margin-top:4px;color:#f8fafc;font-size:13px">' + attachment + '</strong></td></tr></table></td></tr>' : '';
  return '<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark"></head><body bgcolor="#0B1220" style="margin:0;padding:0;background:#0b1220;color:#f8fafc;font-family:Arial,Helvetica,sans-serif"><div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">' + subject + ' · PT Dirac Inovasi Nusantara</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#0B1220" style="width:100%;border-collapse:collapse;background:#0b1220"><tr><td align="center" style="padding:26px 12px"><table role="presentation" width="640" cellspacing="0" cellpadding="0" border="0" bgcolor="#111827" style="width:100%;max-width:640px;border-collapse:separate;border-spacing:0;background:#111827;border:1px solid #273449;border-radius:16px;overflow:hidden"><tr><td style="padding:0"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse"><tr><td width="46%" bgcolor="#22B8CF" style="height:4px;line-height:4px;font-size:0;background:#22b8cf">&nbsp;</td><td width="34%" bgcolor="#4E8FD1" style="height:4px;line-height:4px;font-size:0;background:#4e8fd1">&nbsp;</td><td width="20%" bgcolor="#D2A640" style="height:4px;line-height:4px;font-size:0;background:#d2a640">&nbsp;</td></tr></table></td></tr><tr><td bgcolor="#111827" style="padding:28px 28px 24px;background:#111827;color:#f8fafc"><div style="font-size:10px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#7dd3fc">KOMUNIKASI RESMI</div><div style="margin-top:8px;font-size:14px;line-height:1.4;font-weight:800;letter-spacing:.025em;color:#f8fafc">PT DIRAC INOVASI NUSANTARA</div><div style="margin-top:18px"><span style="display:inline-block;padding:5px 9px;border:1px solid #33465f;border-radius:999px;background:#162235;color:#b9c8dc;font-size:10px;line-height:1.3;font-weight:700">' + kind + '</span></div><h1 style="margin:10px 0 0;font-size:25px;line-height:1.28;font-weight:800;color:#ffffff">' + subject + '</h1></td></tr><tr><td bgcolor="#111827" style="padding:4px 28px 24px;background:#111827"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#151F2E" style="width:100%;border-collapse:separate;border-spacing:0;background:#151f2e;border:1px solid #273449;border-radius:12px"><tr><td style="padding:22px 20px;font-size:15px;line-height:1.78;color:#dbe7f5">' + body + '</td></tr></table></td></tr>' + attachmentBlock + siteBlock + '<tr><td bgcolor="#0F172A" style="padding:20px 28px;background:#0f172a;border-top:1px solid #273449"><div style="font-size:10px;line-height:1.4;font-weight:800;letter-spacing:.14em;color:#7dd3fc">KONTAK RESMI</div><div style="margin-top:9px;font-size:12px;line-height:1.8;color:#aebdd1">Website: ' + (siteUrl ? '<a href="' + siteUrl + '" style="color:#9bdcff;text-decoration:none">' + siteUrl + '</a>' : 'situs resmi perusahaan') + '<br>Email: ' + supportBlock + '<br>WhatsApp: <a href="https://wa.me/6287892523968" style="color:#9bdcff;text-decoration:none">+62 878-9252-3968</a></div></td></tr><tr><td bgcolor="#0F172A" style="padding:0;background:#0f172a"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse">' + adminSocialGridHtml() + '</table></td></tr><tr><td bgcolor="#0F172A" style="padding:16px 28px 24px;background:#0f172a;color:#7f8da3;font-size:10px;line-height:1.7;border-top:1px solid #1e2a3a">Pesan ini dikirim melalui kanal resmi PT Dirac Inovasi Nusantara. Balas email ini bila Anda memerlukan klarifikasi atau ingin menghentikan komunikasi penawaran serupa.<br><span style="color:#64748b">&copy; ' + String(new Date().getUTCFullYear()) + ' PT Dirac Inovasi Nusantara.</span></td></tr></table></td></tr></table></body></html>';
}
function customerMailMime(config, message) {
  const mixed = 'dirac-customer-mixed-' + crypto.randomBytes(16).toString('hex'), alternative = 'dirac-customer-alt-' + crypto.randomBytes(16).toString('hex');
  const b64Text = value => (Buffer.from(String(value), 'utf8').toString('base64').match(/.{1,76}/g) || ['']).join('\r\n');
  const b64Buffer = value => (value.toString('base64').match(/.{1,76}/g) || ['']).join('\r\n');
  const toHeader = message.recipients.length === 1 ? message.recipients[0] : 'undisclosed-recipients:;';
  const lines = ['From: PT Dirac Inovasi Nusantara <' + config.from + '>', 'To: ' + toHeader, 'Reply-To: ' + config.from, 'Subject: =?UTF-8?B?' + Buffer.from(message.subject, 'utf8').toString('base64') + '?=', 'Date: ' + new Date().toUTCString(), 'MIME-Version: 1.0', 'Auto-Submitted: no', 'Content-Type: multipart/mixed; boundary="' + mixed + '"', '', '--' + mixed, 'Content-Type: multipart/alternative; boundary="' + alternative + '"', '', '--' + alternative, 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', b64Text(customerMailText(message)), '--' + alternative, 'Content-Type: text/html; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', b64Text(customerMailHtml(message)), '--' + alternative + '--'];
  if (message.attachment) {
    const fallback = message.attachment.name.replace(/[^A-Za-z0-9._ -]/g, '_').slice(0, 120) || 'document';
    lines.push('--' + mixed, 'Content-Type: ' + message.attachment.type, 'Content-Transfer-Encoding: base64', 'Content-Disposition: attachment; filename="' + fallback.replace(/["\\]/g, '_') + '"; filename*=UTF-8\'\'' + encodeURIComponent(message.attachment.name), '', b64Buffer(message.attachment.bytes));
  }
  lines.push('--' + mixed + '--', '');
  return lines.join('\r\n');
}
async function sendCustomerProviderHttp(config, message) {
  const multiple = message.recipients.length > 1, html = customerMailHtml(message), text = customerMailText(message), encodedAttachment = message.attachment ? message.attachment.bytes.toString('base64') : '';
  let target = '', headers = null, payload = null;
  if (config.provider === 'brevo') {
    target = 'https://api.brevo.com/v3/smtp/email';
    payload = { sender: { name: 'PT Dirac Inovasi Nusantara', email: config.from }, to: multiple ? [{ email: config.from, name: 'PT Dirac Inovasi Nusantara' }] : [{ email: message.recipients[0] }], subject: message.subject, textContent: text, htmlContent: html, replyTo: { name: 'PT Dirac Inovasi Nusantara', email: config.from } };
    if (multiple) payload.bcc = message.recipients.map(email => ({ email }));
    if (message.attachment) payload.attachment = [{ name: message.attachment.name, content: encodedAttachment }];
    headers = { 'api-key': config.apiKey, 'Content-Type': 'application/json', Accept: 'application/json' };
  } else if (config.provider === 'resend') {
    target = 'https://api.resend.com/emails';
    payload = { from: 'PT Dirac Inovasi Nusantara <' + config.from + '>', to: multiple ? [config.from] : [message.recipients[0]], subject: message.subject, text, html, reply_to: config.from };
    if (multiple) payload.bcc = message.recipients;
    if (message.attachment) payload.attachments = [{ filename: message.attachment.name, content: encodedAttachment }];
    headers = { Authorization: 'Bearer ' + config.apiKey, 'Content-Type': 'application/json', Accept: 'application/json' };
  } else return { ok: false, accepted: 0, provider: config.provider, status: 0 };
  const serialized = JSON.stringify(payload);
  if (Buffer.byteLength(serialized, 'utf8') > ADMIN_SMTP_BODY_MAX_BYTES) return { ok: false, accepted: 0, provider: config.provider, status: 0 };
  const controller = typeof AbortController === 'function' ? new AbortController() : null, timer = controller ? setTimeout(() => controller.abort(), config.timeout) : null;
  let response = null;
  try {
    response = await ADMIN_STANDALONE_FETCH(target, { method: 'POST', headers, body: serialized, redirect: 'error', signal: controller ? controller.signal : undefined });
    const accepted = response && [200, 201, 202].includes(Number(response.status)) ? message.recipients.length : 0;
    const status = Number(response && response.status || 0);
    // A lost response, 408/409, or 5xx can follow acceptance. Never resend that blindly.
    return { ok: accepted === message.recipients.length, accepted, provider: config.provider, status, safeToFallback: accepted === 0 && [400, 401, 402, 403, 404, 405, 406, 413, 415, 422, 429].includes(status) };
  } catch (_) { return { ok: false, accepted: 0, provider: config.provider, status: 0 }; }
  finally {
    if (timer) clearTimeout(timer);
    if (response && response.body && typeof response.body.cancel === 'function' && response.body.locked !== true) { try { await Promise.resolve(response.body.cancel()).catch(() => false); } catch (_) {} }
  }
}
async function sendCustomerMailProviderV451(message) {
  const configured = customerMailProviderConfig(message.provider); if (!configured) return { ok: false, accepted: 0, provider: message.provider, configurationUnavailable: true, safeToFallback: true };
  const config = message.mailFailoverV451 === true ? { ...configured, timeout: 8000 } : configured;
  if (config.transport === 'api') return sendCustomerProviderHttp(config, message);
  let socket = null, reader = null, auth = null, shipmentDeadline = null, bodySubmitted = false;
  try {
    socket = tls.connect({ host: config.host, port: config.port, servername: config.host, rejectUnauthorized: true });
    if (message.shipmentNotice === true || message.mailFailoverV451 === true) shipmentDeadline = setTimeout(() => socket.destroy(new Error('SMTP_TIMEOUT')), message.mailFailoverV451 === true ? 12000 : 20000);
    await new Promise((resolve, reject) => { const timer = setTimeout(() => { socket.destroy(); reject(Object.assign(new Error('SMTP_TIMEOUT'), { code: 'SMTP_TIMEOUT' })); }, config.timeout); socket.once('secureConnect', () => { clearTimeout(timer); resolve(); }); socket.once('error', error => { clearTimeout(timer); reject(error); }); });
    reader = smtpReader(socket); await smtpCommand(socket, reader, null, 220, config.timeout);
    const ehlo = message && message.origin ? new URL(message.origin).hostname : 'localhost'; await smtpCommand(socket, reader, 'EHLO ' + ehlo, 250, config.timeout);
    auth = Buffer.from('\0' + config.user + '\0' + config.password, 'utf8'); await smtpCommand(socket, reader, 'AUTH PLAIN ' + auth.toString('base64'), 235, config.timeout);
    await smtpCommand(socket, reader, 'MAIL FROM:<' + config.from + '>', 250, config.timeout);
    const rcpt = async index => { if (index >= message.recipients.length) return; await smtpCommand(socket, reader, 'RCPT TO:<' + message.recipients[index] + '>', [250, 251], config.timeout); return rcpt(index + 1); };
    await rcpt(0); await smtpCommand(socket, reader, 'DATA', 354, config.timeout);
    const data = dotStuff(customerMailMime(config, message)) + '\r\n.'; bodySubmitted = true;
    await smtpCommand(socket, reader, data, 250, config.timeout);
    try { socket.write('QUIT\r\n'); } catch (_) {} return { ok: true, accepted: message.recipients.length, provider: config.provider, status: 250 };
  } catch (error) {
    const code = Number(error && error.smtpCode || 0), rejected = error && error.code === 'SMTP_REJECTED' && Number.isInteger(code) && code >= 400 && code < 600;
    return { ok: false, accepted: 0, provider: config.provider, status: code, safeToFallback: !bodySubmitted || rejected === true };
  }
  finally { if (shipmentDeadline) clearTimeout(shipmentDeadline); if (auth) auth.fill(0); if (reader) reader.close(); try { if (socket) socket.destroy(); } catch (_) {} }
}
// v451: four forward-only attempts. No retry, recursion, polling, or new credentials.
function customerMailConfiguredV451(provider) {
  return provider === 'auto'
    ? !!(customerMailProviderConfig('mailjet') || customerMailProviderConfig('brevo') || customerMailProviderConfig('resend') || customerMailProviderConfig('google'))
    : !!customerMailProviderConfig(provider);
}
function customerMailAcceptedV451(result, requested, count) {
  return !!(result && result.ok === true && result.accepted === count && (requested === 'auto'
    ? ['mailjet', 'brevo', 'resend', 'google'].includes(result.provider)
    : result.provider === requested));
}
async function sendCustomerMail(message, assertContext) {
  if (typeof assertContext === 'function') assertContext();
  if (message.provider !== 'auto') return sendCustomerMailProviderV451(message);
  let configured = false;
  const attempt = async provider => {
    if (typeof assertContext === 'function') assertContext();
    const result = await sendCustomerMailProviderV451({ ...message, provider, mailFailoverV451: true });
    if (typeof assertContext === 'function') assertContext();
    if (result && result.configurationUnavailable !== true) configured = true;
    if (customerMailAcceptedV451(result, provider, message.recipients.length)) return { ...result, requested_provider: 'auto' };
    if (result && result.ok === false && result.accepted === 0 && result.safeToFallback === true) return null;
    return { ok: false, accepted: 0, provider, requested_provider: 'auto', status: Number(result && result.status || 0), safeToFallback: false };
  };
  const mailjet = await attempt('mailjet'); if (mailjet) return mailjet;
  const brevo = await attempt('brevo'); if (brevo) return brevo;
  const resend = await attempt('resend'); if (resend) return resend;
  const google = await attempt('google'); if (google) return google;
  return { ok: false, accepted: 0, provider: 'auto', configurationUnavailable: !configured, safeToFallback: false };
}
async function businessSmtpSend(body, origin, assertContext) {
  if (!body || body.legal_confirm !== true) fail('ADMIN_SMTP_LEGAL_CONFIRMATION_REQUIRED', 400);
  const provider = adminSmtpProvider(body.provider), kind = adminSmtpDocumentKind(body.document_kind), recipients = adminSmtpRecipients(body.recipients, body.recipient_count, body.recipients_sha256, kind), subject = adminSmtpSubject(body.subject, body.subject_sha256), content = adminSmtpBody(body.body_text, body.body_sha256), attachment = adminSmtpAttachment(body);
  try { const result = await sendCustomerMail({ origin, provider, recipients, subject, body: content, kind, attachment }, assertContext); if (result && result.configurationUnavailable === true) fail('ADMIN_SMTP_CONFIGURATION_UNAVAILABLE', 503); if (!customerMailAcceptedV451(result, provider, recipients.length)) fail('ADMIN_SMTP_DELIVERY_UNCONFIRMED', 503); return { ok: true, accepted: result.accepted, provider: result.provider, requested_provider: provider, document_kind: kind, attachment: !!attachment }; }
  finally { if (attachment && attachment.bytes) attachment.bytes.fill(0); }
}

function checkOperations(ops) {
  if (!ops || !Object.isFrozen(ops) || ops.version !== VERSION || typeof ops.assertFullGuard !== 'function') fail('ADMIN_FULL_GUARD_REQUIRED', 503);
  ops.assertFullGuard();
  const identity = ops.identity;
  if (!identity || !Object.isFrozen(identity) || identity.email !== ADMIN_EMAIL || identity.active !== true || identity.role !== 'owner' || identity.userId !== ADMIN_USER_ID || !/^[a-f0-9]{64}$/.test(String(identity.binding || ''))) fail('ADMIN_FIXED_OWNER_REQUIRED', 403);
  let origin; try { origin = new URL(identity.origin); } catch (_) { fail('ADMIN_ORIGIN_INVALID', 403); }
  if (origin.origin !== identity.origin || origin.username || origin.password || (origin.protocol !== 'https:' && !loopbackHost(origin.hostname))) fail('ADMIN_ORIGIN_INVALID', 403);
  if (!ACTIONS.includes(ops.action) || !CONTRACTS[ops.action].methods.includes(ops.method)) fail('ADMIN_ACTION_INVALID', 400);
  if (['read', 'claim', 'replace', 'takeRate', 'deriveKey', 'mail', 'recoveryAlert', 'verifyRegistration', 'verifyAssertion', 'readSession', 'setSession', 'clearSession', 'verifySecret', 'publishPassword', 'securityReport', 'business'].some(name => typeof ops[name] !== 'function')) fail('ADMIN_OPERATION_UNAVAILABLE', 503);
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
async function adminPasskeyRecoveryTicket(ops, scope, token) {
  try { return await ticket(ops, scope, token, 'passkey-start'); }
  catch (error) { if (!error || error.code !== 'ADMIN_TICKET_EXPIRED') throw error; return ticket(ops, scope, token, 'passkey'); }
}
async function adminVerifyRecoveryTotp(ops, scope, enrolled, code) {
  if (!enrolled || enrolled.enrollmentState !== 'active' || typeof code !== 'string' || !/^[0-9]{6}$/.test(code)) fail('ADMIN_TOTP_INVALID', 401);
  const secret = open(ops, enrolled.totp, configKey(scope)); let accepted = null;
  try {
    const current = Math.floor(Date.now() / 30000);
    if (safeEqual(totp(secret, current), code)) accepted = current;
    else if (safeEqual(totp(secret, current - 1), code)) accepted = current - 1;
    else if (safeEqual(totp(secret, current + 1), code)) accepted = current + 1;
  } finally { secret.fill(0); }
  if (accepted === null) fail('ADMIN_TOTP_INVALID', 401);
  if (await ops.claim(PREFIX + 'totp-used:' + digest(scope.owner + ':' + scope.origin + ':' + enrolled.totp + ':' + accepted), { version: VERSION }, 120) !== true) fail('ADMIN_TOTP_ALREADY_USED', 409);
}
async function execute(ops) {
  const scope = checkOperations(ops), body = ops.body || {}, action = ops.action;
  if (ops.method === 'HEAD') return { ok: true };
  if (action === 'admin_entry') {
    const configured = adminSecretState().configured;
    return { ok: true, email: ADMIN_EMAIL, credentials_required: true, credentials_configured: configured, passkey_recovery_configured: adminPasskeyRecoverySecretState().configured, factor_count: 3, email_code_min: EMAIL_CODE_MIN, email_code_max: EMAIL_CODE_MAX, email_code_seconds: EMAIL_CODE_SECONDS, totp_period: 30 };
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
    return { ok: true, email: ADMIN_EMAIL, enrolled: !!enrolled, enrollment_state: enrolled ? enrolled.enrollmentState : 'none', passkey_storage: ADMIN_PASSKEY_TABLE, authenticated: !!active, passkey_recovery_configured: adminPasskeyRecoverySecretState().configured, factor_count: 3, email_code_min: EMAIL_CODE_MIN, email_code_max: EMAIL_CODE_MAX, email_code_seconds: EMAIL_CODE_SECONDS, totp_period: 30, expires_at: null, persistent_session: !!active, action_email_required: false, action_passkey_required: true };
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
  if (action === 'admin_action_passkey_start') {
    await session(ops, scope); const operation = String(body.operation || ''), payload = body.payload;
    if (!Object.prototype.hasOwnProperty.call(ADMIN_APPROVAL_MUTATIONS, operation)) fail('ADMIN_ACTION_APPROVAL_OPERATION_INVALID', 400);
    const enrolled = await config(ops, scope);
    if (!enrolled || enrolled.enrollmentState !== 'active' || !enrolled.passkey || !exactToken(enrolled.revision) || !exactToken(enrolled.userHandle) || typeof enrolled.passkey.credentialId !== 'string' || !/^[A-Za-z0-9_-]{22,1364}$/.test(enrolled.passkey.credentialId)) fail('ADMIN_PASSKEY_STATE_INVALID', 403);
    const payloadHash = approvalPayloadHash(operation, payload); await throttle(ops, scope, 'action-passkey-start-minute', 5, 60); await throttle(ops, scope, 'action-passkey-start-hour', 30, 3600);
    const challenge = randomToken(), token = await issue(ops, scope, 'action-passkey', { challenge, mode: 'authentication', operation, payloadHash, revision: enrolled.revision, credentialId: enrolled.passkey.credentialId, userHandle: enrolled.userHandle }, EMAIL_CODE_SECONDS);
    return { ok: true, ticket: token, stage: 'action-passkey', operation, mode: 'authentication', publicKey: { challenge, rpId: scope.rpId, userVerification: 'required', timeout: 60000, allowCredentials: [{ id: enrolled.passkey.credentialId, type: 'public-key' }] }, expires_in: EMAIL_CODE_SECONDS, one_time: true };
  }
  if (action === 'admin_action_passkey_verify') {
    await session(ops, scope); const entry = await ticket(ops, scope, body.ticket, 'action-passkey'); await throttle(ops, scope, 'action-passkey-verify:' + digest(body.ticket), 5, FACTOR_SECONDS);
    const proof = entry.value, enrolled = await config(ops, scope), credential = body.credential, clientData = validateClientData(body.credential, entry.value, scope);
    if (!enrolled || enrolled.enrollmentState !== 'active' || proof.mode !== 'authentication' || proof.revision !== enrolled.revision || proof.credentialId !== enrolled.passkey.credentialId || proof.userHandle !== enrolled.userHandle || credential.id !== enrolled.passkey.credentialId) fail('ADMIN_PASSKEY_STATE_CHANGED', 409);
    const handle = credential.response && credential.response.userHandle;
    if (handle !== null && handle !== undefined && handle !== '' && handle !== enrolled.userHandle) fail('ADMIN_PASSKEY_USER_MISMATCH', 403);
    const verified = await ops.verifyAssertion({ credential, clientData, rpId: scope.rpId, passkey: enrolled.passkey });
    if (!verified || verified.ok !== true) fail('ADMIN_PASSKEY_INVALID', 403);
    const next = { ...enrolled, passkey: { ...enrolled.passkey, signCount: verified.signCount }, revision: randomToken() };
    if (await ops.replace(configKey(scope), enrolled.revision, next, ENROLLMENT_SECONDS) !== true) fail('ADMIN_PASSKEY_STATE_CHANGED', 409);
    await consume(ops, entry); const approval = await issue(ops, scope, 'action-approval', { operation: proof.operation, payloadHash: proof.payloadHash }, EMAIL_CODE_SECONDS);
    return { ok: true, approval, operation: proof.operation, expires_in: EMAIL_CODE_SECONDS, one_time: true };
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
  if (action === 'admin_passkey_recovery_start') {
    const recoveryState = adminPasskeyRecoverySecretState(); if (!recoveryState.configured) fail('ADMIN_PASSKEY_RECOVERY_NOT_CONFIGURED', 503);
    const entry = await adminPasskeyRecoveryTicket(ops, scope, body.ticket), enrolled = await config(ops, scope);
    await throttle(ops, scope, 'passkey-recovery-hour', 2, 3600);
    if (!enrolled || enrolled.enrollmentState !== 'active' || !verifyAdminPasskeyRecoverySecret(body.recovery_secret)) fail('ADMIN_PASSKEY_RECOVERY_INVALID', 403);
    await adminVerifyRecoveryTotp(ops, scope, enrolled, body.totp_code);
    await consume(ops, entry);
    const reference = crypto.randomBytes(12).toString('hex'), delivered = await ops.recoveryAlert({ to: ADMIN_EMAIL, kind: 'recovery', event: 'started', reference, origin: scope.origin });
    if (!delivered || delivered.ok !== true) fail('ADMIN_EMAIL_DELIVERY_UNCONFIRMED', 503);
    const challenge = randomToken(), token = await issue(ops, scope, 'passkey-recovery', { challenge, mode: 'registration', userHandle: enrolled.userHandle, revision: enrolled.revision, reference }, FACTOR_SECONDS);
    return { ok: true, ticket: token, stage: 'passkey-recovery', mode: 'registration', publicKey: { challenge, rp: { id: scope.rpId, name: 'PT DIRAC INOVASI NUSANTARA' }, user: { id: enrolled.userHandle, name: ADMIN_EMAIL, displayName: 'Administrator DIRAC' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' }, timeout: 60000, attestation: 'none' }, alert_reference: reference };
  }
  if (action === 'admin_passkey_recovery_verify') {
    const entry = await ticket(ops, scope, body.ticket, 'passkey-recovery'); await throttle(ops, scope, 'passkey-recovery-verify:' + digest(body.ticket), 5, FACTOR_SECONDS);
    const proof = entry.value, enrolled = await config(ops, scope); if (!enrolled || enrolled.enrollmentState !== 'active' || enrolled.revision !== proof.revision || enrolled.userHandle !== proof.userHandle) fail('ADMIN_ENROLLMENT_STATE_CHANGED', 409);
    const credential = body.credential, clientData = validateClientData(credential, proof, scope), verified = await ops.verifyRegistration({ credential, clientData, rpId: scope.rpId });
    if (!verified || verified.ok !== true || verified.credentialId !== credential.id || !verified.publicKeyJwk) fail('ADMIN_PASSKEY_INVALID', 403);
    const next = { ...enrolled, passkey: { credentialId: verified.credentialId, publicKeyJwk: verified.publicKeyJwk, signCount: verified.signCount, backupEligible: verified.backupEligible }, revision: randomToken(), recoveredAt: Date.now() };
    if (await ops.replace(configKey(scope), enrolled.revision, next, ENROLLMENT_SECONDS) !== true) fail('ADMIN_PASSKEY_STATE_CHANGED', 409);
    await consume(ops, entry); return { ok: true, stage: 'recovered', recovered: true, relogin_required: true, alert_reference: proof.reference || '' };
  }
  if (action === 'admin_totp_verify') {
    const entry = await ticket(ops, scope, body.ticket, 'totp'); await throttle(ops, scope, 'totp-verify', 5, FACTOR_SECONDS);
    if (typeof body.code !== 'string' || !/^[0-9]{6}$/.test(body.code)) fail('ADMIN_TOTP_INVALID', 401); const proof = entry.value, enrolled = await config(ops, scope);
    if (!enrolled || enrolled.revision !== proof.revision || enrolled.totp !== proof.totp || (proof.enroll ? enrolled.enrollmentState !== 'pending_totp' : enrolled.enrollmentState !== 'active')) fail('ADMIN_ENROLLMENT_STATE_CHANGED', 409);
    const secret = open(ops, proof.totp, configKey(scope)); let accepted = null;
    try { const current = Math.floor(Date.now() / 30000), match = [current, current - 1, current + 1].find(counter => safeEqual(totp(secret, counter), body.code)); accepted = Number.isSafeInteger(match) ? match : null; } finally { secret.fill(0); }
    if (accepted === null) fail('ADMIN_TOTP_INVALID', 401); if (await ops.claim(PREFIX + 'totp-used:' + digest(scope.owner + ':' + scope.origin + ':' + proof.totp + ':' + accepted), { version: VERSION }, 120) !== true) fail('ADMIN_TOTP_ALREADY_USED', 409); await consume(ops, entry);
    if (proof.enroll) { const active = { ...enrolled, enrollmentState: 'active', revision: randomToken(), activatedAt: Date.now() }; if (await ops.replace(configKey(scope), enrolled.revision, active, ENROLLMENT_SECONDS) !== true) fail('ADMIN_ENROLLMENT_STATE_CHANGED', 409); }
    const token = await issue(ops, scope, 'session', { factors: 'email+passkey+totp' }, SESSION_SECONDS); ops.setSession(token, SESSION_SECONDS); return { ok: true, stage: 'complete', authenticated: true, expires_in: null, persistent_session: true, action_email_required: false, action_passkey_required: true };
  }
  if (action === 'admin_logout') { const active = await session(ops, scope, false); if (active) await consume(ops, active); await ops.clearSession(); return { ok: true }; }
  await session(ops, scope); const operation = { admin_orders: 'orders', admin_shipment_update: 'shipment_update', admin_shipment_cancel: 'shipment_cancel', admin_blocks: 'blocks', admin_unban: 'unban', admin_smtp_send: 'smtp_send', admin_local_authorize: 'local_authorize', admin_monitor: 'monitor' }[action];
  if (!operation) fail('ADMIN_ACTION_INVALID', 400);
  if (Object.prototype.hasOwnProperty.call(ADMIN_APPROVAL_MUTATIONS, action)) { const approval = await ticket(ops, scope, body.approval, 'action-approval'); if (approval.value.operation !== action || approval.value.payloadHash !== approvalPayloadHash(action, body)) fail('ADMIN_ACTION_APPROVAL_MISMATCH', 403); await consume(ops, approval); }
  if (action === 'admin_smtp_send') { await throttle(ops, scope, 'smtp-send-minute', 2, 60); await throttle(ops, scope, 'smtp-send-hour', 5, 3600); }
  ops.assertFullGuard(); return ops.business(operation, body);
}

// V453: bounded shipment review, change summaries and signed customer receipts.
const SHIPMENT_CHANGE_FIELDS_V453 = Object.freeze(['tracking_number', 'courier', 'status', 'location', 'route', 'phase', 'eta_start', 'eta_end']);
function shipmentSnapshotV453(value) {
  const v = value || {}, j = v.journey || {};
  return { tracking_number: v.tracking_number || '', courier: v.courier || '', status: v.status || '', location: v.location || '', route: Array.isArray(j.stops) ? j.stops.join(' → ') : '', phase: j.phase || '', eta_start: j.eta_start || '', eta_end: j.eta_end || v.estimated_delivery || '' };
}
function shipmentRisksV453(previous, next) {
  const p = previous || {}, n = next || {}, before = shipmentSnapshotV453(p), after = shipmentSnapshotV453(n), rank = { prepared: 0, shipped: 1, in_transit: 2, delivered: 3 };
  const sameRoute = p.journey && n.journey && JSON.stringify(p.journey.stops) === JSON.stringify(n.journey.stops);
  return [
    p.tracking_number && before.tracking_number !== after.tracking_number ? 'TRACKING_CHANGED' : '',
    p.courier && before.courier !== after.courier ? 'COURIER_CHANGED' : '',
    before.route && before.route !== after.route ? 'ROUTE_CHANGED' : '',
    (Number.isInteger(rank[p.status]) && Number.isInteger(rank[n.status]) && rank[n.status] < rank[p.status]) || (sameRoute && n.journey.position < p.journey.position) ? 'BACKWARD' : '',
    ['eta_start', 'eta_end'].some(key => before[key] && after[key] && Math.abs(Date.parse(after[key]) - Date.parse(before[key])) > 2 * 86400000) ? 'ETA_SHIFT' : '',
    n.status === 'delivered' && (!p.status || p.status === 'prepared') ? 'DELIVERED_WITHOUT_TRANSIT' : '',
    p.status === 'delivered' && n.status !== 'delivered' ? 'DELIVERY_REOPENED' : '',
    n.status === 'cancelled' ? 'CANCELLED' : ''
  ].filter(Boolean).sort();
}
function shipmentChangesV453(previous, next) {
  const before = shipmentSnapshotV453(previous), after = shipmentSnapshotV453(next);
  return SHIPMENT_CHANGE_FIELDS_V453.filter(field => before[field] !== after[field]).map(field => ({ field, before: before[field], after: after[field] }));
}
function shipmentReviewV453(body, current, next) {
  const codes = shipmentRisksV453(current, next), ack = body.review_ack === undefined ? '' : body.review_ack, reason = body.review_reason === undefined ? '' : body.review_reason;
  if (typeof ack !== 'string' || ack.length > 220 || typeof reason !== 'string' || reason.length > 300) fail('ADMIN_SHIPMENT_REVIEW_INVALID', 400);
  const clean = businessText(reason, 300);
  if (ack !== codes.join(',') || (codes.length && clean.length < 10) || (!codes.length && clean)) fail('ADMIN_SHIPMENT_REVIEW_REQUIRED', 409);
  return codes.length ? { codes, reason: clean } : null;
}
function shipmentDeliveryRefV453(value) {
  if (!value || value.state !== 'active' || value.status !== 'delivered') return '';
  if (value.delivery_ref !== undefined) { if (!/^[a-f0-9]{64}$/.test(value.delivery_ref)) fail('SHIPMENT_RECEIPT_INVALID', 503); return value.delivery_ref; }
  const last = (value.events || []).filter(event => event.status === 'delivered').slice(-1)[0];
  return digest(stableJson(['delivery-v453', value.order_kind, value.order_id, value.customer_id, value.tracking_number, value.courier, last ? last.timestamp : value.updated_at]));
}
function shipmentReceiptMacV453(receipt) {
  const data = { ...receipt }; delete data.mac;
  const key = deriveSecret('shipment-customer-receipt-v453');
  try { return crypto.createHmac('sha256', key).update(stableJson(data)).digest('hex'); } finally { key.fill(0); }
}
function shipmentReceiptCheckV453(receipt, value) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt) || Object.keys(receipt).sort().join(',') !== 'auth_user_id,confirmed_at,courier,customer_id,delivery_ref,mac,note,order_id,order_kind,outcome,quantity,sequence,tracking_number,version' || receipt.version !== 453 || !['received', 'issue', 'not_received'].includes(receipt.outcome) || !isUuid(receipt.auth_user_id) || receipt.customer_id !== value.customer_id || receipt.order_id !== value.order_id || receipt.order_kind !== value.order_kind || !/^[a-f0-9]{64}$/.test(String(receipt.delivery_ref || '')) || !/^[a-f0-9]{64}$/.test(String(receipt.mac || '')) || !Number.isSafeInteger(receipt.sequence) || receipt.sequence < 1 || receipt.sequence > 5 || !/^[A-Za-z0-9][A-Za-z0-9 ._-]{2,99}$/.test(String(receipt.tracking_number || '')) || shipmentTimestamp(receipt.confirmed_at) === null || Date.parse(receipt.confirmed_at) > Date.now() + 60000) fail('SHIPMENT_RECEIPT_INVALID', 503);
  businessText(receipt.courier, 80, true); businessText(receipt.note, 300);
  if ((receipt.quantity !== null && (!Number.isSafeInteger(receipt.quantity) || receipt.quantity < 0 || receipt.quantity > 1000000)) || (receipt.outcome === 'received' && receipt.quantity === 0) || (receipt.outcome === 'not_received' && receipt.quantity !== 0) || (receipt.outcome !== 'received' && receipt.note.length < 10) || !safeEqual(receipt.mac, shipmentReceiptMacV453(receipt))) fail('SHIPMENT_RECEIPT_INVALID', 503);
  return receipt;
}
function shipmentExtrasCheckV453(value) {
  if (value.delivery_ref !== undefined && !/^[a-f0-9]{64}$/.test(String(value.delivery_ref))) fail('SHIPMENT_RECEIPT_INVALID', 503);
  if (value.receipt !== undefined) shipmentReceiptCheckV453(value.receipt, value);
  if (value.receipt_history !== undefined && (!Array.isArray(value.receipt_history) || value.receipt_history.length > 20 || value.receipt_history.some(receipt => !shipmentReceiptCheckV453(receipt, value)))) fail('SHIPMENT_RECEIPT_INVALID', 503);
  if (value.events.some(event => {
    if (event.revision !== undefined && (!Number.isSafeInteger(event.revision) || event.revision < 1 || event.revision > value.revision)) return true;
    if (event.review !== undefined && (!event.review || Object.keys(event.review).sort().join(',') !== 'codes,reason' || !Array.isArray(event.review.codes) || !event.review.codes.length || event.review.codes.length > 8 || new Set(event.review.codes).size !== event.review.codes.length || event.review.codes.some(code => !['TRACKING_CHANGED','COURIER_CHANGED','ROUTE_CHANGED','BACKWARD','ETA_SHIFT','DELIVERED_WITHOUT_TRANSIT','DELIVERY_REOPENED','CANCELLED'].includes(code)) || typeof event.review.reason !== 'string' || event.review.reason.length < 10 || event.review.reason.length > 300 || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(event.review.reason))) return true;
    if (event.actor !== undefined && !['admin', 'customer'].includes(event.actor)) return true;
    if (event.changes !== undefined && (!Array.isArray(event.changes) || event.changes.length > 8 || event.changes.some(change => !change || Object.keys(change).sort().join(',') !== 'after,before,field' || !SHIPMENT_CHANGE_FIELDS_V453.includes(change.field) || typeof change.before !== 'string' || typeof change.after !== 'string' || change.before.length > 1020 || change.after.length > 1020 || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(change.before + change.after)))) return true;
    return false;
  })) fail('SHIPMENT_CHANGE_RECORD_INVALID', 503);
  return true;
}
function shipmentReceiptPublicV453(value) {
  const receipt = value && value.receipt; if (!receipt) return null;
  shipmentReceiptCheckV453(receipt, value);
  return { outcome: receipt.outcome, quantity: receipt.quantity, note: receipt.note, confirmed_at: receipt.confirmed_at, sequence: receipt.sequence, tracking_number: receipt.tracking_number, courier: receipt.courier, current: receipt.delivery_ref === shipmentDeliveryRefV453(value) };
}
function shipmentEventPublicV453(event, admin) {
  return { timestamp: event.timestamp, status: event.status, description: event.description, location: event.location, ...(event.revision === undefined ? {} : { revision: event.revision }), ...(event.actor ? { actor: event.actor } : {}), ...(event.changes ? { changes: event.changes.map(change => ({ field: change.field, before: change.before, after: change.after })) } : {}), ...(admin && event.review ? { review: event.review } : {}) };
}
function shipmentPreserveReceiptV453(previous, next) {
  if (previous) { shipmentExtrasCheckV453(previous); if (previous.receipt) next.receipt = JSON.parse(JSON.stringify(previous.receipt)); if (previous.receipt_history) next.receipt_history = JSON.parse(JSON.stringify(previous.receipt_history)); }
  if (next.state === 'active' && next.status === 'delivered') next.delivery_ref = previous && previous.tracking_number === next.tracking_number && previous.courier === next.courier && previous.state === 'active' && previous.status === 'delivered' ? shipmentDeliveryRefV453(previous) : digest(stableJson(['delivery-v453', next.order_kind, next.order_id, next.customer_id, next.tracking_number, next.courier, next.updated_at]));
}
function shipmentReceiptBuildV453(row, owner, input) {
  const previous = validateShipmentRow(row, row.security_key); if (!previous) fail('SHIPMENT_RECEIPT_RECORD_INVALID', 503);
  shipmentExtrasCheckV453(previous);
  if (!owner || owner.customerId !== previous.customer_id || owner.orderId !== previous.order_id || owner.kind !== previous.order_kind || !isUuid(owner.userId)) fail('SHIPMENT_RECEIPT_OWNER_MISMATCH', 403);
  if (previous.state !== 'active' || previous.status !== 'delivered') fail('SHIPMENT_RECEIPT_NOT_DELIVERED', 409);
  const deliveryRef = shipmentDeliveryRefV453(previous), prior = previous.receipt && previous.receipt.delivery_ref === deliveryRef ? previous.receipt : null;
  const note = businessText(input.note, 300), outcome = input.outcome, quantity = input.quantity;
  if (!['received', 'issue', 'not_received'].includes(outcome) || (quantity !== null && (!Number.isSafeInteger(quantity) || quantity < 0 || quantity > 1000000)) || (outcome === 'received' && quantity === 0) || (outcome === 'not_received' && quantity !== 0) || (outcome !== 'received' && note.length < 10)) fail('SHIPMENT_RECEIPT_INPUT_INVALID', 400);
  if (input.delivery_ref !== deliveryRef || input.tracking_number !== previous.tracking_number) fail('SHIPMENT_RECEIPT_VERSION_CONFLICT', 409);
  if (prior && prior.outcome === outcome && prior.quantity === quantity && prior.note === note) return { row, unchanged: true };
  if (!Number.isSafeInteger(input.expected_revision) || input.expected_revision !== previous.revision) fail('SHIPMENT_RECEIPT_VERSION_CONFLICT', 409);
  if (previous.automation && shipmentAutomationV450(previous).lease_until_ms > Date.now()) fail('SHIPMENT_BUSY', 409);
  if (prior && prior.sequence >= 5) fail('SHIPMENT_RECEIPT_LIMIT', 409);
  const next = JSON.parse(JSON.stringify(previous)), now = Math.max(Date.now(), Date.parse(row.updated_at) + 1), timestamp = new Date(now).toISOString();
  const receipt = { version: 453, customer_id: owner.customerId, auth_user_id: owner.userId, order_id: owner.orderId, order_kind: owner.kind, delivery_ref: deliveryRef, tracking_number: previous.tracking_number, courier: previous.courier, outcome, quantity, note, sequence: prior ? prior.sequence + 1 : 1, confirmed_at: timestamp };
  receipt.mac = shipmentReceiptMacV453(receipt);
  if (previous.receipt) next.receipt_history = (previous.receipt_history || []).concat([previous.receipt]).slice(-20);
  next.receipt = receipt; next.delivery_ref = deliveryRef; next.revision += 1; next.updated_at = timestamp;
  next.events = next.events.slice(-49).concat([{ timestamp, status: previous.status, location: previous.location, description: { received: 'Pelanggan mengonfirmasi penerimaan paket.', issue: 'Pelanggan melaporkan selisih atau kondisi barang.', not_received: 'Pelanggan menyatakan paket belum diterima.' }[outcome], revision: next.revision, actor: 'customer' }]);
  const saved = { security_key: row.security_key, record_json: next, blocked_until_ms: 0, updated_at: timestamp, expires_at: row.expires_at };
  if (!validateShipmentRow(saved, saved.security_key)) fail('SHIPMENT_RECEIPT_RECORD_INVALID', 503);
  return { row: saved, unchanged: false };
}

function shipmentKey(kind, id) { if (!Object.prototype.hasOwnProperty.call(ORDER_SELECT, kind) || !isUuid(id)) fail('ADMIN_ORDER_ID_INVALID', 400); return SHIPMENT_PREFIX + kind + ':' + String(id).toLowerCase(); }
function shipmentTimestamp(value) {
  if (typeof value !== 'string') return null; const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(?:Z|\+00:00)$/.exec(value); if (!match) return null;
  const ms = Date.parse(match[1] + 'Z'); if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== match[1]) return null; return BigInt(ms) * 1000n + BigInt((match[2] || '').padEnd(6, '0'));
}
function businessText(value, maximum, required = false) { if (typeof value !== 'string' || value.length > maximum || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(value) || (required && !value.trim())) fail('ADMIN_SHIPMENT_TEXT_INVALID', 400); return value.trim(); }
// Manual shipment data only. This validator performs no network or database I/O.
function shipmentJourneyV452(input) {
  if (input === undefined || input === null) return null;
  const invalid = () => { throw Object.assign(new Error('ADMIN_SHIPMENT_JOURNEY_INVALID'), { code: 'ADMIN_SHIPMENT_JOURNEY_INVALID', status: 400, statusCode: 400 }); };
  const keys = ['version', 'source', 'stops', 'position', 'phase', 'observed_at', 'eta_start', 'eta_end'];
  if (typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== keys.length || Object.keys(input).some(key => !keys.includes(key)) || input.version !== 452 || input.source !== 'admin') invalid();
  if (!Array.isArray(input.stops) || input.stops.length < 2 || input.stops.length > 12 || input.stops.some(stop => typeof stop !== 'string' || !stop.trim() || stop !== stop.trim() || stop.length > 80 || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(stop))) invalid();
  if (!Number.isSafeInteger(input.position) || input.position < 0 || input.position >= input.stops.length || !['prepared', 'handed_over', 'linehaul', 'at_hub', 'sorting', 'out_for_delivery', 'delayed', 'delivered'].includes(input.phase)) invalid();
  if ((input.phase === 'delivered') !== (input.position === input.stops.length - 1) || (['prepared', 'handed_over'].includes(input.phase) && input.position !== 0)) invalid();
  const observed = typeof input.observed_at === 'string' ? Date.parse(input.observed_at) : NaN;
  if (!Number.isFinite(observed) || observed < 946684800000 || new Date(observed).toISOString() !== input.observed_at) invalid();
  const validDay = value => typeof value === 'string' && (/^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(Date.parse(value)).toISOString().slice(0, 10) === value);
  if (!((input.eta_start === '' && input.eta_end === '') || (validDay(input.eta_start) && validDay(input.eta_end) && input.eta_start <= input.eta_end && Date.parse(input.eta_end) <= observed + 366 * 86400000))) invalid();
  return { version: 452, source: 'admin', stops: input.stops.slice(), position: input.position, phase: input.phase, observed_at: input.observed_at, eta_start: input.eta_start, eta_end: input.eta_end };
}
function shipmentJourneyApplyV452(options, cancel, current, next) {
  const prior = current.value && shipmentJourneyV452(current.value.journey);
  const explicit = options && Object.prototype.hasOwnProperty.call(options, 'journey');
  const sameShipment = current.value && next.tracking_number === current.value.tracking_number && next.courier === current.value.courier;
  const journey = cancel ? prior : explicit ? options.journey : sameShipment ? prior : null;
  if (!journey) return;
  if (!cancel) {
    const expected = { prepared: 'prepared', handed_over: 'shipped', linehaul: 'in_transit', at_hub: 'in_transit', sorting: 'in_transit', out_for_delivery: 'in_transit', delayed: 'in_transit', delivered: 'delivered' }[journey.phase];
    if (next.status !== expected || Date.parse(journey.observed_at) > Date.now() + 60000 || (sameShipment && prior && Date.parse(journey.observed_at) < Date.parse(prior.observed_at))) fail('ADMIN_SHIPMENT_JOURNEY_CONFLICT', 400);
    next.location = journey.stops[journey.position];
    next.estimated_delivery = journey.eta_end;
  }
  next.journey = journey;
}
function validateShipmentRow(row, key) {
  if (!row || typeof row !== 'object' || Array.isArray(row) || row.security_key !== key || Number(row.blocked_until_ms) !== 0 || shipmentTimestamp(row.updated_at) === null || !Number.isFinite(Date.parse(row.expires_at)) || Date.parse(row.expires_at) <= Date.now()) return null;
  const value = row.record_json;
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schema !== 'dirac.admin_shipment.v406' || !['active', 'cancelled'].includes(value.state) || !isUuid(value.customer_id) || !isUuid(value.updated_by) || !Number.isSafeInteger(value.revision) || value.revision < 1 || !['prepared', 'shipped', 'in_transit', 'delivered', 'cancelled'].includes(value.status) || (value.state === 'cancelled') !== (value.status === 'cancelled') || shipmentTimestamp(value.updated_at) === null || shipmentTimestamp(value.updated_at) !== shipmentTimestamp(row.updated_at) || !Array.isArray(value.events) || value.events.length < 1 || value.events.length > 50) return null;
  try { shipmentExtrasCheckV453(value); shipmentJourneyV452(value.journey); if (shipmentKey(value.order_kind, value.order_id) !== key || !/^[A-Za-z0-9][A-Za-z0-9 ._-]{2,99}$/.test(value.tracking_number)) return null; businessText(value.courier, 80, true); businessText(value.location, 160); businessText(value.origin, 600); businessText(value.destination, 600); if (value.estimated_delivery !== '' && (!/^\d{4}-\d{2}-\d{2}$/.test(value.estimated_delivery) || !Number.isFinite(Date.parse(value.estimated_delivery)))) return null; const invalidEvent = value.events.some(event => { if (!event || typeof event !== 'object' || Array.isArray(event) || !Number.isFinite(Date.parse(event.timestamp)) || typeof event.status !== 'string') return true; businessText(event.description, 300, true); businessText(event.location, 160); return false; }); if (invalidEvent) return null; } catch (_) { return null; }
  return value;
}
function shipmentPublic(value) { return value ? { kind: value.order_kind, receipt: shipmentReceiptPublicV453(value), delivery_ref: shipmentDeliveryRefV453(value), ...(value.journey ? { journey: shipmentJourneyV452(value.journey) } : {}), ...(value.automation ? { automation: shipmentAutomationPublicV450(value) } : {}), tracking_number: value.tracking_number, courier: value.courier, state: value.state, status: value.status, location: value.location, origin: value.origin, destination: value.destination, estimated_delivery: value.estimated_delivery, updated_at: value.updated_at, revision: value.revision, events: value.events.map(event => shipmentEventPublicV453(event, true)) } : null; }
function orderPublic(row, kind) {
  if (!row || !isUuid(row.id) || !isUuid(row.customer_id)) fail('ADMIN_ORDER_RECORD_INVALID', 503);
  const total = Number(row.total === undefined ? row.total_price : row.total); if (!Number.isFinite(total)) fail('ADMIN_ORDER_RECORD_INVALID', 503);
  return { id: row.id, kind, order_id: String(row.order_id || (kind === 'domain' ? 'DOM-' + row.id.slice(0, 8).toUpperCase() : row.id)), customer_id: row.customer_id, customer_name: String(row.customer_name || '').slice(0, 160), customer_email: String(row.customer_email || '').slice(0, 254), customer_phone: String(row.customer_phone || row.customer_whatsapp || '').slice(0, 40), shipping_address: String(row.shipping_address || '').slice(0, 600), service_type: kind === 'domain' ? 'domain' : String(row.service_type || '').slice(0, 60), domain_name: String(row.domain_name || '').slice(0, 254), total, currency: String(row.currency || 'IDR').slice(0, 8), payment_method: String(row.payment_method || '').slice(0, 80), payment_status: String(row.payment_status || '').slice(0, 40), order_status: String(row.order_status || '').slice(0, 40), created_at: row.created_at };
}
function domainOrderUndefinedColumn(result) { return !!(result && result.ok === false && result.status === 400 && result.data && String(result.data.code || '') === '42703'); }
async function businessOrders(body) {
  const kind = String(body.kind || 'regular'), offsetRaw = String(body.offset || '0'); if (!Object.prototype.hasOwnProperty.call(ORDER_SELECT, kind) || !/^(0|[1-9][0-9]{0,4})$/.test(offsetRaw) || Number(offsetRaw) > 50000) fail('ADMIN_PAGE_INVALID', 400);
  const table = kind === 'domain' ? 'domain_orders' : 'orders', suffix = '&order=created_at.desc,id.desc&limit=41&offset=' + Number(offsetRaw), path = '/rest/v1/' + table + '?select=' + encodeURIComponent(ORDER_SELECT[kind]) + suffix; let result = await dbFetch(path, { method: 'GET' }, kind === 'laboratorium' ? 'security' : '');
  if (kind === 'domain' && domainOrderUndefinedColumn(result)) result = await dbFetch('/rest/v1/domain_orders?select=' + encodeURIComponent(DOMAIN_ORDER_COMPAT_SELECT) + suffix, { method: 'GET' });
  if (!result.ok || !Array.isArray(result.data) || result.data.length > 41) fail('ADMIN_DATA_UNAVAILABLE', 503); const rows = result.data, orders = rows.slice(0, 40).map(row => orderPublic(row, kind)), keys = orders.map(row => shipmentKey(kind, row.id));
  let shipments = []; if (keys.length) { const shipped = await dbFetch('/rest/v1/dirac_s2s_security?select=' + encodeURIComponent(SHIPMENT_SELECT) + '&security_key=in.(' + keys.map(encodeURIComponent).join(',') + ')&limit=' + keys.length, { method: 'GET' }, 'security'); if (!shipped.ok || !Array.isArray(shipped.data) || shipped.data.length > keys.length) fail('ADMIN_SHIPMENT_RECORD_INVALID', 503); shipments = shipped.data; }
  const map = new Map(); shipments.forEach(row => { if (!keys.includes(row && row.security_key) || map.has(row.security_key)) fail('ADMIN_SHIPMENT_RECORD_INVALID', 503); const value = validateShipmentRow(row, row.security_key), order = orders.find(item => item.id === (value && value.order_id)); if (!value || !order || order.customer_id !== value.customer_id) fail('ADMIN_SHIPMENT_OWNER_MISMATCH', 503); map.set(row.security_key, value); });
  return { ok: true, kind, offset: Number(offsetRaw), has_more: rows.length === 41, orders: orders.map(row => ({ ...row, shipment: shipmentPublic(map.get(shipmentKey(kind, row.id))) })), time: new Date().toISOString() };
}
async function loadOrder(kind, id, database = dbFetch) {
  const table = kind === 'domain' ? 'domain_orders' : 'orders', suffix = '&id=eq.' + encodeURIComponent(id) + '&limit=2', path = '/rest/v1/' + table + '?select=' + encodeURIComponent(ORDER_SELECT[kind]) + suffix; let result = await database(path, { method: 'GET' }, kind === 'laboratorium' ? 'security' : '');
  if (kind === 'domain' && domainOrderUndefinedColumn(result)) result = await database('/rest/v1/domain_orders?select=' + encodeURIComponent(DOMAIN_ORDER_COMPAT_SELECT) + suffix, { method: 'GET' });
  if (!result.ok || !Array.isArray(result.data)) fail('ADMIN_DATA_UNAVAILABLE', 503); if (result.data.length !== 1 || result.data[0].id !== id) fail('ADMIN_ORDER_NOT_FOUND', 404); return orderPublic(result.data[0], kind);
}
async function loadShipment(key) {
  const result = await dbFetch('/rest/v1/dirac_s2s_security?select=' + encodeURIComponent(SHIPMENT_SELECT) + '&security_key=eq.' + encodeURIComponent(key) + '&limit=2', { method: 'GET' }, 'security');
  if (!result.ok || !Array.isArray(result.data) || result.data.length > 1) fail('ADMIN_DATA_UNAVAILABLE', 503); if (!result.data.length) return { row: null, value: null }; const value = validateShipmentRow(result.data[0], key); if (!value) fail('ADMIN_SHIPMENT_RECORD_INVALID', 503); return { row: result.data[0], value };
}
async function businessShipment(body, cancel, origin, assertContext) {
  const kind = String(body.kind || ''), id = String(body.order_id || ''), key = shipmentKey(kind, id), revision = body.expected_revision; if (!Number.isSafeInteger(revision) || revision < 0 || revision >= Number.MAX_SAFE_INTEGER) fail('ADMIN_REVISION_INVALID', 400);
  const order = await loadOrder(kind, id), current = await loadShipment(key); if (current.value && current.value.customer_id !== order.customer_id) fail('ADMIN_SHIPMENT_OWNER_MISMATCH', 503); if (revision !== (current.value ? current.value.revision : 0)) fail('ADMIN_VERSION_CONFLICT', 409); if (cancel && (!current.value || current.value.state === 'cancelled')) fail('ADMIN_SHIPMENT_NOT_ACTIVE', 409);
  const description = businessText(body.description || (cancel ? 'Resi dibatalkan oleh admin.' : 'Informasi pengiriman diperbarui oleh admin.'), 300, true), status = cancel ? 'cancelled' : String(body.status || ''); if (!['prepared', 'shipped', 'in_transit', 'delivered', 'cancelled'].includes(status) || (!cancel && status === 'cancelled')) fail('ADMIN_SHIPMENT_STATUS_INVALID', 400);
  const tracking = cancel ? current.value.tracking_number : String(body.tracking_number || '').trim(); if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{2,99}$/.test(tracking)) fail('ADMIN_TRACKING_NUMBER_INVALID', 400);
  const now = Math.max(Date.now(), current.row ? Date.parse(current.row.updated_at) + 1 : 0), timestamp = new Date(now).toISOString(), value = { schema: 'dirac.admin_shipment.v406', order_kind: kind, order_id: id, customer_id: order.customer_id, revision: revision + 1, state: cancel ? 'cancelled' : 'active', tracking_number: tracking, courier: cancel ? current.value.courier : businessText(body.courier, 80, true), status, location: cancel ? current.value.location : businessText(body.location || '', 160), origin: cancel ? current.value.origin : businessText(body.origin || '', 600), destination: cancel ? current.value.destination : businessText(body.destination || order.shipping_address || '', 600), estimated_delivery: cancel ? current.value.estimated_delivery : String(body.estimated_delivery || ''), events: (current.value ? current.value.events : []).slice(-49), updated_at: timestamp, updated_by: ADMIN_USER_ID };
  const mailStage = await prepareShipmentV450(body, cancel, current, value, order, origin);
  const review = shipmentReviewV453(body, current.value, value); shipmentPreserveReceiptV453(current.value, value);
  value.events.push({ timestamp, status, description, location: value.location, revision: value.revision, actor: 'admin', changes: shipmentChangesV453(current.value, value), ...(review ? { review } : {}) }); const row = { security_key: key, record_json: value, blocked_until_ms: 0, expires_at: new Date(now + ENROLLMENT_SECONDS * 1000).toISOString(), updated_at: timestamp }; if (!validateShipmentRow(row, key)) fail('ADMIN_SHIPMENT_RECORD_INVALID', 400);
  let path, method, bodyValue; if (!current.row) { path = '/rest/v1/dirac_s2s_security?select=' + encodeURIComponent(SHIPMENT_SELECT); method = 'POST'; bodyValue = [row]; } else { path = '/rest/v1/dirac_s2s_security?select=' + encodeURIComponent(SHIPMENT_SELECT) + '&security_key=eq.' + encodeURIComponent(key) + '&updated_at=eq.' + encodeURIComponent(current.row.updated_at); method = 'PATCH'; bodyValue = row; }
  const result = await dbFetch(path, { method, prefer: 'return=representation', body: bodyValue }, 'security'); if (!result.ok || !Array.isArray(result.data) || result.data.length !== 1) fail('ADMIN_VERSION_CONFLICT', 409); const confirmed = validateShipmentRow(result.data[0], key); if (!confirmed || stableJson(confirmed) !== stableJson(value)) fail('ADMIN_SHIPMENT_WRITE_UNVERIFIED', 503);
  if (mailStage) { const notice = await shipmentNotifyV450(result.data[0], mailStage, order, origin, dbFetch, sendCustomerMail, assertContext); return { ok: true, shipment: shipmentPublic(notice.row.record_json), shipment_notification: notice.notification }; }
  return { ok: true, shipment: shipmentPublic(confirmed) };
}
/* Shipment notices use manual updates only. Legacy signed state remains readable.
 * No carrier API, worker queue, new table, or new environment variable is used. */
const SHIPMENT_LEASE_V450 = 180000;
const SHIPMENT_OPTION_KEYS_V450 = Object.freeze(['enabled', 'courier_code', 'tracking_id', 'smtp_provider', 'mode', 'journey']);
function shipmentOptionsV450(input) {
  if (input === undefined) return null;
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !SHIPMENT_OPTION_KEYS_V450.includes(key)) || typeof input.enabled !== 'boolean') fail('SHIPMENT_OPTIONS_INVALID', 400);
  if (input.mode !== undefined && input.mode !== 'manual') fail('SHIPMENT_OPTIONS_INVALID', 400);
  const fields = ['courier_code', 'tracking_id', 'smtp_provider'];
  if (fields.some(key => input[key] !== undefined && typeof input[key] !== 'string')) fail('SHIPMENT_OPTIONS_INVALID', 400);
  const out = { enabled: input.enabled, mode: 'manual', courier_code: String(input.courier_code || 'manual').trim(), tracking_id: String(input.tracking_id || '').trim(), smtp_provider: String(input.smtp_provider || 'auto').trim() };
  if (!/^[a-z0-9][a-z0-9_-]{0,39}$/.test(out.courier_code) || !/^[A-Za-z0-9._-]{0,120}$/.test(out.tracking_id) || !['auto', 'google', 'mailjet', 'brevo', 'resend'].includes(out.smtp_provider)) fail('SHIPMENT_OPTIONS_INVALID', 400);
  if (input.journey !== undefined) out.journey = shipmentJourneyV452(input.journey);
  return out;
}
function shipmentIntegrationKeyV450(purpose) {
  const material = deriveSecret('shipment-v450-' + purpose);
  try { return crypto.createHash('sha256').update(material).digest(); } finally { material.fill(0); }
}
function shipmentMacV450(value) {
  const metadata = { ...value.automation }; delete metadata.mac;
  const key = shipmentIntegrationKeyV450('state');
  try { return crypto.createHmac('sha256', key).update(stableJson({ order_id: value.order_id, order_kind: value.order_kind, customer_id: value.customer_id, tracking_number: value.tracking_number, courier: value.courier, ...(value.journey ? { journey: shipmentJourneyV452(value.journey) } : {}), automation: metadata })).digest('hex'); } finally { key.fill(0); }
}
function shipmentSignV450(value) { if (value.automation) value.automation.mac = shipmentMacV450(value); return value; }
function shipmentAutomationV450(value) {
  const a = value && value.automation; if (a === undefined) return null;
  if (!a || a.version !== 450 || typeof a.enabled !== 'boolean' || typeof a.polling !== 'boolean' || !/^[a-f0-9]{64}$/.test(String(a.generation || '')) || !/^[a-z0-9][a-z0-9_-]{0,39}$/.test(String(a.courier_code || '')) || !/^[A-Za-z0-9._-]{0,120}$/.test(String(a.tracking_id || '')) || !['auto', 'google', 'mailjet', 'brevo', 'resend'].includes(a.smtp_provider) || (a.mode !== undefined && !['api', 'manual'].includes(a.mode)) || (a.mode === 'manual' && a.polling) || !a.mail || !['initial', 'transit', 'delivered'].every(stage => ['pending', 'claimed', 'accepted', 'uncertain', 'skipped'].includes(a.mail[stage])) || !['next_check_ms', 'last_attempt_ms', 'last_check_ms', 'lease_until_ms'].every(name => Number.isSafeInteger(a[name]) && a[name] >= 0) || !/^[A-Z0-9_]{0,80}$/.test(a.last_error || '') || !/^[a-f0-9]{64}$/.test(String(a.mac || '')) || !safeEqual(a.mac, shipmentMacV450(value))) fail('SHIPMENT_STATE_INVALID', 503);
  return a;
}
function shipmentAutomationPublicV450(value) {
  const a = shipmentAutomationV450(value); if (!a) return null;
  const expiredClaim = a.lease_until_ms <= Date.now();
  return { enabled: a.enabled, polling: false, mode: 'manual', courier_code: a.courier_code, tracking_id: a.tracking_id, smtp_provider: a.smtp_provider, next_check_ms: null, last_attempt_ms: a.last_attempt_ms || null, last_check_ms: a.last_check_ms || null, last_error: a.last_error || '', provider_status: String(a.provider_status || '').slice(0, 80), mail: Object.fromEntries(['initial', 'transit', 'delivered'].map(stage => [stage, expiredClaim && a.mail[stage] === 'claimed' ? 'uncertain' : a.mail[stage]])) };
}
function shipmentStageV450(value, firstSave) {
  const a = value.automation; if (!a || !a.enabled || value.state !== 'active') return '';
  if (value.status === 'delivered') { if (a.mail.initial === 'pending') a.mail.initial = 'skipped'; if (a.mail.transit === 'pending') a.mail.transit = 'skipped'; return a.mail.delivered === 'pending' ? 'delivered' : ''; }
  if (a.mail.initial === 'pending') return 'initial';
  return !firstSave && value.status === 'in_transit' && a.mail.transit === 'pending' ? 'transit' : '';
}
function shipmentCustomerOriginV450(origin) {
  let url; try { url = new URL(origin); } catch (_) { fail('SHIPMENT_ORIGIN_INVALID', 503); }
  if (url.protocol !== 'https:' || url.port || url.username || url.password || url.pathname !== '/' || url.search || url.hash || !/^pt\.(?:[a-z0-9-]+\.)+[a-z]{2,63}$/.test(url.hostname)) fail('SHIPMENT_ORIGIN_INVALID', 503);
  return url.origin;
}
async function prepareShipmentV450(body, cancel, current, next, order, origin) {
  const previous = current.value ? shipmentAutomationV450(current.value) : null, options = cancel ? null : shipmentOptionsV450(body.tracking_options);
  if (previous && previous.lease_until_ms > Date.now()) fail('SHIPMENT_BUSY', 409);
  shipmentJourneyApplyV452(options, cancel, current, next);
  if (!previous && (!options || !options.enabled)) return '';
  if (previous && !options) {
    if (!cancel && (next.tracking_number !== current.value.tracking_number || next.courier !== current.value.courier)) fail('SHIPMENT_OPTIONS_REQUIRED', 409);
    next.automation = JSON.parse(JSON.stringify(previous));
  } else if (options && options.enabled) {
    if (!isEmail(order.customer_email)) fail('SHIPMENT_CUSTOMER_EMAIL_REQUIRED', 409);
    if (!customerMailConfiguredV451('auto')) fail('SHIPMENT_SMTP_NOT_CONFIGURED', 503);
    // Keep the existing generation and mail receipts when converting an API row.
    const sameShipment = previous && current.value.tracking_number === next.tracking_number && current.value.courier === next.courier;
    const generation = sameShipment ? previous.generation : digest([next.order_kind, next.order_id, next.tracking_number, next.courier, options.courier_code, options.tracking_id].join('\0'));
    next.automation = sameShipment ? JSON.parse(JSON.stringify(previous)) : { version: 450, generation, enabled: true, polling: false, mode: 'manual', courier_code: options.courier_code, tracking_id: options.tracking_id, smtp_provider: 'auto', next_check_ms: 0, last_attempt_ms: 0, last_check_ms: 0, lease_until_ms: 0, last_error: '', provider_status: '', mail: { initial: 'pending', transit: 'pending', delivered: 'pending' } };
    next.automation.enabled = true; next.automation.smtp_provider = 'auto';
  } else { next.automation = JSON.parse(JSON.stringify(previous)); next.automation.enabled = false; }
  const a = next.automation;
  if (cancel) a.enabled = false;
  a.mode = 'manual'; a.polling = false; a.next_check_ms = 0;
  const stage = shipmentStageV450(next, !previous);
  if (stage) { a.mail[stage] = 'claimed'; a.lease_until_ms = Date.now() + SHIPMENT_LEASE_V450; }
  shipmentSignV450(next); return stage;
}
function shipmentNextRowV450(row, value) {
  const now = Math.max(Date.now(), Date.parse(row.updated_at) + 1);
  if (!Number.isFinite(now) || !Number.isSafeInteger(value.revision) || value.revision >= Number.MAX_SAFE_INTEGER) fail('SHIPMENT_STATE_INVALID', 503);
  value.revision += 1; value.updated_at = new Date(now).toISOString(); shipmentSignV450(value);
  return { security_key: row.security_key, record_json: value, blocked_until_ms: 0, expires_at: row.expires_at, updated_at: value.updated_at };
}
async function shipmentCasV450(row, value, database) {
  const next = shipmentNextRowV450(row, value);
  if (!validateShipmentRow(next, next.security_key) || !shipmentAutomationV450(value)) fail('SHIPMENT_STATE_INVALID', 503);
  const path = '/rest/v1/dirac_s2s_security?security_key=eq.' + encodeURIComponent(row.security_key) + '&updated_at=eq.' + encodeURIComponent(row.updated_at) + '&select=' + encodeURIComponent(SHIPMENT_SELECT);
  const write = await database(path, { method: 'PATCH', body: next, prefer: 'return=representation' }, 'security');
  if (!write.ok || !Array.isArray(write.data)) fail('SHIPMENT_WRITE_UNCONFIRMED', 503);
  if (!write.data.length) return null;
  if (write.data.length !== 1 || !validateShipmentRow(write.data[0], row.security_key) || stableJson(write.data[0].record_json) !== stableJson(next.record_json)) fail('SHIPMENT_WRITE_UNCONFIRMED', 503);
  return write.data[0];
}
function shipmentMessageV450(value, order, origin, stage) {
  const site = shipmentCustomerOriginV450(origin), link = site + '/cekresi.html';
  const label = { initial: 'Nomor resi pesanan Anda telah dicatat', transit: 'Paket Anda sedang dalam perjalanan', delivered: 'Paket Anda telah diterima' }[stage];
  if (!label || !isEmail(order.customer_email) || order.customer_id !== value.customer_id || order.id !== value.order_id) fail('SHIPMENT_OWNER_MISMATCH', 503);
  const latest = value.events[value.events.length - 1], journey = shipmentJourneyV452(value.journey);
  const routeNote = journey ? 'Rencana rute: ' + journey.stops.join(' → ') + '\nTitik terakhir dilaporkan admin: ' + journey.stops[journey.position] + (journey.position < journey.stops.length - 1 ? '\nTitik berikutnya (rencana): ' + journey.stops[journey.position + 1] : '') + (journey.eta_start && stage !== 'delivered' ? '\nEstimasi admin: ' + journey.eta_start + ' s.d. ' + journey.eta_end : '') + '\nSumber: input admin, bukan pelacakan GPS atau API.' : '';
  const body = ['Halo ' + String(order.customer_name || 'Pelanggan').replace(/[\r\n]/g, ' ').slice(0, 160) + ',', '', label + '.', 'Nomor pesanan: ' + order.order_id, 'Kurir: ' + value.courier, 'Nomor resi: ' + value.tracking_number, value.location ? 'Lokasi terakhir: ' + value.location : '', latest ? 'Keterangan terakhir: ' + latest.description : '', routeNote, '', 'Lihat rincian melalui akun Anda: ' + link, '', 'Notifikasi otomatis terkait pesanan Anda. Balas email ini untuk bantuan.'].filter(line => line !== '').join('\n');
  return { provider: 'auto', recipients: [order.customer_email], subject: label + ' | ' + value.tracking_number, body, kind: 'delivery', attachment: null, origin: site, shipmentNotice: true };
}
async function shipmentNotifyV450(row, stage, order, origin, database, send, assertContext) {
  const value = JSON.parse(JSON.stringify(row.record_json));
  if (!stage || !shipmentAutomationV450(value) || value.automation.mail[stage] !== 'claimed') fail('SHIPMENT_NOTIFICATION_INVALID', 503);
  let outcome = 'uncertain';
  try { assertContext(); const message = shipmentMessageV450(value, order, origin, stage), result = await send(message, assertContext); assertContext(); if (customerMailAcceptedV451(result, message.provider, 1)) outcome = 'accepted'; } catch (_) { outcome = 'uncertain'; }
  value.automation.mail[stage] = outcome; value.automation.lease_until_ms = 0;
  if (outcome === 'uncertain') value.automation.last_error = 'SHIPMENT_SMTP_UNCONFIRMED';
  try { const updated = await shipmentCasV450(row, value, database); if (updated) return { row: updated, notification: outcome }; } catch (_) { /* Do not resubmit an ambiguous SMTP transaction. */ }
  return { row, notification: 'uncertain' };
}
async function shipmentDailyV450(req, transport) {
  const passport = req && Object.getOwnPropertyDescriptor(req, '__diracSupportCentralSecurityGuardPassedV146');
  const secret = String(process.env.CRON_SECRET || ''), supplied = String(req && req.headers && req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!passport || passport.value !== true || passport.writable !== false || passport.configurable !== false || req.diracSupportAction !== 'monitor_run' || !['GET', 'POST'].includes(String(req.method || '').toUpperCase()) || Buffer.byteLength(secret) < 32 || !safeEqual(secret, supplied) || !transport || typeof transport.assert !== 'function' || typeof transport.request !== 'function') fail('SHIPMENT_FULL_GUARD_REQUIRED', 403);
  transport.assert();
  return { ok: true, disabled: true, reason: 'manual_only', checked: 0, failed: 0, notified: 0, notification_uncertain: 0, batch_full: false };
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
    const logicalKey = String(record && record.type || '') === 'central_external_ban_v354'
      ? ['central_external_ban_v354', String(record.identity_email || record.identityEmail || record.email || '').trim().toLowerCase(), String(record.reason || ''), String(record.created_at || record.createdAt || ''), String(record.blocked_until_ms || record.blockedUntilMs || '')].join('|')
      : String(row.security_key || '');
    const id = digest(logicalKey); if (seen.has(id)) return; seen.add(id);
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
const ADMIN_CENTRAL_BAN_FAILURE_CODES = Object.freeze([
  'ADMIN_BODY_FIELD_INVALID', 'ADMIN_BODY_REQUIRED_FIELD', 'ADMIN_QUERY_FIELD_INVALID', 'ADMIN_FIELD_TOO_LARGE',
  'ADMIN_ACTION_APPROVAL_MISMATCH', 'ADMIN_ACTION_MISMATCH', 'ADMIN_BODY_FRAMING_INVALID', 'ADMIN_BODY_INVALID', 'ADMIN_BODY_KEY_INVALID',
  'ADMIN_BODY_TOO_COMPLEX', 'ADMIN_BODY_TOO_LARGE', 'ADMIN_CLIENT_HEADERS_INVALID', 'ADMIN_CONTENT_TYPE_INVALID', 'ADMIN_CREDENTIALS_INVALID',
  'ADMIN_EMAIL_CODE_INVALID', 'ADMIN_ENCODING_INVALID', 'ADMIN_FIXED_OWNER_REQUIRED', 'ADMIN_METHOD_NOT_ALLOWED', 'ADMIN_ORIGIN_INVALID',
  'ADMIN_PASSKEY_ALGORITHM_INVALID', 'ADMIN_PASSKEY_ATTESTATION_INVALID', 'ADMIN_PASSKEY_ATTESTED_DATA_REQUIRED', 'ADMIN_PASSKEY_AUTHDATA_INVALID',
  'ADMIN_PASSKEY_BACKUP_STATE_INVALID', 'ADMIN_PASSKEY_CBOR_INVALID', 'ADMIN_PASSKEY_CLIENT_INVALID', 'ADMIN_PASSKEY_CLIENT_MISMATCH',
  'ADMIN_PASSKEY_COUNTER_REPLAY', 'ADMIN_PASSKEY_CREDENTIAL_INVALID', 'ADMIN_PASSKEY_CREDENTIAL_MISMATCH', 'ADMIN_PASSKEY_INVALID',
  'ADMIN_PASSKEY_KEY_INVALID', 'ADMIN_PASSKEY_RECOVERY_INVALID', 'ADMIN_PASSKEY_RPID_MISMATCH', 'ADMIN_PASSKEY_SCOPE_INVALID',
  'ADMIN_PASSKEY_SIGNATURE_INVALID', 'ADMIN_PASSKEY_USER_MISMATCH', 'ADMIN_PASSKEY_UV_REQUIRED', 'ADMIN_PREFLIGHT_INVALID', 'ADMIN_PROOF_INVALID',
  'ADMIN_PROOF_REPLAYED', 'ADMIN_QUERY_DUPLICATE', 'ADMIN_REFERER_INVALID', 'ADMIN_REQUEST_INVALID', 'ADMIN_SECURITY_REPORT_INVALID',
  'ADMIN_SECURITY_REPORT_ONE_STRIKE', 'ADMIN_TICKET_ALREADY_USED', 'ADMIN_TICKET_INVALID', 'ADMIN_TOTP_ALREADY_USED', 'ADMIN_TOTP_INVALID'
]);
function adminCentralBanRequired(error) {
  const code = String(error && error.code || ''), status = Number(error && (error.status || error.statusCode) || 0);
  return [400, 401, 403, 405, 409, 413, 415].includes(status) && ADMIN_CENTRAL_BAN_FAILURE_CODES.includes(code);
}
function adminGuardSelfTest() {
  try {
    const expected = ['admin_entry','admin_security_report','admin_login','admin_status','admin_email_start','admin_email_verify','admin_action_passkey_start','admin_action_passkey_verify','admin_passkey_start','admin_passkey_verify','admin_passkey_recovery_start','admin_passkey_recovery_verify','admin_totp_verify','admin_logout','admin_orders','admin_shipment_update','admin_shipment_cancel','admin_blocks','admin_unban','admin_smtp_send','admin_local_authorize','admin_monitor'];
    return Object.isFrozen(CONTRACTS) && Object.isFrozen(ACTIONS) && ACTIONS.length === expected.length && expected.every((name, index) => ACTIONS[index] === name && Object.isFrozen(CONTRACTS[name]) && Object.isFrozen(CONTRACTS[name].methods) && Object.isFrozen(CONTRACTS[name].allowed) && Object.isFrozen(CONTRACTS[name].required))
      && exactToken(randomToken()) && PASSWORD_COOKIE.startsWith('__Host-') && SESSION_COOKIE.startsWith('__Host-') && adminSecretState().configured === true;
  } catch (_) { return false; }
}
const ADMIN_STATIC_GATE = Object.freeze({ ok: Object.isFrozen(CONTRACTS) && Object.isFrozen(ACTIONS) && Object.isFrozen(ADMIN_CENTRAL_BAN_FAILURE_CODES) && !ACTIONS.includes('__proto__') && !ACTIONS.includes('constructor') });

async function businessMonitor() {
  let rows = [], ready = false; try { const result = await dbFetch('/rest/v1/security_customer_events?select=id,event_type,status,risk_level,description,created_at&order=created_at.desc&limit=20', { method: 'GET' }); if (result.ok && Array.isArray(result.data) && result.data.length <= 20) { rows = result.data; ready = true; } } catch (_) { ready = false; }
  const memory = process.memoryUsage(); return { ok: true, time: new Date().toISOString(), guard: { self_test_ok: adminGuardSelfTest(), static_gate_ok: ADMIN_STATIC_GATE.ok, scope: 'Guard internal handler admin mandiri yang menangani permintaan ini.' }, runtime: { uptime_seconds: Math.floor(process.uptime()), rss_bytes: memory.rss, heap_used_bytes: memory.heapUsed, heap_total_bytes: memory.heapTotal }, events_ready: ready, events: ready ? rows.map(row => ({ event_type: String(row && row.event_type || '').slice(0, 100), status: String(row && row.status || '').slice(0, 40), risk_level: String(row && row.risk_level || '').slice(0, 40), description: String(row && row.description || '').slice(0, 240), created_at: String(row && row.created_at || '').slice(0, 48) })) : [] };
}
async function business(operation, body, origin, assertContext) { if (operation === 'local_authorize') { const checked = approvalPayload('admin_local_authorize', body); assertContext(); return { ok: true, authorized: true, purpose: checked.purpose, content_sha256: checked.content_sha256, one_time: true }; } if (operation === 'orders') return businessOrders(body); if (operation === 'shipment_update') return businessShipment(body, false, origin, assertContext); if (operation === 'shipment_cancel') return businessShipment(body, true, origin, assertContext); if (operation === 'blocks') return businessBlocks(body); if (operation === 'unban') return businessUnban(body); if (operation === 'smtp_send') return businessSmtpSend(body, origin, assertContext); if (operation === 'monitor') return businessMonitor(); fail('ADMIN_OPERATION_INVALID', 400); }

function adminCentralBanReason(error) {
  const raw = String(error && error.code || 'admin_failure').trim().toLowerCase().replace(/[^a-z0-9_:-]+/g, '_').replace(/^_+|_+$/g, '');
  return ('admin_failure:' + (raw || 'unknown')).slice(0, 96);
}
function adminCentralBanAuthority() {
  try {
    const central = require('./health.js'), authority = central && central.__diracCentralBanAuthorityV354;
    return authority && authority.version === 'dirac-central-ban-authority-v354' && typeof authority.ban === 'function' && typeof authority.check === 'function' ? authority : null;
  } catch (_) { return null; }
}
function adminCentralBanDiagnosticV445(req, error, required, outcome) {
  try {
    const rawUrl = String(req && req.url || '');
    const actionMatch = rawUrl.match(/[?&]action=([a-z0-9_]{1,80})(?:&|$)/i);
    const result = outcome && typeof outcome === 'object' ? outcome : {};
    console.error('[dirac-admin-ban-decision-diagnostic-v445] ' + JSON.stringify({
      patch: 'dirac-admin-ban-decision-diagnostic-v445',
      event: 'admin_central_ban_decision',
      action: actionMatch ? actionMatch[1].toLowerCase() : '',
      method: String(req && req.method || '').toUpperCase().slice(0, 12),
      error_code: String(error && error.code || '').slice(0, 96),
      error_status: Number(error && (error.status || error.statusCode) || 0),
      central_ban_required: required === true,
      central_ban_reason: required === true ? adminCentralBanReason(error) : '',
      outcome_ok: result.ok === true,
      outcome_skipped: result.skipped === true,
      outcome_reason: String(result.reason || '').slice(0, 96),
      central_ban_header_expected: required === true && result.ok === true && result.skipped !== true
    }));
  } catch (_) {}
}
async function adminCentralBanFailure(req, error) {
  // A security report writes its ban inside execute(); the outer catch must reuse
  // that result, not lose its acknowledgement or perform a second ban write.
  if (req && ADMIN_BAN_OUTCOMES.has(req)) return ADMIN_BAN_OUTCOMES.get(req);
  const required = adminCentralBanRequired(error);
  if (!required) {
    const skipped = Object.freeze({ ok: true, skipped: true });
    adminCentralBanDiagnosticV445(req, error, false, skipped);
    return skipped;
  }
  const pending = (async () => {
    let outcome;
    try {
      const authority = adminCentralBanAuthority();
      const result = authority ? await authority.ban(req, adminCentralBanReason(error), 10 * 365 * 24 * 60 * 60) : null;
      outcome = result && result.ok === true && result.blocked === true && Number.isSafeInteger(result.blocked_until_ms) && result.blocked_until_ms > Date.now()
        ? result : Object.freeze({ ok: false, reason: String(result && result.reason || 'central_ban_write_unverified') });
    } catch (_) { outcome = Object.freeze({ ok: false, reason: 'central_ban_write_exception' }); }
    adminCentralBanDiagnosticV445(req, error, true, outcome);
    return outcome;
  })();
  if (req && typeof req === 'object') ADMIN_BAN_OUTCOMES.set(req, pending);
  return pending;
}
async function enforceAdminCentralBan(req) {
  const authority = adminCentralBanAuthority();
  let result; try { result = authority ? await authority.check(req) : null; } catch (_) { result = null; }
  if (!result || result.ok !== true || typeof result.blocked !== 'boolean') fail('ADMIN_CENTRAL_BAN_CHECK_UNAVAILABLE', 503);
  if (result.blocked) {
    if (!Number.isSafeInteger(result.blocked_until_ms) || result.blocked_until_ms <= Date.now()) fail('ADMIN_CENTRAL_BAN_CHECK_UNAVAILABLE', 503);
    ADMIN_BAN_OUTCOMES.set(req, Promise.resolve(result));
    fail('ADMIN_SECURITY_BLOCKED', 403);
  }
}
function adminBanResponse(res, error, centralBan) {
  if (!centralBan || centralBan.ok !== true) {
    const unavailable = errorPayload({ code: 'ADMIN_CENTRAL_BAN_PERSISTENCE_UNAVAILABLE', status: 503 });
    unavailable.body.central_ban = false; unavailable.body.ban_persisted = false;
    return res.status(unavailable.status).json(unavailable.body);
  }
  const result = errorPayload(error), confirmed = centralBan.skipped !== true && centralBan.blocked === true;
  if (confirmed) {
    res.setHeader('X-Dirac-Central-Ban', '1');
    res.setHeader('Retry-After', String(Math.max(1, Math.ceil((centralBan.blocked_until_ms - Date.now()) / 1000))));
  }
  result.body.central_ban = confirmed; result.body.ban_persisted = confirmed;
  return res.status(result.status).json(result.body);
}
function allowedAdminKey(key) { return typeof key === 'string' && /^s2s-admin-v405:(?:ticket:[a-f0-9]{64}(?::used)?|enrollment:[a-f0-9]{64}|totp-used:[a-f0-9]{64}|rate:[a-f0-9]{64})$/.test(key); }
async function replaceEnrollment(records, key, expectedRevision, record, ttl) {
  const previous = records.get(key), expectedTtl = record && record.enrollmentState === 'pending_totp' ? PENDING_ENROLLMENT_SECONDS : ENROLLMENT_SECONDS;
  if (!enrollmentKey(key) || !previous || previous.revision !== expectedRevision || !record || record.revision === expectedRevision || ttl !== expectedTtl) fail('ADMIN_STORAGE_COMPARE_INVALID', 503);
  const next = validateDurableEnrollment(key, record);
  // Compare-and-swap on a revision, not a timestamp; enrollment has no TTL.
  const path = '/rest/v1/' + ADMIN_PASSKEY_TABLE + '?security_key=eq.' + encodeURIComponent(key) + '&revision=eq.' + encodeURIComponent(expectedRevision) + '&select=security_key,revision';
  const result = await dbFetch(path, { method: 'PATCH', prefer: 'return=representation', body: { revision: next.revision, record_json: next, updated_at: new Date().toISOString() } }, 'security');
  assertPasskeyStoreResultV454(result, 'replace');
  if (!result.data.length) return false;
  if (result.data[0].security_key !== key || result.data[0].revision !== next.revision) fail('ADMIN_PASSKEY_WRITE_UNVERIFIED', 503);
  records.set(key, { revision: next.revision });
  return true;
}
function buildOps(req, res, state) {
  const records = new Map(), secretState = adminSecretState(), identity = Object.freeze({ email: ADMIN_EMAIL, userId: ADMIN_USER_ID, active: true, role: 'owner', origin: state.origin, binding: secretState.configured ? scopeBinding(state.origin, state.device, secretState.secret) : digest('unconfigured:' + state.origin + ':' + state.device) });
  let active = true; const assertFullGuard = () => { if (!active || state.req !== req || state.method !== String(req.method || '').toUpperCase() || state.action !== state.currentAction || state.origin !== sourceOrigin(req) || state.device !== deviceFingerprint(req, state.origin)) fail('ADMIN_FULL_GUARD_REQUIRED', 503); };
  const ops = Object.freeze({
    version: VERSION, action: state.action, method: state.method, identity, body: state.body, assertFullGuard,
    deriveKey: purpose => { assertFullGuard(); if (purpose !== 'totp-storage') fail('ADMIN_KEY_PURPOSE_INVALID', 503); const key = deriveSecret('admin-v405-totp-storage'); try { return crypto.createHmac('sha256', key).update(ADMIN_USER_ID).digest(); } finally { key.fill(0); } },
    read: async key => { assertFullGuard(); if (!allowedAdminKey(key)) fail('ADMIN_STORAGE_KEY_INVALID', 503); const result = enrollmentKey(key) ? await durableEnrollmentRead(key) : await securityRead(key); assertFullGuard(); if (result.ok && result.found) records.set(key, { revision: result.record.revision, expiresAt: result.expiresAt }); return result; },
    claim: async (key, record, ttl) => { assertFullGuard(); if (!allowedAdminKey(key) || !record || record.version !== VERSION) fail('ADMIN_STORAGE_CLAIM_INVALID', 503); const result = enrollmentKey(key) ? await durableEnrollmentClaim(key, record) : await securityClaim(key, record, ttl); assertFullGuard(); if (result && enrollmentKey(key)) records.set(key, { revision: record.revision }); return result; },
    replace: async (key, expectedRevision, record, ttl) => { assertFullGuard(); const result = await replaceEnrollment(records, key, expectedRevision, record, ttl); assertFullGuard(); return result; },
    takeRate: async (key, limit, seconds) => { assertFullGuard(); const actionPasskeyHourly = state.action === 'admin_action_passkey_start' && limit === 30 && seconds === 3600; if (!allowedAdminKey(key) || !key.startsWith(PREFIX + 'rate:') || !Number.isInteger(limit) || limit < 1 || (limit > 5 && !actionPasskeyHourly) || ![60, 600, 3600].includes(seconds)) fail('ADMIN_RATE_CONTRACT_INVALID', 503); const result = await atomicRate(key, limit, seconds); assertFullGuard(); return result; },
    mail: async message => { assertFullGuard(); const loginMail = state.action === 'admin_email_start' && message && message.kind === 'login' && message.operation === ''; if (!loginMail || message.to !== ADMIN_EMAIL || !validAdminEmailCode(message.code) || !/^[a-f0-9]{24}$/.test(message.reference) || !Number.isSafeInteger(message.expiresAt) || message.expiresAt <= Date.now() || message.expiresAt > Date.now() + EMAIL_CODE_SECONDS * 1000 + 5000) fail('ADMIN_MAIL_CONTRACT_INVALID', 503); const result = await sendAdminMail({ ...message, origin: state.origin }); assertFullGuard(); return result; },
    recoveryAlert: async message => { assertFullGuard(); if (state.action !== 'admin_passkey_recovery_start' || !message || message.to !== ADMIN_EMAIL || message.kind !== 'recovery' || message.event !== 'started' || message.origin !== state.origin || !/^[a-f0-9]{24}$/.test(String(message.reference || ''))) fail('ADMIN_MAIL_CONTRACT_INVALID', 503); const result = await sendAdminMail(message); assertFullGuard(); return result; },
    verifyRegistration: input => { assertFullGuard(); if (!['admin_passkey_verify', 'admin_passkey_recovery_verify'].includes(state.action) || input.rpId !== new URL(state.origin).hostname) fail('ADMIN_PASSKEY_SCOPE_INVALID', 403); return verifyRegistration(input); },
    verifyAssertion: input => { assertFullGuard(); if (!['admin_passkey_verify', 'admin_action_passkey_verify'].includes(state.action) || input.rpId !== new URL(state.origin).hostname) fail('ADMIN_PASSKEY_SCOPE_INVALID', 403); return verifyAssertion(input); },
    readSession: () => { assertFullGuard(); return cookieToken(req, SESSION_COOKIE); },
    setSession: (token, seconds) => { assertFullGuard(); if (state.action !== 'admin_totp_verify' || !exactToken(token) || seconds !== SESSION_SECONDS) fail('ADMIN_SESSION_PUBLICATION_INVALID', 503); appendCookie(res, SESSION_COOKIE + '=' + token + '; Path=/; Secure; HttpOnly; SameSite=Strict'); },
    clearSession: async () => { assertFullGuard(); if (state.action !== 'admin_logout') fail('ADMIN_SESSION_CLEAR_INVALID', 503); if (await revokePasswordProof(state.passwordAuthority) !== true) fail('ADMIN_PROOF_REVOCATION_UNVERIFIED', 503); appendCookie(res, SESSION_COOKIE + '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'); appendCookie(res, PASSWORD_COOKIE + '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'); },
    verifySecret: value => { assertFullGuard(); const current = adminSecretState(); return current.configured && typeof value === 'string' && safeEqual(digest(value), digest(current.secret)); },
    publishPassword: async () => { assertFullGuard(); const current = adminSecretState(); if (!current.configured) fail('ADMIN_CREDENTIAL_NOT_CONFIGURED', 503); await publishPasswordProof(req, res, state.origin, state.device, current.secret); },
    securityReport: async report => { assertFullGuard(); if (state.action !== 'admin_security_report' || !report || report.evidenceHash === undefined) fail('ADMIN_SECURITY_REPORT_INVALID', 400); const centralBan = await adminCentralBanFailure(req, Object.assign(new Error('ADMIN_SECURITY_REPORT_ONE_STRIKE'), { code: 'ADMIN_SECURITY_REPORT_ONE_STRIKE', status: 403, statusCode: 403 })); if (!centralBan || centralBan.ok !== true) fail('ADMIN_CENTRAL_BAN_PERSISTENCE_UNAVAILABLE', 503); assertFullGuard(); res.setHeader('Retry-After', String(SECURITY_BLOCK_SECONDS)); res.setHeader('X-Dirac-Central-Ban', '1'); return { blockedUntil: centralBan.blocked_until_ms, central_ban: true }; },
    business: async (operation, body) => { assertFullGuard(); if (!state.passwordAuthority || !['orders', 'shipment_update', 'shipment_cancel', 'blocks', 'unban', 'smtp_send', 'local_authorize', 'monitor'].includes(operation)) fail('ADMIN_THREE_FACTORS_REQUIRED', 403); const result = await business(operation, body, state.origin, assertFullGuard); assertFullGuard(); return result; }
  });
  state.deactivate = () => { active = false; records.clear(); };
  return ops;
}

function setCommonHeaders(res, origin) {
  res.setHeader('Cache-Control', 'no-store, max-age=0'); res.setHeader('Pragma', 'no-cache'); res.setHeader('Expires', '0'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin'); res.setHeader('Vary', 'Origin'); res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Access-Control-Allow-Credentials', 'true'); res.setHeader('Access-Control-Expose-Headers', 'X-Dirac-CSRF-Token, X-Dirac-Page-Nonce, X-Dirac-Central-Ban, Retry-After'); res.setHeader('Content-Type', 'application/json; charset=utf-8');
}
function queryObject(query) { const out = {}; query.forEach((value, key) => { if (Object.prototype.hasOwnProperty.call(out, key)) fail('ADMIN_QUERY_DUPLICATE', 400); out[key] = value; }); return out; }
async function readJsonBody(req, maximum) {
  const contentType = String(req.headers && req.headers['content-type'] || '').trim().toLowerCase(); if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/.test(contentType)) fail('ADMIN_CONTENT_TYPE_INVALID', 415);
  if (String(req.headers && req.headers['transfer-encoding'] || '').trim()) fail('ADMIN_BODY_FRAMING_INVALID', 400);
  const encoding = String(req.headers && req.headers['content-encoding'] || '').trim().toLowerCase(); if (encoding && encoding !== 'identity') fail('ADMIN_CONTENT_TYPE_INVALID', 415);
  const declared = String(req.headers && req.headers['content-length'] || '').trim(); if (declared && !/^(?:0|[1-9][0-9]{0,11})$/.test(declared)) fail('ADMIN_BODY_FRAMING_INVALID', 400); if (declared && Number(declared) > maximum) fail('ADMIN_BODY_TOO_LARGE', 413);
  const chunks = []; let size = 0;
  await new Promise((resolve, reject) => {
    let settled = false, timer;
    const cleanup = () => { clearTimeout(timer); req.off('data', onData); req.off('end', onEnd); req.off('error', onError); req.off('aborted', onAborted); req.off('close', onAborted); };
    const finish = callback => { if (settled) return; settled = true; cleanup(); callback(); };
    const rejectCode = (code, status) => finish(() => { if (typeof req.pause === 'function') req.pause(); chunks.length = 0; reject(Object.assign(new Error(code), { code, status, statusCode: status })); });
    const onData = chunk => { if (settled) return; const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); size += bytes.length; if (size > maximum) { rejectCode('ADMIN_BODY_TOO_LARGE', 413); return; } chunks.push(bytes); };
    const onEnd = () => finish(resolve);
    const onError = () => rejectCode('ADMIN_BODY_INVALID', 400);
    const onAborted = () => rejectCode('ADMIN_BODY_INVALID', 400);
    if (req.aborted === true || req.destroyed === true || req.readableEnded === true) { rejectCode('ADMIN_BODY_INVALID', 400); return; }
    timer = setTimeout(() => rejectCode('ADMIN_BODY_TIMEOUT', 408), 6500);
    req.on('data', onData); req.on('end', onEnd); req.on('error', onError); req.on('aborted', onAborted); req.on('close', onAborted);
  });
  if (declared && size !== Number(declared)) fail('ADMIN_BODY_FRAMING_INVALID', 400);
  let data, source; try { source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks)); data = JSON.parse(source); } catch (_) { fail('ADMIN_BODY_INVALID', 400); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) fail('ADMIN_BODY_INVALID', 400);
  const containers = [], tokens = Array.from(source.matchAll(/"(?:[^"\\]|\\[\s\S])*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\]]/g));
  if (tokens.length > 4096) fail('ADMIN_BODY_TOO_COMPLEX', 413);
  tokens.forEach(match => {
    const token = match[0];
    if (token === '{' || token === '[') { containers.push(token === '{' ? new Set() : null); if (containers.length > 12) fail('ADMIN_BODY_TOO_COMPLEX', 413); }
    else if (token === '}' || token === ']') containers.pop();
    else if (token[0] === '"') {
      const value = JSON.parse(token); if (/[\u0000\ud800-\udfff]/u.test(value)) fail('ADMIN_BODY_INVALID', 400);
      if (/^[\x20\t\r\n]*:/.test(source.slice(match.index + token.length))) {
        const names = containers[containers.length - 1];
        if (!names || names.has(value) || ['__proto__', 'prototype', 'constructor'].includes(value)) fail('ADMIN_BODY_KEY_INVALID', 400);
        names.add(value);
      }
    } else if (/^-?\d/.test(token)) {
      const value = Number(token); if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) fail('ADMIN_BODY_INVALID', 400);
    }
  });
  return data;
}
function validateShape(action, method, query, body) {
  const contract = CONTRACTS[action]; if (!contract || !contract.methods.includes(method)) fail('ADMIN_METHOD_NOT_ALLOWED', 405); const allowed = new Set(contract.allowed);
  if (Object.keys(query).some(key => !allowed.has(key))) fail('ADMIN_QUERY_FIELD_INVALID', 400);
  if (method === 'POST') { if (Object.keys(body).some(key => !allowed.has(key))) fail('ADMIN_BODY_FIELD_INVALID', 400); if (contract.required.some(key => !Object.prototype.hasOwnProperty.call(body, key))) fail('ADMIN_BODY_REQUIRED_FIELD', 400); if (body.action !== undefined && body.action !== action) fail('ADMIN_ACTION_MISMATCH', 400); }
  const source = method === 'POST' ? body : query; if (Object.entries(source).some(([key, value]) => Array.isArray(value) && !(contract.allowArrayItems && key === 'transports'))) fail('ADMIN_BODY_FIELD_INVALID', 400); if (Object.values(source).some(value => typeof value === 'string' && Buffer.byteLength(value, 'utf8') > contract.maxFieldBytes)) fail('ADMIN_FIELD_TOO_LARGE', 413);
}
function errorPayload(error) {
  const known = error && (/^ADMIN_[A-Z0-9_]{1,90}$/.test(String(error.code || '')) || String(error.code || '') === 'SECURITY_REPORT_EVIDENCE_REJECTED' || ['SHIPMENT_BUSY', 'SHIPMENT_CONFIG_REQUIRED', 'SHIPMENT_SMTP_NOT_CONFIGURED', 'SHIPMENT_CUSTOMER_EMAIL_REQUIRED', 'SHIPMENT_TRACKING_ID_REQUIRED', 'SHIPMENT_ENDPOINT_INVALID', 'SHIPMENT_CONFIG_INVALID', 'SHIPMENT_OPTIONS_INVALID', 'SHIPMENT_OPTIONS_REQUIRED', 'SHIPMENT_STATE_INVALID', 'SHIPMENT_CONFIG_WRITE_UNCONFIRMED', 'SHIPMENT_CONFIG_UNAVAILABLE'].includes(String(error.code || ''))), supplied = Number(error && (error.status || error.statusCode) || 503), status = known && ALLOWED_RESPONSE_STATUSES.has(supplied) ? supplied : 503;
  return { status, body: { ok: false, code: known ? error.code : 'ADMIN_OPERATION_UNAVAILABLE', message: status === 503 ? 'Layanan admin belum dapat diverifikasi. Periksa konfigurasi yang diwajibkan lalu coba kembali.' : status === 429 ? 'Batas percobaan tercapai. Tunggu sebelum mencoba lagi.' : 'Verifikasi admin belum valid atau sudah kedaluwarsa.' } };
}
async function adminBusiness(req, res, operations) {
  try { return res.status(200).json(await execute(operations)); }
  catch (error) {
    const centralBan = await adminCentralBanFailure(req, error);
    return adminBanResponse(res, error, centralBan);
  }
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
    // Nonces and logout do not grant access; avoid an extra DB read for each nonce bootstrap.
    // All substantive admin requests (including reports) consult the SAME central authority.
    if (adminSecretState().configured && !['admin_entry', 'admin_logout'].includes(action)) await enforceAdminCentralBan(req);
    const device = deviceFingerprint(req, origin);
    if (adminSecretState().configured && !['admin_entry', 'admin_security_report', 'admin_logout'].includes(action)) {
      const blocked = await activeSecurityBlock(origin, device);
      if (blocked) {
        adminBlockDiagnosticLogV446('request_blocked', {
          action,
          method,
          remaining_ms: Math.max(0, blocked.blockedUntil - Date.now()),
          created_age_ms: Math.max(0, Date.now() - blocked.createdAt),
          origin_hash: digest(origin).slice(0, 24),
          device_hash: digest(device).slice(0, 24)
        });
        res.setHeader('Retry-After', String(Math.max(1, Math.ceil((blocked.blockedUntil - Date.now()) / 1000)))); fail('ADMIN_SECURITY_BLOCKED', 403);
      }
    }
    const contract = CONTRACTS[action], query = queryObject(queryParams), body = method === 'POST' ? await readJsonBody(req, contract.maxBodyBytes) : query; validateShape(action, method, query, body);
    const currentAction = action, state = { req, action, currentAction, method, origin, device, body, passwordAuthority: null, deactivate: null };
    if (method === 'POST') await verifyPageNonce(req, action, origin, device);
    if (!['admin_entry', 'admin_security_report', 'admin_login'].includes(action)) state.passwordAuthority = await verifyPasswordProof(req, origin, device, ['admin_email_start', 'admin_email_verify', 'admin_passkey_start', 'admin_passkey_verify', 'admin_passkey_recovery_start', 'admin_passkey_recovery_verify', 'admin_totp_verify'].includes(action));
    if (action === 'admin_entry') {
      const target = String(query._dirac_page_nonce_for || ''); if (target) { if (!CONTRACTS[target] || !CONTRACTS[target].methods.includes('POST')) fail('ADMIN_NONCE_TARGET_INVALID', 400); const proof = issuePageNonce(target, origin, device); res.setHeader('X-Dirac-CSRF-Token', proof.csrf); res.setHeader('X-Dirac-Page-Nonce', proof.nonce); }
    }
    const ops = buildOps(req, res, state);
    try { const payload = await execute(ops); if (method === 'HEAD') return res.status(200).end(); return res.status(200).json(payload); }
    finally { if (state.deactivate) state.deactivate(); }
  } catch (error) {
    const centralBan = await adminCentralBanFailure(req, error);
    try { if (origin) setCommonHeaders(res, origin); else { res.setHeader('Cache-Control', 'no-store'); res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('X-Content-Type-Options', 'nosniff'); } } catch (_) {}
    return adminBanResponse(res, error, centralBan);
  }
}
Object.defineProperties(adminHandler, {
  config: { value: Object.freeze({ api: Object.freeze({ bodyParser: false }) }), enumerable: true },
  __diracAdminBusinessV405: { value: adminBusiness },
  __diracShipmentDailyV450: { value: shipmentDailyV450 },
  __diracShipmentDataV453: { value: Object.freeze({ validate: shipmentExtrasCheckV453, validateRow: validateShipmentRow, receipt: shipmentReceiptPublicV453, deliveryRef: shipmentDeliveryRefV453, event: shipmentEventPublicV453, buildReceipt: shipmentReceiptBuildV453 }) },
  __diracAdminContractsV405: { value: CONTRACTS },
  __diracAdminActionsV405: { value: ACTIONS },
  __diracAdminEmailV405: { value: ADMIN_EMAIL },
  __diracAdminVersionV405: { value: VERSION },
  __diracAdminStandaloneV411: { value: true },
  __diracAdminSelfTestV411: { value: Object.freeze({ ok: true, healthDependency: true, adminTableDependency: true, newEnvironmentNames: false, durablePasskeyTable: ADMIN_PASSKEY_TABLE }) }
});
module.exports = Object.freeze(adminHandler);

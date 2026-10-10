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
  admin_orders: get(['kind', 'offset', 'view', 'from', 'until']),
  admin_shipment_update: post(['kind', 'order_id', 'expected_revision', 'tracking_number', 'courier', 'status', 'location', 'origin', 'destination', 'estimated_delivery', 'description', 'tracking_options', 'review_ack', 'review_reason', 'approval'], ['kind', 'order_id', 'expected_revision', 'tracking_number', 'courier', 'status', 'approval']),
  admin_shipment_cancel: post(['kind', 'order_id', 'expected_revision', 'description', 'review_ack', 'review_reason', 'approval'], ['kind', 'order_id', 'expected_revision', 'approval']),
  admin_blocks: get(['offset']),
  admin_banned_data: get(['export_ref']),
  admin_unban: post(['block_id', 'approval'], ['block_id', 'approval']),
  admin_banned_pdf: Object.freeze({ methods: Object.freeze(['POST']), allowed: Object.freeze(['action', ...COMMON_PROOF, 'export_ref', 'mode', 'raw_pdf_base64', 'raw_pdf_sha256', 'approval']), required: Object.freeze(['export_ref', 'mode', 'raw_pdf_base64', 'raw_pdf_sha256', 'approval']), maxBodyBytes: 5700000, maxFieldBytes: 5500000, mutation: true, allowArrayItems: false }),
  admin_account_create: post(['role', 'email', 'name', 'phone', 'partner_request_id', 'approval'], ['email', 'approval']),
  admin_account_disable: post(['email', 'approval'], ['email', 'approval']),
  admin_account_enable: post(['email', 'approval'], ['email', 'approval']),
  admin_account_delete: post(['email', 'approval'], ['email', 'approval']),
  admin_account_password_reset: post(['email', 'approval'], ['email', 'approval']),
  admin_account_passkey_reset: post(['email', 'approval'], ['email', 'approval']),
  admin_partner_requests: get(),
  admin_partner_request_update: post(['request_id', 'status', 'note', 'approval'], ['request_id', 'status', 'approval']),
  admin_smtp_send: Object.freeze({ methods: Object.freeze(['POST']), allowed: Object.freeze(['action', ...COMMON_PROOF, 'provider', 'recipients', 'recipient_count', 'recipients_sha256', 'subject', 'subject_sha256', 'body_text', 'body_sha256', 'document_kind', 'attachment_name', 'attachment_type', 'attachment_base64', 'attachment_sha256', 'legal_confirm', 'approval']), required: Object.freeze(['provider', 'recipients', 'recipient_count', 'recipients_sha256', 'subject', 'subject_sha256', 'body_text', 'body_sha256', 'document_kind', 'attachment_name', 'attachment_type', 'attachment_base64', 'attachment_sha256', 'legal_confirm', 'approval']), maxBodyBytes: ADMIN_SMTP_BODY_MAX_BYTES, maxFieldBytes: ADMIN_SMTP_BODY_MAX_BYTES, mutation: true, allowArrayItems: false }),
  admin_local_authorize: post(['purpose', 'content_sha256', 'approval'], ['purpose', 'content_sha256', 'approval']),
  admin_document_prepare: post(['document_kind','reference','page_count','content_sha256','approval'], ['document_kind','reference','page_count','content_sha256','approval']),
  admin_document_seal: Object.freeze({ methods: Object.freeze(['POST']), allowed: Object.freeze(['action', ...COMMON_PROOF, 'identity','format','page','raw_sha256','file_base64','approval']), required: Object.freeze(['identity','format','page','raw_sha256','file_base64','approval']), maxBodyBytes: 4250000, maxFieldBytes: 4194304, mutation: true, allowArrayItems: false }),
  admin_document_verify: get(['file_sha256','document_id','qr_proof']),
  admin_monitor: get(['view', 'from', 'until'])
});
const ACTIONS = Object.freeze(Object.keys(CONTRACTS));
const ADMIN_ACCOUNT_ACTION_MODES = Object.freeze({ admin_account_create: 'create', admin_account_disable: 'disable', admin_account_enable: 'enable', admin_account_delete: 'delete', admin_account_password_reset: 'reset_password', admin_account_passkey_reset: 'reset_passkey' });
const ADMIN_APPROVAL_MUTATIONS = Object.freeze({ admin_shipment_update: 'shipment_update', admin_shipment_cancel: 'shipment_cancel', admin_unban: 'unban', admin_banned_pdf: 'banned_pdf', admin_account_create: 'account_create', admin_account_disable: 'account_disable', admin_account_enable: 'account_enable', admin_account_delete: 'account_delete', admin_account_password_reset: 'account_password_reset', admin_account_passkey_reset: 'account_passkey_reset', admin_partner_request_update: 'partner_request_update', admin_smtp_send: 'smtp_send', admin_local_authorize: 'local_authorize', admin_document_prepare: 'document_prepare', admin_document_seal: 'document_seal' });
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
function maskedAdminEmail() {
  const value = String(ADMIN_EMAIL || '').trim().toLowerCase(), split = value.lastIndexOf('@');
  if (split <= 0 || split >= value.length - 1) return 'a***@***';
  const local = value.slice(0, split), domain = value.slice(split + 1), dot = domain.lastIndexOf('.'), host = dot > 0 ? domain.slice(0, dot) : domain, suffix = dot > 0 ? domain.slice(dot) : '';
  return local.slice(0, 1) + '*'.repeat(Math.max(3, Math.min(12, local.length - 2))) + (local.length > 1 ? local.slice(-1) : '') + '@' + host.slice(0, 1) + '***' + suffix;
}
const ADMIN_EMAIL_MASKED = maskedAdminEmail();
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
const ADMIN_OWNER_V466 = digest('dirac-admin-fixed-owner-v466');
function legacyAdminOwnerV466() { return digest(ADMIN_EMAIL + ':' + ADMIN_USER_ID); }

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
  try {
    const index = hash[hash.length - 1] & 15;
    return String((hash.readUInt32BE(index) & 0x7fffffff) % 1000000).padStart(6, '0');
  } finally { hash.fill(0); message.fill(0); }
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
function open(ops, value, context, keyPurpose = 'totp-storage') {
  const key = keyPurpose === 'totp-storage' ? encryptionKey(ops) : ops.deriveKey(keyPurpose); let plaintext = null, tail = null;
  if (!Buffer.isBuffer(key) || key.length !== 32) fail('ADMIN_SECRET_UNAVAILABLE', 503);
  try {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) fail('ADMIN_STATE_INVALID', 503);
    const parts = value.split('.').map(v => decodeB64url(v, 64));
    if (parts[0].length !== 12 || parts[1].length !== 32 || parts[2].length !== 16) fail('ADMIN_STATE_INVALID', 503);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, parts[0]);
    decipher.setAAD(Buffer.from(VERSION + ':' + context)); decipher.setAuthTag(parts[2]);
    plaintext = decipher.update(parts[1]); tail = decipher.final();
    return Buffer.concat([plaintext, tail]);
  } catch (error) { if (error && error.code === 'ADMIN_SECRET_UNAVAILABLE') throw error; fail('ADMIN_STATE_INVALID', 503); }
  finally { key.fill(0); if (plaintext) plaintext.fill(0); if (tail) tail.fill(0); }
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
  const map = { customers: 'CORE', security_customer_auth_links: 'CUSTOMER_SECURITY', security_customer_sessions: 'CUSTOMER_SECURITY', domain_passkeys: 'DOMAIN', domain_orders: 'DOMAIN', domain_order_items: 'DOMAIN', orders: 'COMMERCE', order_items: 'COMMERCE', payment_transactions: 'PAYMENT_SERVICE', security_customer_account_requests: 'PAYMENT_SERVICE', security_customer_events: 'PAYMENT_SERVICE' };
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
async function readAdminUpstreamText(response, maximum, code) {
  const declared = String(response.headers.get('content-length') || '');
  const cancel = () => { try { if (response.body) Promise.resolve(response.body.cancel()).catch(() => {}); } catch (_) {} };
  if (declared && (!/^(?:0|[1-9][0-9]*)$/.test(declared) || Number(declared) > maximum)) { cancel(); fail(code, 503); }
  if (!response.body) return '';
  if (typeof response.body.pipeTo !== 'function') { cancel(); fail(code, 503); }
  let bytes = Buffer.allocUnsafe(Math.min(maximum, 16384));
  let size = 0;
  try {
    await response.body.pipeTo(new WritableStream({
      write(part) {
        if (!(part instanceof Uint8Array) || !part.byteLength) fail(code, 503);
        const nextSize = size + part.byteLength;
        if (nextSize > maximum) fail(code, 503);
        if (nextSize > bytes.length) {
          const expanded = Buffer.allocUnsafe(Math.min(maximum, Math.max(nextSize, bytes.length * 2)));
          bytes.copy(expanded, 0, 0, size);
          bytes.fill(0, 0, size);
          bytes = expanded;
        }
        bytes.set(part, size);
        size = nextSize;
      }
    }));
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size)); }
    catch (_) { fail(code, 503); }
  } finally {
    bytes.fill(0, 0, size);
  }
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
    const raw = await readAdminUpstreamText(response, MAX_RESPONSE_BYTES, 'ADMIN_DATABASE_RESPONSE_INVALID');
    let data = null; if (raw) { try { data = JSON.parse(raw); } catch (_) { fail('ADMIN_DATABASE_RESPONSE_INVALID', 503); } }
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    if (error && /^ADMIN_/.test(String(error.code || ''))) throw error;
    return { ok: false, status: 0, data: null, diagnostic_transport: { name: String(error && error.name || '').slice(0, 120), code: String(error && error.code || '').slice(0, 120), message: String(error && error.message || '').slice(0, 700), aborted: !!(error && (error.name === 'AbortError' || error.code === 'ABORT_ERR')) } };
  } finally { clearTimeout(timer); }
}
async function authAdminUserRequest(path, method, body) {
  const cleanPath = String(path || '');
  const verb = String(method || 'GET').toUpperCase();
  if (!(cleanPath === '/auth/v1/admin/users' || /^\/auth\/v1\/admin\/users\/[0-9a-f-]{36}$/i.test(cleanPath) || /^\/auth\/v1\/admin\/users\?filter=[A-Za-z0-9.!%_+\-]+(?:%40|@)[A-Za-z0-9.%_+\-]+$/i.test(cleanPath))
      || !['GET','POST','PUT','DELETE'].includes(verb)
      || ((verb === 'POST' || verb === 'PUT') && (!body || typeof body !== 'object' || Array.isArray(body)))
      || ((verb === 'GET' || verb === 'DELETE') && body !== undefined)) fail('ADMIN_AUTH_REQUEST_INVALID', 503);
  const creds = legacyCredentials();
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 12000);
  try {
    const headers = { apikey: creds.service, Authorization: 'Bearer ' + creds.service, Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await ADMIN_STANDALONE_FETCH(creds.url + cleanPath, {
      method: verb,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: controller.signal
    });
    const raw = await readAdminUpstreamText(response, 262144, 'ADMIN_AUTH_RESPONSE_INVALID');
    let data = null; if (raw) { try { data = JSON.parse(raw); } catch (_) { fail('ADMIN_AUTH_RESPONSE_INVALID', 503); } }
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    if (error && /^ADMIN_/.test(String(error.code || ''))) throw error;
    return { ok: false, status: 0, data: null, diagnostic_transport: { name: String(error && error.name || '').slice(0, 120), code: String(error && error.code || '').slice(0, 120), message: String(error && error.message || '').slice(0, 700), aborted: !!(error && (error.name === 'AbortError' || error.code === 'ABORT_ERR')) } };
  } finally { clearTimeout(timer); }
}
function adminAccountMutationPayload(value) {
  const row = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const mode = String(row.mode || 'create').trim().toLowerCase();
  const email = String(row.email || '').trim().toLowerCase();
  if (!['create','disable','enable','delete','reset_password','reset_passkey'].includes(mode) || !isEmail(email) || email.length > 120
      || !/^[a-z0-9]+(?:\.[a-z0-9]+)*@[a-z0-9]+(?:\.[a-z0-9]+)+$/.test(email)) fail('ADMIN_ACCOUNT_INPUT_INVALID', 400);
  if (mode !== 'create') {
    if (String(row.role || '').trim() || String(row.name || '').trim() || String(row.phone || '').trim() || String(row.partner_request_id || '').trim()) fail('ADMIN_ACCOUNT_INPUT_INVALID', 400);
    return { mode, email };
  }
  const role = String(row.role || '').trim().toLowerCase();
  const name = String(row.name || '').trim();
  const phone = String(row.phone || '').trim().replace(/[ .()\-]/g, '');
  const partnerRequestId = String(row.partner_request_id || '').trim().toLowerCase();
  if (!['reseller','partner'].includes(role)
      || name.length < 3 || name.length > 120 || /[\x00-\x1f\x7f\u202A-\u202E\u2066-\u2069]/.test(name)
      || (phone && !/^\+?[0-9]{8,16}$/.test(phone))
      || (partnerRequestId && (!isUuid(partnerRequestId) || role !== 'reseller'))) fail('ADMIN_ACCOUNT_INPUT_INVALID', 400);
  return { mode, role, email, name, phone, partner_request_id: partnerRequestId };
}
function adminAccountBaseDomainFromOrigin(origin) {
  let url; try { url = new URL(String(origin || '')); } catch (_) { fail('ADMIN_ACCOUNT_DOMAIN_INVALID', 400); }
  let host = String(url.hostname || '').trim().toLowerCase().replace(/\.$/, '');
  if (url.protocol !== 'https:' || !host) fail('ADMIN_ACCOUNT_DOMAIN_INVALID', 400);
  if (host.startsWith('pt.')) host = host.slice(3);
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host)) fail('ADMIN_ACCOUNT_DOMAIN_INVALID', 400);
  return host;
}
function adminAccountEmailForOrigin(email, origin) {
  const value = String(email || '').trim().toLowerCase();
  adminAccountBaseDomainFromOrigin(origin);
  if (!isEmail(value) || value.length > 120 || /[\r\n\u0000-\u001f\u007f]/.test(value)) fail('ADMIN_ACCOUNT_DOMAIN_INVALID', 400);
  return value;
}
function adminAccountExactUser(data, email) {
  let candidate = null;
  const rows = Array.isArray(data) ? data : data && Array.isArray(data.users) ? data.users : null;
  if (rows) {
    const matches = rows.filter(row => row && typeof row === 'object' && String(row.email || '').trim().toLowerCase() === email);
    if (matches.length !== 1) return null;
    candidate = matches[0];
  }
  else if (data && data.user && typeof data.user === 'object') candidate = data.user;
  else if (data && typeof data === 'object' && data.id) candidate = data;
  return candidate && typeof candidate === 'object' && String(candidate.email || '').trim().toLowerCase() === email ? candidate : null;
}
function adminAccountRoleFromUser(user) {
  const meta = user && user.app_metadata && typeof user.app_metadata === 'object' && !Array.isArray(user.app_metadata) ? user.app_metadata : null;
  const role = meta && String(meta.dirac_account_role || '').trim().toLowerCase();
  return meta && meta.dirac_account_provisioned === true && meta.dirac_account_policy_version === 1 && ['reseller','partner'].includes(role) ? role : '';
}
function adminAccountBanned(user) {
  const raw = String(user && (user.banned_until || user.bannedUntil) || '').trim();
  if (!raw) return false;
  const until = Date.parse(raw);
  return Number.isFinite(until) && until > Date.now();
}
function adminAccountProvisionMetadata(role, partnerInvite) {
  return { dirac_account_role: role, dirac_account_provisioned: true, dirac_account_policy_version: 1,
    ...(partnerInvite ? { dirac_parent_partner_customer_id: partnerInvite.customer_id, dirac_partner_request_id: partnerInvite.id } : {}) };
}
function adminAccountProfileMetadata(name, phone) { return { name, full_name: name, phone }; }
function adminAccountUserUpgradeable(user, email) {
  return !!(user && isUuid(user.id) && String(user.email || '').trim().toLowerCase() === email && !adminAccountRoleFromUser(user)
    && !String(user.deleted_at || '').trim() && !String(user.disabled_at || '').trim()
    && user.disabled !== true && user.is_disabled !== true && user.is_anonymous !== true);
}
function adminAccountLabel(role) { return role === 'reseller' ? 'Reseller / Distributor Resmi' : 'Partner'; }
function adminBusinessAccountPublicV479(user) {
  const role = adminAccountRoleFromUser(user), email = String(user && user.email || '').trim().toLowerCase();
  if (!role || !user || !isUuid(user.id) || !isEmail(email) || String(user.deleted_at || '').trim() || user.is_anonymous === true) return null;
  const meta = user.user_metadata && typeof user.user_metadata === 'object' && !Array.isArray(user.user_metadata) ? user.user_metadata : {};
  const accountActive = !(adminAccountBanned(user) || String(user.disabled_at || '').trim() || user.disabled === true || user.is_disabled === true);
  return { user_id: String(user.id).toLowerCase(), email, account_role: role, account_label: adminAccountLabel(role), account_active: accountActive, name: String(meta.name || meta.full_name || '').trim().slice(0, 120), phone: String(meta.phone || '').trim().slice(0, 24), created_at: String(user.created_at || '').slice(0, 48) };
}
const ADMIN_ACCOUNT_DELETE_DIAGNOSTIC_V489 = 'dirac-admin-account-delete-diagnostic-v489';
function adminAccountDiagnosticTextV489(value, max = 700) {
  return String(value || '')
    .replace(/https?:\/\/[^\s\"']+/gi, '<url>')
    .replace(/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/gi, '<email>')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<uuid>')
    .replace(/[A-Za-z0-9_-]{43,}/g, '<token>')
    .slice(0, max);
}
function adminAccountDiagnosticRouteV489(table) {
  const alias = table === 'domain_passkeys' ? 'DOMAIN' : (table === 'security_customer_auth_links' || table === 'security_customer_sessions' ? 'CUSTOMER_SECURITY' : 'LEGACY');
  if (alias === 'LEGACY' || !multiDbEnabled()) return 'legacy';
  const prefix = 'DIRAC_' + alias + '_SUPABASE_';
  const complete = !!(String(process.env[prefix + 'URL'] || '').trim() && String(process.env[prefix + 'ANON_KEY'] || '').trim() && String(process.env[prefix + 'SERVICE_ROLE_KEY'] || '').trim());
  return complete ? 'multi:' + alias : 'legacy_fallback:' + alias;
}
function adminAccountDeleteDiagnosticV489(stage, context) {
  try {
    const row = context && typeof context === 'object' && !Array.isArray(context) ? context : {};
    const result = row.result && typeof row.result === 'object' ? row.result : null;
    const arrayData = result && Array.isArray(result.data) ? result.data : null;
    const objectData = result && result.data && typeof result.data === 'object' && !Array.isArray(result.data) ? result.data : null;
    const first = arrayData && arrayData.length && arrayData[0] && typeof arrayData[0] === 'object' ? arrayData[0] : null;
    const transport = result && result.diagnostic_transport && typeof result.diagnostic_transport === 'object' ? result.diagnostic_transport : {};
    console.error('[' + ADMIN_ACCOUNT_DELETE_DIAGNOSTIC_V489 + '] ' + JSON.stringify({
      patch: ADMIN_ACCOUNT_DELETE_DIAGNOSTIC_V489,
      event: 'admin_account_delete_diagnostic',
      stage: String(stage || '').slice(0, 120),
      trace_ref: String(row.trace_ref || '').slice(0, 32),
      failure_stage: String(row.failure_stage || '').slice(0, 120),
      failure_code: String(row.failure_code || '').slice(0, 120),
      error_status: Number(row.error_status || 0),
      reason: String(row.reason || '').slice(0, 64),
      email_sha256_16: row.email ? digest(String(row.email).trim().toLowerCase()).slice(0, 16) : '',
      auth_user_sha256_16: row.auth_user_id ? digest(String(row.auth_user_id).trim().toLowerCase()).slice(0, 16) : '',
      customer_sha256_16: row.customer_id ? digest(String(row.customer_id).trim().toLowerCase()).slice(0, 16) : '',
      has_security_link: row.has_security_link === true,
      table: String(row.table || '').slice(0, 80),
      db_route: row.table ? adminAccountDiagnosticRouteV489(String(row.table)) : '',
      multi_db_enabled: multiDbEnabled(),
      request_method: String(row.request_method || '').toUpperCase().slice(0, 12),
      request_shape: String(row.request_shape || '').slice(0, 420),
      request_body_keys: String(row.request_body_keys || '').slice(0, 240),
      expected_row_count: Number.isInteger(row.expected_row_count) ? row.expected_row_count : -1,
      response_present: !!result,
      response_ok: result ? result.ok === true : false,
      response_status: result ? Number(result.status || 0) : 0,
      response_data_type: result ? (Array.isArray(result.data) ? 'array' : (result.data === null ? 'null' : typeof result.data)) : 'missing',
      response_row_count: arrayData ? arrayData.length : -1,
      response_object_keys: objectData ? Object.keys(objectData).sort().join(',').slice(0, 300) : '',
      first_row_keys: first ? Object.keys(first).sort().join(',').slice(0, 300) : '',
      first_row_has_id: !!(first && Object.prototype.hasOwnProperty.call(first, 'id')),
      first_row_has_user_id: !!(first && Object.prototype.hasOwnProperty.call(first, 'user_id')),
      first_row_is_active: first && Object.prototype.hasOwnProperty.call(first, 'is_active') ? first.is_active === true : null,
      first_row_rotation_state: first ? String(first.rotation_state || '').slice(0, 80) : '',
      first_row_revoked_at_present: !!(first && first.revoked_at),
      condition_result_present: row.condition_result_present === true,
      condition_ok_true: row.condition_ok_true === true,
      condition_data_array: row.condition_data_array === true,
      condition_row_count_match: row.condition_row_count_match === true,
      response_error_code: adminAccountDiagnosticTextV489(objectData && objectData.code, 160),
      response_error_message: adminAccountDiagnosticTextV489(objectData && objectData.message),
      response_error_details: adminAccountDiagnosticTextV489(objectData && objectData.details),
      response_error_hint: adminAccountDiagnosticTextV489(objectData && objectData.hint),
      transport_error_name: adminAccountDiagnosticTextV489(transport.name, 120),
      transport_error_code: adminAccountDiagnosticTextV489(transport.code, 120),
      transport_error_message: adminAccountDiagnosticTextV489(transport.message),
      transport_aborted: transport.aborted === true
    }));
  } catch (_) {}
}
async function adminAccountSecurityLinkV480(user, email, assertContext) {
  const authUserId = String(user && user.id || '').trim().toLowerCase(), normalizedEmail = String(email || '').trim().toLowerCase();
  if (!isUuid(authUserId) || !isEmail(normalizedEmail) || normalizedEmail !== String(user && user.email || '').trim().toLowerCase()) fail('ADMIN_ACCOUNT_SECURITY_STATE_INVALID', 503);
  const result = await dbFetch('/rest/v1/security_customer_auth_links?select=' + encodeURIComponent('id,auth_user_id,customer_id,email,link_status,disabled_at,revoked_at') + '&auth_user_id=eq.' + encodeURIComponent(authUserId) + '&link_status=eq.active&revoked_at=is.null&limit=2', { method: 'GET' });
  assertContext();
  if (!result || !result.ok || !Array.isArray(result.data) || result.data.length > 1) fail('ADMIN_ACCOUNT_SECURITY_STATE_UNAVAILABLE', 503);
  if (result.data.length === 0) return null;
  const row = result.data[0], linkId = String(row && row.id || '').trim().toLowerCase(), customerId = String(row && row.customer_id || '').trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(linkId) || !isUuid(customerId) || String(row && row.auth_user_id || '').trim().toLowerCase() !== authUserId || String(row && row.email || '').trim().toLowerCase() !== normalizedEmail || String(row && row.link_status || '').trim().toLowerCase() !== 'active' || row.revoked_at) fail('ADMIN_ACCOUNT_SECURITY_STATE_INVALID', 503);
  return { id: linkId, auth_user_id: authUserId, customer_id: customerId, email: normalizedEmail, link_status: 'active', disabled_at: row.disabled_at || null, revoked_at: null };
}
async function adminAccountSetLinkDisabledV480(link, disabled, assertContext) {
  if (!link) return false;
  if (disabled === true && link.disabled_at) return true;
  if (disabled === false && !link.disabled_at) return true;
  const nowIso = new Date().toISOString();
  const path = '/rest/v1/security_customer_auth_links?select=' + encodeURIComponent('id,auth_user_id,customer_id,email,link_status,disabled_at,revoked_at') + '&id=eq.' + encodeURIComponent(link.id) + '&auth_user_id=eq.' + encodeURIComponent(link.auth_user_id) + '&customer_id=eq.' + encodeURIComponent(link.customer_id) + '&email=eq.' + encodeURIComponent(link.email) + '&link_status=eq.active&revoked_at=is.null';
  const patched = await dbFetch(path, { method: 'PATCH', prefer: 'return=representation', body: { disabled_at: disabled ? nowIso : null, updated_at: nowIso } });
  assertContext();
  if (!patched || !patched.ok || !Array.isArray(patched.data) || patched.data.length !== 1) fail('ADMIN_ACCOUNT_SECURITY_STATE_UPDATE_FAILED', 503);
  const row = patched.data[0];
  if (String(row && row.id || '').trim().toLowerCase() !== link.id || String(row && row.auth_user_id || '').trim().toLowerCase() !== link.auth_user_id || String(row && row.customer_id || '').trim().toLowerCase() !== link.customer_id || String(row && row.email || '').trim().toLowerCase() !== link.email || String(row && row.link_status || '').trim().toLowerCase() !== 'active' || row.revoked_at || (disabled ? !row.disabled_at : !!row.disabled_at)) fail('ADMIN_ACCOUNT_SECURITY_STATE_UPDATE_UNCONFIRMED', 503);
  link.disabled_at = row.disabled_at || null;
  return true;
}
async function adminAccountRevokeLinkV480(link, assertContext) {
  if (!link) return false;
  const nowIso = new Date().toISOString();
  const path = '/rest/v1/security_customer_auth_links?select=' + encodeURIComponent('id,auth_user_id,customer_id,email,link_status,disabled_at,revoked_at') + '&id=eq.' + encodeURIComponent(link.id) + '&auth_user_id=eq.' + encodeURIComponent(link.auth_user_id) + '&customer_id=eq.' + encodeURIComponent(link.customer_id) + '&email=eq.' + encodeURIComponent(link.email) + '&link_status=eq.active&revoked_at=is.null';
  const patched = await dbFetch(path, { method: 'PATCH', prefer: 'return=representation', body: { disabled_at: nowIso, revoked_at: nowIso, updated_at: nowIso } });
  assertContext();
  if (!patched || !patched.ok || !Array.isArray(patched.data) || patched.data.length !== 1) fail('ADMIN_ACCOUNT_SECURITY_STATE_UPDATE_FAILED', 503);
  const row = patched.data[0];
  if (String(row && row.id || '').trim().toLowerCase() !== link.id || String(row && row.auth_user_id || '').trim().toLowerCase() !== link.auth_user_id || String(row && row.customer_id || '').trim().toLowerCase() !== link.customer_id || String(row && row.email || '').trim().toLowerCase() !== link.email || String(row && row.link_status || '').trim().toLowerCase() !== 'active' || !row.disabled_at || !row.revoked_at) fail('ADMIN_ACCOUNT_SECURITY_STATE_UPDATE_UNCONFIRMED', 503);
  link.disabled_at = row.disabled_at; link.revoked_at = row.revoked_at;
  return true;
}
async function adminAccountRevokeSessionsV480(link, reason, assertContext) {
  if (!link) return 0;
  if (!['admin_account_disable','admin_account_delete','admin_password_reset','admin_passkey_reset'].includes(reason)) fail('ADMIN_ACCOUNT_SECURITY_STATE_INVALID', 503);
  const nowIso = new Date().toISOString();
  const revoked = await dbFetch('/rest/v1/security_customer_sessions?select=' + encodeURIComponent('id,customer_id,status,revoked_at,revoke_reason') + '&customer_id=eq.' + encodeURIComponent(link.customer_id) + '&status=eq.active&revoked_at=is.null', { method: 'PATCH', prefer: 'return=representation', body: { status: 'revoked', revoked_at: nowIso, revoke_reason: reason } });
  assertContext();
  if (!revoked || !revoked.ok || !Array.isArray(revoked.data)) fail('ADMIN_ACCOUNT_SESSION_REVOCATION_FAILED', 503);
  const active = await dbFetch('/rest/v1/security_customer_sessions?select=id&customer_id=eq.' + encodeURIComponent(link.customer_id) + '&status=eq.active&revoked_at=is.null&limit=1', { method: 'GET' });
  assertContext();
  if (!active || !active.ok || !Array.isArray(active.data) || active.data.length !== 0) fail('ADMIN_ACCOUNT_SESSION_REVOCATION_UNCONFIRMED', 503);
  return revoked.data.length;
}
async function adminAccountRevokePasskeysV480(link, reason, assertContext, traceRef = '') {
  if (!link) return 0;
  if (!['admin_account_delete','admin_passkey_reset'].includes(reason)) fail('ADMIN_ACCOUNT_SECURITY_STATE_INVALID', 503);
  const diagTrace = String(traceRef || crypto.randomBytes(6).toString('hex').toUpperCase()).slice(0, 32);
  const readPath = '/rest/v1/domain_passkeys?select=' + encodeURIComponent('id,user_id,is_active,rotation_state,revoked_at') + '&user_id=eq.' + encodeURIComponent(link.customer_id) + '&is_active=eq.true&revoked_at=is.null';
  adminAccountDeleteDiagnosticV489('passkeys.read.begin', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'GET', request_shape: 'select=id,user_id,is_active,rotation_state,revoked_at;filter=user_id:eq:<customer>;is_active:eq:true;revoked_at:is:null' });
  const active = await dbFetch(readPath, { method: 'GET' });
  assertContext();
  adminAccountDeleteDiagnosticV489('passkeys.read.result', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'GET', result: active, expected_row_count: -1, condition_result_present: !!active, condition_ok_true: !!(active && active.ok), condition_data_array: !!(active && Array.isArray(active.data)), condition_row_count_match: !!(active && Array.isArray(active.data) && active.data.length <= 16) });
  if (!active || !active.ok || !Array.isArray(active.data) || active.data.length > 16) {
    adminAccountDeleteDiagnosticV489('passkeys.read.failure', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'GET', result: active, failure_code: 'ADMIN_ACCOUNT_PASSKEY_STATE_UNAVAILABLE', condition_result_present: !!active, condition_ok_true: !!(active && active.ok), condition_data_array: !!(active && Array.isArray(active.data)), condition_row_count_match: !!(active && Array.isArray(active.data) && active.data.length <= 16) });
    fail('ADMIN_ACCOUNT_PASSKEY_STATE_UNAVAILABLE', 503);
  }
  if (active.data.length === 0) {
    adminAccountDeleteDiagnosticV489('passkeys.none_active', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'GET', result: active, expected_row_count: 0, condition_result_present: true, condition_ok_true: true, condition_data_array: true, condition_row_count_match: true });
    return 0;
  }
  const nowIso = new Date().toISOString();
  const patchPath = '/rest/v1/domain_passkeys?select=' + encodeURIComponent('id,user_id,is_active,rotation_state,revoked_at,revoke_reason') + '&user_id=eq.' + encodeURIComponent(link.customer_id) + '&is_active=eq.true&revoked_at=is.null';
  adminAccountDeleteDiagnosticV489('passkeys.patch.begin', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'PATCH', request_shape: 'select=id,user_id,is_active,rotation_state,revoked_at,revoke_reason;filter=user_id:eq:<customer>;is_active:eq:true;revoked_at:is:null;prefer=return=representation', request_body_keys: 'is_active,rotation_state,revoked_at,revoke_reason,updated_at', expected_row_count: active.data.length });
  const revoked = await dbFetch(patchPath, { method: 'PATCH', prefer: 'return=representation', body: { is_active: false, rotation_state: 'revoked', revoked_at: nowIso, revoke_reason: reason, updated_at: nowIso } });
  assertContext();
  const revokedPresent = !!revoked, revokedOk = !!(revoked && revoked.ok), revokedArray = !!(revoked && Array.isArray(revoked.data)), revokedCountMatch = !!(revokedArray && revoked.data.length === active.data.length);
  adminAccountDeleteDiagnosticV489('passkeys.patch.result', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'PATCH', request_shape: 'select=id,user_id,is_active,rotation_state,revoked_at,revoke_reason;filter=user_id:eq:<customer>;is_active:eq:true;revoked_at:is:null;prefer=return=representation', request_body_keys: 'is_active,rotation_state,revoked_at,revoke_reason,updated_at', result: revoked, expected_row_count: active.data.length, condition_result_present: revokedPresent, condition_ok_true: revokedOk, condition_data_array: revokedArray, condition_row_count_match: revokedCountMatch });
  if (!revokedPresent || !revokedOk || !revokedArray || !revokedCountMatch) {
    adminAccountDeleteDiagnosticV489('passkeys.patch.failure', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'PATCH', result: revoked, expected_row_count: active.data.length, failure_code: 'ADMIN_ACCOUNT_PASSKEY_RESET_FAILED', condition_result_present: revokedPresent, condition_ok_true: revokedOk, condition_data_array: revokedArray, condition_row_count_match: revokedCountMatch });
    fail('ADMIN_ACCOUNT_PASSKEY_RESET_FAILED', 503);
  }
  const verifyPath = '/rest/v1/domain_passkeys?select=id&user_id=eq.' + encodeURIComponent(link.customer_id) + '&is_active=eq.true&revoked_at=is.null&limit=1';
  adminAccountDeleteDiagnosticV489('passkeys.verify.begin', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'GET', request_shape: 'select=id;filter=user_id:eq:<customer>;is_active:eq:true;revoked_at:is:null;limit=1', expected_row_count: 0 });
  const check = await dbFetch(verifyPath, { method: 'GET' });
  assertContext();
  const checkPresent = !!check, checkOk = !!(check && check.ok), checkArray = !!(check && Array.isArray(check.data)), checkEmpty = !!(checkArray && check.data.length === 0);
  adminAccountDeleteDiagnosticV489('passkeys.verify.result', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'GET', result: check, expected_row_count: 0, condition_result_present: checkPresent, condition_ok_true: checkOk, condition_data_array: checkArray, condition_row_count_match: checkEmpty });
  if (!checkPresent || !checkOk || !checkArray || !checkEmpty) {
    adminAccountDeleteDiagnosticV489('passkeys.verify.failure', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'GET', result: check, expected_row_count: 0, failure_code: 'ADMIN_ACCOUNT_PASSKEY_RESET_UNCONFIRMED', condition_result_present: checkPresent, condition_ok_true: checkOk, condition_data_array: checkArray, condition_row_count_match: checkEmpty });
    fail('ADMIN_ACCOUNT_PASSKEY_RESET_UNCONFIRMED', 503);
  }
  adminAccountDeleteDiagnosticV489('passkeys.completed', { trace_ref: diagTrace, email: link.email, auth_user_id: link.auth_user_id, customer_id: link.customer_id, has_security_link: true, reason, table: 'domain_passkeys', request_method: 'PATCH', expected_row_count: revoked.data.length, condition_result_present: true, condition_ok_true: true, condition_data_array: true, condition_row_count_match: true });
  return revoked.data.length;
}
async function businessAccountManage(body, origin, assertContext) {
  const account = adminAccountMutationPayload(body);
  adminAccountEmailForOrigin(account.email, origin);
  assertContext();
  if (account.mode === 'create') {
    const partnerInvite = account.partner_request_id ? await adminPartnerInviteForAccountCreateV478(account, assertContext) : null;
    assertContext();
    const provisionMetadata = adminAccountProvisionMetadata(account.role, partnerInvite);
    const profileMetadata = adminAccountProfileMetadata(account.name, account.phone);
    const temporaryPassword = crypto.randomBytes(24).toString('base64url') + 'aA9!';
    const result = await authAdminUserRequest('/auth/v1/admin/users', 'POST', {
      email: account.email,
      password: temporaryPassword,
      email_confirm: true,
      app_metadata: provisionMetadata,
      user_metadata: profileMetadata
    });
    assertContext();
    let user = result && result.data && typeof result.data === 'object' ? (result.data.user || result.data) : null;
    let passwordDelivery = 'admin_one_time_display', passwordPreserved = false, accountUpgraded = false, preservedProviderBan = false;
    if (!result || result.ok !== true || !user || !isUuid(user.id) || String(user.email || '').trim().toLowerCase() !== account.email) {
      if (!(result && (result.status === 409 || result.status === 422))) fail('ADMIN_ACCOUNT_CREATE_FAILED', 503);
      const lookupExisting = await authAdminUserRequest('/auth/v1/admin/users?filter=' + encodeURIComponent(account.email), 'GET');
      assertContext();
      if (!lookupExisting || lookupExisting.ok !== true) fail('ADMIN_ACCOUNT_LOOKUP_FAILED', 503);
      const existing = adminAccountExactUser(lookupExisting.data, account.email);
      if (!adminAccountUserUpgradeable(existing, account.email)) fail('ADMIN_ACCOUNT_EMAIL_EXISTS', 409);
      preservedProviderBan = adminAccountBanned(existing);
      const existingAppMetadata = existing.app_metadata && typeof existing.app_metadata === 'object' && !Array.isArray(existing.app_metadata) ? { ...existing.app_metadata } : {};
      const existingUserMetadata = existing.user_metadata && typeof existing.user_metadata === 'object' && !Array.isArray(existing.user_metadata) ? { ...existing.user_metadata } : {};
      const existingPath = '/auth/v1/admin/users/' + String(existing.id).toLowerCase();
      const upgraded = await authAdminUserRequest(existingPath, 'PUT', {
        email_confirm: true,
        app_metadata: { ...existingAppMetadata, ...provisionMetadata },
        user_metadata: { ...existingUserMetadata, ...profileMetadata }
      });
      assertContext();
      user = upgraded && upgraded.ok === true ? adminAccountExactUser(upgraded.data, account.email) : null;
      if (!user || String(user.id || '').toLowerCase() !== String(existing.id).toLowerCase() || adminAccountRoleFromUser(user) !== account.role || adminAccountBanned(user) !== preservedProviderBan) fail('ADMIN_ACCOUNT_ROLE_UNCONFIRMED', 503);
      if (partnerInvite) {
        try { await adminPartnerInviteCompleteV478(partnerInvite, user, assertContext); }
        catch (error) {
          const rollback = await authAdminUserRequest(existingPath, 'PUT', {
            email_confirm: true,
            app_metadata: existingAppMetadata,
            user_metadata: existingUserMetadata
          });
          assertContext();
          const rolledBack = rollback && rollback.ok === true && adminAccountRoleFromUser(adminAccountExactUser(rollback.data, account.email)) === '';
          if (!rolledBack) fail('ADMIN_ACCOUNT_PARTNER_LINK_ROLLBACK_FAILED', 503);
          throw error;
        }
      }
      passwordDelivery = 'existing_password_preserved';
      passwordPreserved = true;
      accountUpgraded = true;
    }
    const verify = await authAdminUserRequest('/auth/v1/admin/users/' + String(user.id).toLowerCase(), 'GET');
    assertContext();
    const confirmed = verify && verify.ok === true ? adminAccountExactUser(verify.data, account.email) : null;
    if (!confirmed || !isUuid(confirmed.id) || String(confirmed.id).toLowerCase() !== String(user.id).toLowerCase() || adminAccountRoleFromUser(confirmed) !== account.role || adminAccountBanned(confirmed) !== preservedProviderBan) fail('ADMIN_ACCOUNT_ROLE_UNCONFIRMED', 503);
    if (partnerInvite && !accountUpgraded) {
      try { await adminPartnerInviteCompleteV478(partnerInvite, confirmed, assertContext); }
      catch (error) {
        const rolledBack = await adminRollbackBusinessAccountV478(confirmed.id, account.email, assertContext);
        if (!rolledBack) fail('ADMIN_ACCOUNT_PARTNER_LINK_ROLLBACK_FAILED', 503);
        throw error;
      }
    }
    return { ok: true, mode: 'create', user_id: confirmed.id, email: account.email, account_role: account.role,
      account_label: adminAccountLabel(account.role), account_active: !preservedProviderBan, temporary_password: passwordPreserved ? '' : temporaryPassword,
      password_delivery: passwordDelivery, password_preserved: passwordPreserved, account_upgraded: accountUpgraded,
      self_registration: false, partner_request_id: partnerInvite ? partnerInvite.id : '' };
  }
  const lookup = await authAdminUserRequest('/auth/v1/admin/users?filter=' + encodeURIComponent(account.email), 'GET');
  assertContext();
  if (!lookup || lookup.ok !== true) fail('ADMIN_ACCOUNT_LOOKUP_FAILED', 503);
  const user = adminAccountExactUser(lookup.data, account.email);
  if (!user || !isUuid(user.id)) fail('ADMIN_ACCOUNT_NOT_FOUND', 404);
  const role = adminAccountRoleFromUser(user);
  if (!role) fail('ADMIN_ACCOUNT_NOT_BUSINESS', 409);
  const userPath = '/auth/v1/admin/users/' + String(user.id).toLowerCase();
  if (account.mode === 'delete') {
    const deleteTraceRef = crypto.randomBytes(6).toString('hex').toUpperCase();
    let deleteFailureStage = 'begin', securityLink = null;
    adminAccountDeleteDiagnosticV489('delete.begin', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, reason: 'admin_account_delete' });
    try {
      deleteFailureStage = 'security_link';
      adminAccountDeleteDiagnosticV489('delete.security_link.begin', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, reason: 'admin_account_delete', table: 'security_customer_auth_links', request_method: 'GET', request_shape: 'active non-revoked auth link by auth_user_id;limit=2' });
      securityLink = await adminAccountSecurityLinkV480(user, account.email, assertContext);
      adminAccountDeleteDiagnosticV489('delete.security_link.resolved', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, customer_id: securityLink && securityLink.customer_id, has_security_link: !!securityLink, reason: 'admin_account_delete', table: 'security_customer_auth_links', request_method: 'GET' });
      deleteFailureStage = 'link_disable';
      const linkDisabled = await adminAccountSetLinkDisabledV480(securityLink, true, assertContext);
      adminAccountDeleteDiagnosticV489('delete.link_disabled', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, customer_id: securityLink && securityLink.customer_id, has_security_link: !!securityLink, reason: 'admin_account_delete', table: 'security_customer_auth_links', request_method: 'PATCH', condition_result_present: linkDisabled === true, condition_ok_true: linkDisabled === true });
      deleteFailureStage = 'session_revoke';
      const sessionsRevoked = await adminAccountRevokeSessionsV480(securityLink, 'admin_account_delete', assertContext);
      adminAccountDeleteDiagnosticV489('delete.sessions_revoked', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, customer_id: securityLink && securityLink.customer_id, has_security_link: !!securityLink, reason: 'admin_account_delete', table: 'security_customer_sessions', request_method: 'PATCH', expected_row_count: sessionsRevoked, condition_result_present: true, condition_ok_true: true });
      deleteFailureStage = 'passkey_revoke';
      const passkeysRevoked = await adminAccountRevokePasskeysV480(securityLink, 'admin_account_delete', assertContext, deleteTraceRef);
      adminAccountDeleteDiagnosticV489('delete.passkeys_revoked', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, customer_id: securityLink && securityLink.customer_id, has_security_link: !!securityLink, reason: 'admin_account_delete', table: 'domain_passkeys', request_method: 'PATCH', expected_row_count: passkeysRevoked, condition_result_present: true, condition_ok_true: true });
      deleteFailureStage = 'link_revoke';
      const linkRevoked = await adminAccountRevokeLinkV480(securityLink, assertContext);
      adminAccountDeleteDiagnosticV489('delete.link_revoked', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, customer_id: securityLink && securityLink.customer_id, has_security_link: !!securityLink, reason: 'admin_account_delete', table: 'security_customer_auth_links', request_method: 'PATCH', condition_result_present: linkRevoked === true, condition_ok_true: linkRevoked === true });
      deleteFailureStage = 'auth_user_delete';
      const removed = await authAdminUserRequest(userPath, 'DELETE');
      assertContext();
      adminAccountDeleteDiagnosticV489('delete.auth_user_delete.result', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, customer_id: securityLink && securityLink.customer_id, has_security_link: !!securityLink, reason: 'admin_account_delete', request_method: 'DELETE', request_shape: '/auth/v1/admin/users/<user>', result: removed, condition_result_present: !!removed, condition_ok_true: !!(removed && removed.ok) });
      if (!removed || removed.ok !== true) fail('ADMIN_ACCOUNT_DELETE_FAILED', 503);
      deleteFailureStage = 'auth_user_verify';
      const verify = await authAdminUserRequest(userPath, 'GET');
      assertContext();
      adminAccountDeleteDiagnosticV489('delete.auth_user_verify.result', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, customer_id: securityLink && securityLink.customer_id, has_security_link: !!securityLink, reason: 'admin_account_delete', request_method: 'GET', request_shape: '/auth/v1/admin/users/<user>;expected_status=404', result: verify, expected_row_count: 0, condition_result_present: !!verify, condition_ok_true: !!(verify && verify.status === 404) });
      if (!verify || verify.status !== 404) fail('ADMIN_ACCOUNT_DELETE_UNCONFIRMED', 503);
      adminAccountDeleteDiagnosticV489('delete.completed', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, customer_id: securityLink && securityLink.customer_id, has_security_link: !!securityLink, reason: 'admin_account_delete', expected_row_count: passkeysRevoked, condition_result_present: true, condition_ok_true: true });
      return { ok: true, mode: 'delete', email: account.email, account_role: role, account_label: adminAccountLabel(role), deleted: true, link_disabled: linkDisabled, link_revoked: linkRevoked, sessions_revoked: sessionsRevoked, passkeys_revoked: passkeysRevoked };
    } catch (error) {
      adminAccountDeleteDiagnosticV489('delete.failure', { trace_ref: deleteTraceRef, email: account.email, auth_user_id: user.id, customer_id: securityLink && securityLink.customer_id, has_security_link: !!securityLink, reason: 'admin_account_delete', failure_stage: deleteFailureStage, failure_code: String(error && error.code || ''), error_status: Number(error && (error.status || error.statusCode) || 0) });
      throw error;
    }
  }
  if (account.mode === 'reset_password') {
    const temporaryPassword = crypto.randomBytes(24).toString('base64url') + 'aA9!';
    const securityLink = await adminAccountSecurityLinkV480(user, account.email, assertContext);
    const sessionsRevoked = await adminAccountRevokeSessionsV480(securityLink, 'admin_password_reset', assertContext);
    const updated = await authAdminUserRequest(userPath, 'PUT', { password: temporaryPassword });
    assertContext();
    const changed = updated && updated.ok === true ? adminAccountExactUser(updated.data, account.email) : null;
    if (!changed || String(changed.id || '').toLowerCase() !== String(user.id).toLowerCase() || adminAccountRoleFromUser(changed) !== role) fail('ADMIN_ACCOUNT_PASSWORD_RESET_FAILED', 503);
    const verify = await authAdminUserRequest(userPath, 'GET');
    assertContext();
    const confirmed = verify && verify.ok === true ? adminAccountExactUser(verify.data, account.email) : null;
    if (!confirmed || adminAccountRoleFromUser(confirmed) !== role || adminAccountBanned(confirmed) !== adminAccountBanned(user)) fail('ADMIN_ACCOUNT_PASSWORD_RESET_UNCONFIRMED', 503);
    return { ok: true, mode: 'reset_password', email: account.email, account_role: role, account_label: adminAccountLabel(role), temporary_password: temporaryPassword, password_delivery: 'admin_one_time_display', sessions_revoked: sessionsRevoked };
  }
  if (account.mode === 'reset_passkey') {
    const securityLink = await adminAccountSecurityLinkV480(user, account.email, assertContext);
    if (!securityLink) return { ok: true, mode: 'reset_passkey', email: account.email, account_role: role, account_label: adminAccountLabel(role), passkeys_revoked: 0, sessions_revoked: 0, passkey_enrolled: false };
    const sessionsRevoked = await adminAccountRevokeSessionsV480(securityLink, 'admin_passkey_reset', assertContext);
    const passkeysRevoked = await adminAccountRevokePasskeysV480(securityLink, 'admin_passkey_reset', assertContext);
    return { ok: true, mode: 'reset_passkey', email: account.email, account_role: role, account_label: adminAccountLabel(role), passkeys_revoked: passkeysRevoked, sessions_revoked: sessionsRevoked, passkey_enrolled: passkeysRevoked > 0 };
  }
  const shouldDisable = account.mode === 'disable', wasBanned = adminAccountBanned(user);
  const securityLink = await adminAccountSecurityLinkV480(user, account.email, assertContext);
  let linkSynchronized = !securityLink, sessionsRevoked = 0;
  if (shouldDisable) {
    linkSynchronized = await adminAccountSetLinkDisabledV480(securityLink, true, assertContext);
    sessionsRevoked = await adminAccountRevokeSessionsV480(securityLink, 'admin_account_disable', assertContext);
  }
  try {
    const updated = await authAdminUserRequest(userPath, 'PUT', { ban_duration: shouldDisable ? '876000h' : 'none' });
    assertContext();
    if (!updated || updated.ok !== true) fail(shouldDisable ? 'ADMIN_ACCOUNT_DISABLE_FAILED' : 'ADMIN_ACCOUNT_ENABLE_FAILED', 503);
    const verify = await authAdminUserRequest(userPath, 'GET');
    assertContext();
    const confirmed = verify && verify.ok === true ? adminAccountExactUser(verify.data, account.email) : null;
    if (!confirmed || adminAccountRoleFromUser(confirmed) !== role || adminAccountBanned(confirmed) !== shouldDisable) fail(shouldDisable ? 'ADMIN_ACCOUNT_DISABLE_UNCONFIRMED' : 'ADMIN_ACCOUNT_ENABLE_UNCONFIRMED', 503);
    if (!shouldDisable) linkSynchronized = await adminAccountSetLinkDisabledV480(securityLink, false, assertContext);
  } catch (error) {
    if (!shouldDisable && wasBanned) {
      const rollback = await authAdminUserRequest(userPath, 'PUT', { ban_duration: '876000h' });
      assertContext();
      const rollbackVerify = rollback && rollback.ok === true ? await authAdminUserRequest(userPath, 'GET') : null;
      assertContext();
      const restored = rollbackVerify && rollbackVerify.ok === true ? adminAccountExactUser(rollbackVerify.data, account.email) : null;
      if (!restored || adminAccountRoleFromUser(restored) !== role || adminAccountBanned(restored) !== true) fail('ADMIN_ACCOUNT_ENABLE_ROLLBACK_FAILED', 503);
    }
    throw error;
  }
  return { ok: true, mode: account.mode, email: account.email, account_role: role, account_label: adminAccountLabel(role), account_active: !shouldDisable, link_synchronized: linkSynchronized, sessions_revoked: sessionsRevoked };
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
  const ownerValidV466 = value.owner === ADMIN_OWNER_V466 || value.owner === legacyAdminOwnerV466();
  if (value.version !== VERSION || !ownerValidV466 || typeof value.origin !== 'string'
      || key !== configKey({ owner: value.owner, origin: value.origin }) || !exactToken(value.revision) || !exactToken(value.userHandle)
      || !['active', 'pending_totp'].includes(state) || !passkey || typeof passkey !== 'object' || Array.isArray(passkey)
      || typeof passkey.credentialId !== 'string' || !/^[A-Za-z0-9_-]{22,1364}$/.test(passkey.credentialId)
      || !Number.isSafeInteger(passkey.signCount) || passkey.signCount < 0 || passkey.signCount > 4294967295
      || typeof value.totp !== 'string' || !/^[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{22}$/.test(value.totp)
      || (value.factorGuardV466 !== undefined && (typeof value.factorGuardV466 !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value.factorGuardV466)))
      || (value.totpKeyV466 !== undefined && value.totpKeyV466 !== true)
      || (value.legacyConfigKeyV466 !== undefined && (typeof value.legacyConfigKeyV466 !== 'string' || !/^s2s-admin-v405:enrollment:[a-f0-9]{64}$/.test(value.legacyConfigKeyV466)))
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

// Manual administrator verification-code requests only. Reuse dirac_s2s_security,
// an existing atomic claim RPC, and a compare-and-set update. No new tables or ENV.
const ADMIN_EMAIL_REQUEST_RATE_VERSION_V491 = 'dirac-admin-email-request-rate-v491';
const ADMIN_EMAIL_REQUEST_COOLDOWNS_V491 = Object.freeze([300000, 900000, 3600000, 86400000]);
function adminEmailRateKeyV491(scope) {
  return 's2s-admin-v411:email-rate:' + digest(ADMIN_EMAIL_REQUEST_RATE_VERSION_V491 + ':' + scope.owner);
}
function adminEmailRateRecordV491(scope, count, now) {
  return {
    version: VERSION, policy: ADMIN_EMAIL_REQUEST_RATE_VERSION_V491,
    ownerHash: digest(scope.owner), count, updatedAt: now,
    blockedUntilMs: count ? now + ADMIN_EMAIL_REQUEST_COOLDOWNS_V491[count - 1] : 0,
    revision: randomToken()
  };
}
function adminEmailRateValidateV491(entry, scope) {
  if (!entry || entry.ok !== true) fail('ADMIN_EMAIL_RATE_STORE_UNAVAILABLE', 503);
  if (entry.found !== true) return null;
  const r = entry.record, now = Date.now();
  if (!r || Object.keys(r).sort().join(',') !== 'blockedUntilMs,count,ownerHash,policy,revision,updatedAt,version'
    || r.version !== VERSION || r.policy !== ADMIN_EMAIL_REQUEST_RATE_VERSION_V491
    || r.ownerHash !== digest(scope.owner) || !Number.isSafeInteger(r.count) || r.count < 0 || r.count > 4
    || !Number.isSafeInteger(r.updatedAt) || r.updatedAt <= 0 || r.updatedAt > now + 10000
    || !Number.isSafeInteger(r.blockedUntilMs)
    || r.blockedUntilMs !== (r.count === 0 ? 0 : r.updatedAt + ADMIN_EMAIL_REQUEST_COOLDOWNS_V491[r.count - 1])
    || !exactToken(r.revision) || !Number.isFinite(Date.parse(String(entry.expiresAt || '')))) {
    fail('ADMIN_EMAIL_RATE_STATE_INVALID', 503);
  }
  return r;
}
async function adminEmailRateWriteV491(scope, prior, count) {
  const key = adminEmailRateKeyV491(scope), next = adminEmailRateRecordV491(scope, count, Date.now());
  if (!prior || prior.found !== true) {
    if (count !== 1 || await securityClaim(key, next, 10 * 365 * 86400) !== true) fail('ADMIN_EMAIL_RATE_STORE_UNAVAILABLE', 503);
    return true;
  }
  const oldExpiry = Date.parse(prior.expiresAt);
  if (!Number.isFinite(oldExpiry)) fail('ADMIN_EMAIL_RATE_STATE_INVALID', 503);
  const nextExpiry = new Date(Math.max(Date.now() + 10 * 365 * 86400000, oldExpiry + 1)).toISOString();
  const result = await dbFetch('/rest/v1/dirac_s2s_security?security_key=eq.' + encodeURIComponent(key)
    + '&expires_at=eq.' + encodeURIComponent(prior.expiresAt)
    + '&select=security_key,record_json,expires_at', {
    method: 'PATCH', prefer: 'return=representation',
    body: { record_json: next, expires_at: nextExpiry }
  }, 'security');
  const row = result && result.ok === true && Array.isArray(result.data) && result.data.length === 1 ? result.data[0] : null;
  if (!row || row.security_key !== key || Date.parse(String(row.expires_at || '')) !== Date.parse(nextExpiry)
      || !row.record_json || row.record_json.revision !== next.revision) fail('ADMIN_EMAIL_RATE_CONCURRENT_REQUEST', 503);
  return true;
}
async function adminEmailRateTakeV491(ops, scope) {
  ops.assertFullGuard();
  const entry = await securityRead(adminEmailRateKeyV491(scope));
  const record = adminEmailRateValidateV491(entry, scope);
  const count = record ? record.count : 0;
  if (count && record.blockedUntilMs > Date.now()) {
    const error = Object.assign(new Error('ADMIN_EMAIL_REQUEST_RATE_LIMITED'), {
      code: 'ADMIN_EMAIL_REQUEST_RATE_LIMITED', status: 429,
      retryAfterSeconds: Math.max(1, Math.ceil((record.blockedUntilMs - Date.now()) / 1000)),
      resetAt: new Date(record.blockedUntilMs).toISOString()
    });
    throw error;
  }
  if (count >= 4) fail('ADMIN_SMTP_REQUEST_PERMANENT_BAN', 403);
  await adminEmailRateWriteV491(scope, entry, count + 1);
  ops.assertFullGuard();
}
async function adminEmailRateResetV491(ops, scope) {
  ops.assertFullGuard();
  const entry = await securityRead(adminEmailRateKeyV491(scope));
  const record = adminEmailRateValidateV491(entry, scope);
  if (record && record.count !== 0) await adminEmailRateWriteV491(scope, entry, 0);
  ops.assertFullGuard();
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
// V457: enforce the algorithms advertised to authenticators, including RS256 >= 2048 bits.
function adminPasskeyPublicKeyV457(jwk, status) {
  let key;
  try {
    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)
        || ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(name => Object.prototype.hasOwnProperty.call(jwk, name))) throw new Error();
    key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const ec = jwk.kty === 'EC' && jwk.crv === 'P-256' && (!jwk.alg || jwk.alg === 'ES256')
      && key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails.namedCurve === 'prime256v1';
    const rsa = jwk.kty === 'RSA' && (!jwk.alg || jwk.alg === 'RS256') && key.asymmetricKeyType === 'rsa'
      && key.asymmetricKeyDetails.modulusLength >= 2048 && key.asymmetricKeyDetails.modulusLength <= 8192;
    if (!ec && !rsa) throw new Error();
  } catch (_) { fail('ADMIN_PASSKEY_KEY_INVALID', status); }
  return key;
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
    if (!Buffer.isBuffer(n) || n.length < 256 || n.length > 1024 || !Buffer.isBuffer(e) || e.length < 1 || e.length > 8) fail('ADMIN_PASSKEY_KEY_INVALID', 400);
    jwk = { kty: 'RSA', n: n.toString('base64url'), e: e.toString('base64url'), alg: 'RS256', ext: true, key_ops: ['verify'] };
  } else fail('ADMIN_PASSKEY_ALGORITHM_INVALID', 403);
  adminPasskeyPublicKeyV457(jwk, 400);
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
  const key = adminPasskeyPublicKeyV457(passkey.publicKeyJwk, 503);
  let ok = false; try { ok = crypto.verify('sha256', signed, key, signature); } catch (_) { ok = false; }
  if (!ok) fail('ADMIN_PASSKEY_SIGNATURE_INVALID', 403);
  const previous = Number(passkey.signCount || 0), current = parsed.signCount;
  if (previous > 0 && current <= previous) fail('ADMIN_PASSKEY_COUNTER_REPLAY', 409);
  return { ok: true, signCount: current };
}

function approvalPayload(action, body) {
  const value = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  if (action === 'admin_document_prepare') {
    if (!DOCUMENT_KINDS_V464.includes(value.document_kind) || typeof value.reference !== 'string' || !value.reference || value.reference.length > 253
        || /[\u0000-\u001f\u007f]/.test(value.reference) || !Number.isInteger(value.page_count) || value.page_count < 1 || value.page_count > 64
        || typeof value.content_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.content_sha256)) fail('ADMIN_DOCUMENT_META_INVALID',400);
    return { action, document_kind: value.document_kind, reference: value.reference, page_count: value.page_count, content_sha256: value.content_sha256 };
  }
  if (action === 'admin_document_seal') {
    if (!documentIdentityValidV464(value.identity) || value.identity.owner_scope !== documentAdminScopeV464() || !['png','pdf'].includes(value.format)
        || !Number.isInteger(value.page) || (value.format === 'png' ? value.page < 1 || value.page > value.identity.page_count : value.page !== 0)
        || typeof value.raw_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.raw_sha256)) fail('ADMIN_DOCUMENT_SEAL_INVALID',400);
    return { action, identity: value.identity, format: value.format, page: value.page, raw_sha256: value.raw_sha256 };
  }
  if (action === 'admin_local_authorize') {
    if (!['document_preview', 'document_pdf', 'document_png', 'document_print', 'theme_save'].includes(value.purpose) || typeof value.content_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.content_sha256)) fail('ADMIN_LOCAL_AUTHORIZATION_INVALID', 400);
    return { action, purpose: value.purpose, content_sha256: value.content_sha256 };
  }
  if (action === 'admin_shipment_update') return { action, review_ack: value.review_ack || '', review_reason: value.review_reason || '', kind: value.kind, order_id: value.order_id, expected_revision: value.expected_revision, tracking_number: value.tracking_number, courier: value.courier, status: value.status, location: value.location || '', origin: value.origin || '', destination: value.destination || '', estimated_delivery: value.estimated_delivery || '', description: value.description || '', ...(value.tracking_options === undefined ? {} : { tracking_options: shipmentOptionsV450(value.tracking_options) }) };
  if (action === 'admin_shipment_cancel') return { action, review_ack: value.review_ack || '', review_reason: value.review_reason || '', kind: value.kind, order_id: value.order_id, expected_revision: value.expected_revision, description: value.description || '' };
  if (action === 'admin_unban') return { action, block_id: value.block_id };
  if (action === 'admin_banned_pdf') {
    if (!adminBannedExportRefValidV476(value.export_ref) || !['download','email'].includes(String(value.mode || ''))
        || typeof value.raw_pdf_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.raw_pdf_sha256)) fail('ADMIN_BANNED_PDF_INPUT_INVALID', 400);
    return { action, export_ref: value.export_ref, mode: value.mode, raw_pdf_sha256: value.raw_pdf_sha256 };
  }
  if (Object.prototype.hasOwnProperty.call(ADMIN_ACCOUNT_ACTION_MODES, action)) { const account = adminAccountMutationPayload({ ...value, mode: ADMIN_ACCOUNT_ACTION_MODES[action] }); return { action, ...account }; }
  if (action === 'admin_partner_request_update') { const request = adminPartnerRequestUpdatePayloadV478(value); return { action, ...request }; }
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
  return '<tr><td style="padding:18px 24px 8px"><div style="font-size:10px;line-height:1.4;font-weight:800;letter-spacing:.14em;color:#7dd3fc">IKUTI KANAL RESMI</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;table-layout:fixed;border-collapse:collapse"><tr><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://x.com/achzaenuddin?s=11" target="_blank" rel="noopener noreferrer" aria-label="X" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:20px;font-weight:700;line-height:28px;text-align:center">X</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">X</span></a></td><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.facebook.com/share/1J3EEbguNX/?mibextid=wwXIfr" target="_blank" rel="noopener noreferrer" aria-label="Facebook" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:24px;font-weight:700;line-height:28px;text-align:center">f</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">Facebook</span></a></td><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.instagram.com/achzaenuddin15?stkn=MW4zc3FldjAzb21wNg%3D%3D&utm_source=qr" target="_blank" rel="noopener noreferrer" aria-label="Instagram" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><table role="presentation" width="22" height="22" cellpadding="0" cellspacing="0" border="0" style="width:22px;height:22px;border:2px solid #E2E8F0;border-radius:6px;border-collapse:separate;table-layout:fixed"><tr><td align="center" valign="middle" style="padding:0;font-size:0;line-height:0"><table role="presentation" width="10" height="10" cellpadding="0" cellspacing="0" border="0" style="width:10px;height:10px;border:2px solid #E2E8F0;border-radius:50%;border-collapse:separate"><tr><td style="padding:0;font-size:0;line-height:0">&nbsp;</td></tr></table></td></tr></table></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">Instagram</span></a></td></tr><tr><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.threads.com/@achzaenuddin15?igshid=NTc4MTIwNjQ2YQ==" target="_blank" rel="noopener noreferrer" aria-label="Threads" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:23px;font-weight:700;line-height:28px;text-align:center">@</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">Threads</span></a></td><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.linkedin.com/in/pt-dirac-inovasi-nusantara" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:17px;font-weight:700;line-height:28px;text-align:center">in</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">LinkedIn</span></a></td><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.tiktok.com/@achzaenuddin" target="_blank" rel="noopener noreferrer" aria-label="TikTok" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:24px;font-weight:700;line-height:28px;text-align:center">&#9834;</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">TikTok</span></a></td></tr></table></td></tr>';
}
function adminExecutiveEscalationHtml(supportEmail) {
  return '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" data-dirac-executive-report="v380" style="width:100%;margin:18px 0 0;border-collapse:collapse"><tr><td align="center" style="padding:0 12px"><table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" bgcolor="#F7F9FC" style="width:100%;max-width:600px;border-collapse:separate;border-spacing:0;border:1px solid #CBD5E1;border-radius:16px;overflow:hidden;background-color:#F7F9FC"><tr><td style="padding:0"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td width="42%" bgcolor="#27B3CB" style="height:4px;line-height:4px;font-size:0;background-color:#27B3CB">&nbsp;</td><td width="34%" bgcolor="#2D6FAD" style="height:4px;line-height:4px;font-size:0;background-color:#2D6FAD">&nbsp;</td><td width="24%" bgcolor="#C69A32" style="height:4px;line-height:4px;font-size:0;background-color:#C69A32">&nbsp;</td></tr></table></td></tr><tr><td bgcolor="#F7F9FC" style="padding:18px 18px 17px;font-family:Arial,Helvetica,sans-serif;background-color:#F7F9FC;color:#172033"><div style="font-size:10px;line-height:1.4;font-weight:800;letter-spacing:.15em;color:#087A8F">JALUR PRIVAT PELANGGAN</div><div style="margin-top:5px;font-size:20px;line-height:1.28;font-weight:800;color:#0F172A">Lapor ke Direktur &amp; Founder</div><p style="margin:8px 0 14px;font-size:13px;line-height:1.55;color:#475569">Dugaan penyalahgunaan, penipuan, manipulasi, pemaksaan, atau pelanggaran oleh staf/mitra dapat dilaporkan langsung kepada Achmad Zaenuddin, Direktur &amp; Founder PT Dirac Inovasi Nusantara.</p><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td bgcolor="#0B6F88" style="padding:0;border-radius:10px;background-color:#0B6F88"><a href="mailto:companydirac@gmail.com?subject=Laporan%20Pelanggan%20ke%20Direktur%20%26%20Founder&amp;body=Halo%20Achmad%20Zaenuddin%2C%20Direktur%20%26%20Founder%20PT%20Dirac%20Inovasi%20Nusantara%2C%0D%0A%0D%0ASaya%20ingin%20menyampaikan%20laporan%20pelanggan%20berikut.%0D%0A%0D%0AIDENTITAS%20PELAPOR%0D%0ANama%20lengkap%3A%0D%0AEmail%20akun%3A%0D%0AKontak%20balasan%20%28opsional%29%3A%0D%0A%0D%0ARINCIAN%20KEJADIAN%0D%0ANomor%20pesanan%2Finvoice%2Ftiket%20%28jika%20ada%29%3A%0D%0ALayanan%20dan%20alamat%20halaman%20yang%20digunakan%3A%0D%0ATanggal%20dan%20waktu%20kejadian%20%28WIB%29%3A%0D%0ANama%2Fjabatan%20staf%20atau%20mitra%20terkait%20%28jika%20diketahui%29%3A%0D%0ARingkasan%20masalah%3A%0D%0AKronologi%20kejadian%3A%0D%0ADampak%20atau%20kerugian%20yang%20dialami%3A%0D%0A%0D%0ATINDAK%20LANJUT%0D%0ALangkah%20yang%20sudah%20dilakukan%20dan%20tanggapan%20yang%20diterima%3A%0D%0APenyelesaian%20yang%20diharapkan%3A%0D%0A%0D%0ABUKTI%20PENDUKUNG%0D%0ADaftar%20lampiran%2C%20tangkapan%20layar%2C%20atau%20percakapan%20terkait%3A%0D%0AHapus%20atau%20tutupi%20data%20rahasia%20sebelum%20melampirkan%20bukti.%20Jangan%20sertakan%20kata%20sandi%2C%20kode%20verifikasi%2C%20PIN%2C%20CVV%2C%20Passkey%2C%20atau%20data%20akses%20akun.%0D%0A%0D%0AInformasi%20di%20atas%20saya%20sampaikan%20sesuai%20kejadian%20yang%20saya%20alami.%20Mohon%20laporan%20ini%20ditinjau%20dan%20balas%20melalui%20kontak%20yang%20saya%20cantumkan.%0D%0A%0D%0ATerima%20kasih." style="display:block;padding:12px 14px;font-size:13px;line-height:1.35;font-weight:800;text-align:center;color:#FFFFFF;text-decoration:none"><font color="#FFFFFF" style="color:#FFFFFF">EMAIL&nbsp;&nbsp;•&nbsp;&nbsp;SIAPKAN LAPORAN</font></a></td></tr></table><p style="margin:12px 0 0;font-size:11px;line-height:1.5;color:#64748B">Lengkapi identitas, kronologi, dampak, dan penyelesaian yang Anda harapkan. Lampirkan bukti setelah menutupi data rahasia. Jangan sertakan kata sandi, kode verifikasi, PIN, CVV, Passkey, atau data akses akun.</p></td></tr></table></td></tr></table>';
}

function adminMailHtml(message) {
  const code = mailEscape(message.code), reference = mailEscape(message.reference), parts = mailOriginParts(message.origin), operation = 'Verifikasi masuk administrator';
  const title = 'Verifikasi Akses<br>Administrator';
  const summary = 'Kode ini digunakan sebagai faktor email pada proses masuk administrator. Gunakan hanya pada halaman administrasi resmi yang sedang Anda buka.';
  const destination = parts.actionUrl ? mailEscape(new URL(parts.actionUrl).hostname) : '', supportEmail = mailEscape(parts.supportEmail || ''), careEmail = mailEscape(parts.careEmail || ''), socialSupportRowHtml = adminSocialGridHtml(), executiveHtml = adminExecutiveEscalationHtml(supportEmail);
  const banner = parts.bannerUrl ? '<tr><td bgcolor="#10151e" style="padding:0;line-height:0;font-size:0;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)"><img src="' + mailEscape(parts.bannerUrl) + '" width="600" alt="PT Dirac Inovasi Nusantara" style="display:block;width:100%;max-width:600px;height:auto;border:0;outline:none;text-decoration:none;background:#10151e;background-color:#10151e"></td></tr>' : '';
  const button = parts.actionUrl ? '<table class="dirac-button" role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;margin:0 0 9px;border-collapse:separate"><tr><td align="center" bgcolor="#5276e8" style="border-radius:10px;background:#5276e8;background-color:#5276e8"><a href="' + mailEscape(parts.actionUrl) + '" style="display:block;padding:17px 18px;font-size:15px;line-height:1.2;font-weight:800;letter-spacing:.04em;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;text-decoration:none;border-radius:10px">BUKA ADMINISTRASI</a></td></tr></table>' : '';
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>Pemberitahuan PT Dirac Inovasi Nusantara</title>
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
        <tr><td class="dirac-pad" bgcolor="#141820" style="padding:27px 32px 13px;background:#141820;background-color:#141820;background-image:linear-gradient(#141820,#141820)"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:21px;line-height:1.2;font-weight:800;letter-spacing:.14em;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">PT Dirac Inovasi Nusantara</div><div style="margin-top:7px;font-size:11px;line-height:1.4;font-weight:700;letter-spacing:.2em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">PEMULIHAN AKUN</div></div></div></td></tr>
        <tr><td class="dirac-pad" bgcolor="#141820" style="padding:24px 32px 32px;background:#141820;background-color:#141820;background-image:linear-gradient(#141820,#141820)">
          <div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#9eb6ff!important;-webkit-text-fill-color:#9eb6ff!important;mso-color-alt:#9eb6ff">PEMBERITAHUAN KEAMANAN</div><div class="dirac-title" style="margin-top:13px;font-size:38px;line-height:1.16;font-weight:800;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">${title}</div><p style="margin:25px 0 0;font-size:17px;line-height:1.55;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">Yth. Administrator PT Dirac Inovasi Nusantara,</p><p style="margin:12px 0 0;font-size:16px;line-height:1.65;color:#c5ccd6!important;-webkit-text-fill-color:#c5ccd6!important;mso-color-alt:#c5ccd6">${mailEscape(summary)}</p></div></div>
          <table class="dirac-code-card" role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#101b2b" style="width:100%;margin:20px 0 18px;border-collapse:separate;border-spacing:0;border:1px solid #3d5f92;border-radius:16px;overflow:hidden;background:#101b2b;background-color:#101b2b;background-image:linear-gradient(#101b2b,#101b2b)"><tr><td style="padding:20px;border-left:4px solid #6fb8ff"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.15em;color:#9fc9ff!important;-webkit-text-fill-color:#9fc9ff!important;mso-color-alt:#9fc9ff">KODE DIMINTA</div><div class="dirac-code-value" aria-label="Kode verifikasi" style="margin-top:12px;font-family:SFMono-Regular,Consolas,Liberation Mono,Menlo,monospace;font-size:15px;line-height:1.55;font-weight:800;letter-spacing:.055em;word-break:break-all;overflow-wrap:anywhere;white-space:normal;-webkit-user-select:all;user-select:all;cursor:text;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;mso-color-alt:#ffffff">${code}</div><div style="margin-top:14px;padding-top:12px;border-top:1px solid #2b4160;font-size:11px;line-height:1.55;color:#9fb0c5!important;-webkit-text-fill-color:#9fb0c5!important;mso-color-alt:#9fb0c5"><b class="dirac-code-copy-pill" style="color:#cfe5ff!important;-webkit-text-fill-color:#cfe5ff!important;mso-color-alt:#cfe5ff">SALIN KODE</b><br>Untuk kode panjang, ketuk area kode lalu tekan dan tahan untuk memilih dan menyalin.</div></div></div></td></tr></table>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#1a1f29" style="width:100%;margin:24px 0 18px;border-collapse:separate;border-spacing:0;border:1px solid #303a49;border-radius:14px;overflow:hidden;box-shadow:0 8px 22px rgba(0,0,0,.12);background:#1a1f29;background-color:#1a1f29;background-image:linear-gradient(#1a1f29,#1a1f29)"><tr><td style="padding:18px 20px;border-left:4px solid #5276e8"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#9eb6ff!important;-webkit-text-fill-color:#9eb6ff!important;mso-color-alt:#9eb6ff">STATUS KEAMANAN</div><div style="margin-top:8px;font-size:19px;line-height:1.45;font-weight:800;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">MENUNGGU KONFIRMASI</div><div style="margin-top:7px;font-size:13px;line-height:1.55;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">Kode berlaku 5 menit dan hanya dapat digunakan satu kali.</div></div></div></td></tr></table>
          ${button}
          ${destination ? '<div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="margin:0 0 25px;text-align:center;font-size:12px;line-height:1.5;color:#8f99a7!important;-webkit-text-fill-color:#8f99a7!important;mso-color-alt:#8f99a7">Tujuan resmi: ' + destination + '</div><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">DETAIL AKTIVITAS</div></div></div>' : '<div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4">DETAIL AKTIVITAS</div>'}
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10151e" style="width:100%;margin:13px 0 0;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:14px;overflow:hidden;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)"><tr><td style="padding:16px 20px;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">AKSI</div><div style="margin-top:6px;font-size:15px;line-height:1.55;font-weight:700;word-break:break-word;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">${mailEscape(operation)}</div></div></div></td></tr><tr><td style="padding:16px 20px;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">REFERENSI</div><div style="margin-top:6px;font-size:15px;line-height:1.55;font-weight:700;word-break:break-word;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">${reference}</div></div></div></td></tr><tr><td style="padding:16px 20px"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">KETENTUAN</div><div style="margin-top:6px;font-size:15px;line-height:1.55;font-weight:700;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">5 menit &middot; sekali pakai</div></div></div></td></tr></table>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#1d1b17" style="width:100%;margin:28px 0;border-collapse:separate;border-spacing:0;border:1px solid #4a4030;border-radius:14px;overflow:hidden;background:#1d1b17;background-color:#1d1b17;background-image:linear-gradient(#1d1b17,#1d1b17)"><tr><td style="padding:18px 20px;border-left:4px solid #9a741f"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.14em;color:#f0c86c!important;-webkit-text-fill-color:#f0c86c!important;mso-color-alt:#f0c86c">PERINGATAN KEAMANAN</div><p style="margin:10px 0 0;font-size:14px;line-height:1.65;color:#e8ebef!important;-webkit-text-fill-color:#e8ebef!important;mso-color-alt:#e8ebef">Jika Anda tidak meminta verifikasi ini, jangan gunakan kode. Jangan bagikan kode verifikasi, kata sandi, passkey, atau data akses akun kepada siapa pun.</p></div></div></td></tr></table>
          <div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">BANTUAN RESMI PT Dirac Inovasi Nusantara</div><p style="margin:9px 0 13px;font-size:14px;line-height:1.6;color:#9aa4b2!important;-webkit-text-fill-color:#9aa4b2!important;mso-color-alt:#9aa4b2">Butuh bantuan untuk memeriksa aktivitas keamanan? Gunakan kanal resmi perusahaan.</p></div></div>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10151e" style="width:100%;margin:0 0 13px;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:14px;overflow:hidden;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)">
            <tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">WHATSAPP</div><a href="https://wa.me/6287892523968" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">0878 9252 3968</a></div></div></td></tr>
            <tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">EMAIL SUPPORT</div><a href="mailto:${supportEmail}" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;word-break:break-all;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">${supportEmail}</a></div></div></td></tr>
            <tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">EMAIL PERUSAHAAN</div><a href="mailto:${careEmail}" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;word-break:break-all;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">${careEmail}</a></div></div></td></tr>
            ${socialSupportRowHtml}
          </table>
          <div class="gmail-blend-screen"><div class="gmail-blend-difference"><p style="margin:0;font-size:12px;line-height:1.65;color:#8f99a7!important;-webkit-text-fill-color:#8f99a7!important;mso-color-alt:#8f99a7">Tim PT Dirac Inovasi Nusantara tidak pernah meminta kata sandi, kode verifikasi, PIN, CVV, atau data akses akun melalui WhatsApp, Instagram, telepon, maupun balasan email.</p></div></div>
        </td></tr>
        <tr><td class="dirac-footer-pad" bgcolor="#b9dcff" style="padding:24px 26px 26px;border-top:1px solid #79aee5;background:#b9dcff;background-color:#b9dcff;background-image:linear-gradient(#b9dcff,#b9dcff)"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10213a" style="width:100%;border-collapse:separate;border-spacing:0;border:1px solid #24466c;border-radius:16px;overflow:hidden;box-shadow:0 10px 24px rgba(14,42,72,.18);background:#10213a;background-color:#10213a;background-image:linear-gradient(#10213a,#10213a)"><tr><td style="padding:22px 24px 23px;border-left:4px solid #27a2bd"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:18px;line-height:1.3;font-weight:800;letter-spacing:.14em;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;mso-color-alt:#ffffff">PT Dirac Inovasi Nusantara</div><div style="margin-top:7px;font-size:11px;line-height:1.5;font-weight:700;letter-spacing:.13em;color:#d9e8ff!important;-webkit-text-fill-color:#d9e8ff!important;mso-color-alt:#d9e8ff">AKUN &bull; PRIVASI &bull; BANTUAN</div><div style="margin-top:14px;font-size:13px;line-height:1.55;color:#d7e7f8!important;-webkit-text-fill-color:#d7e7f8!important;mso-color-alt:#d7e7f8">Layanan PT Dirac Inovasi Nusantara</div><p style="margin:17px 0 0;font-size:11px;line-height:1.65;color:#bfd0e3!important;-webkit-text-fill-color:#bfd0e3!important;mso-color-alt:#bfd0e3">Email ini dikirim otomatis. Jangan balas email ini atau bagikan kode verifikasi maupun data akses akun kepada orang lain.</p></div></div></td></tr></table></td></tr>
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
  rows.push('', 'Jika ada pertanyaan, balas email ini. Untuk berhenti menerima penawaran, sampaikan permintaan Anda melalui balasan email.');
  return rows.join('\n');
}
function customerMailHtml(message) {
  const parts = mailOriginParts(message.origin), shipment = message.shipmentNotice === true ? message.shipmentDetails : null;
  const privateKind = ['invoice', 'proforma', 'receipt', 'delivery'].includes(message.kind), labelText = customerMailKindLabel(message.kind);
  const banner = parts.bannerUrl ? '<tr><td bgcolor="#10151e" style="padding:0;line-height:0;font-size:0;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)"><img src="' + mailEscape(parts.bannerUrl) + '" width="600" alt="PT Dirac Inovasi Nusantara" style="display:block;width:100%;max-width:600px;height:auto;border:0;outline:none;text-decoration:none;background:#10151e;background-color:#10151e"></td></tr>' : '';
  const supportEmail = mailEscape(parts.supportEmail || ''), careEmail = mailEscape(parts.careEmail || ''), websiteUrl = mailEscape(parts.siteUrl || '');
  const socialSupportRowHtml = `<tr><td style="padding:16px 18px 13px;border-left:4px solid #148ba4"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">MEDIA SOSIAL</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;table-layout:fixed;border-collapse:collapse"><tr><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://x.com/achzaenuddin?s=11" target="_blank" rel="noopener noreferrer" aria-label="X" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:20px;font-weight:700;line-height:28px;text-align:center">X</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">X</span></a></td><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.facebook.com/share/1J3EEbguNX/?mibextid=wwXIfr" target="_blank" rel="noopener noreferrer" aria-label="Facebook" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:24px;font-weight:700;line-height:28px;text-align:center">f</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">Facebook</span></a></td><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.instagram.com/achzaenuddin15?stkn=MW4zc3FldjAzb21wNg%3D%3D&utm_source=qr" target="_blank" rel="noopener noreferrer" aria-label="Instagram" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><table role="presentation" width="22" height="22" cellpadding="0" cellspacing="0" border="0" style="width:22px;height:22px;border:2px solid #E2E8F0;border-radius:6px;border-collapse:separate;table-layout:fixed"><tr><td align="center" valign="middle" style="padding:0;font-size:0;line-height:0"><table role="presentation" width="10" height="10" cellpadding="0" cellspacing="0" border="0" style="width:10px;height:10px;border:2px solid #E2E8F0;border-radius:50%;border-collapse:separate"><tr><td style="padding:0;font-size:0;line-height:0">&nbsp;</td></tr></table></td></tr></table></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">Instagram</span></a></td></tr><tr><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.threads.com/@achzaenuddin15?igshid=NTc4MTIwNjQ2YQ==" target="_blank" rel="noopener noreferrer" aria-label="Threads" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:23px;font-weight:700;line-height:28px;text-align:center">@</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">Threads</span></a></td><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.linkedin.com/in/pt-dirac-inovasi-nusantara" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:17px;font-weight:700;line-height:28px;text-align:center">in</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">LinkedIn</span></a></td><td width="33.33%" align="center" valign="top" style="width:33.33%;padding:10px 2px;vertical-align:top"><a href="https://www.tiktok.com/@achzaenuddin" target="_blank" rel="noopener noreferrer" aria-label="TikTok" style="display:block;color:#E2E8F0;text-decoration:none"><table role="presentation" align="center" width="44" height="44" cellpadding="0" cellspacing="0" border="0" style="width:44px;height:44px;border:1px solid #8B7B58;border-radius:50%;border-collapse:separate;table-layout:fixed;margin:0 auto"><tr><td align="center" valign="middle" width="42" height="42" style="width:42px;height:42px;padding:0;font-size:0;line-height:0;vertical-align:middle"><span style="display:block;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:24px;font-weight:700;line-height:28px;text-align:center">&#9834;</span></td></tr></table><span style="display:block;margin-top:8px;color:#E2E8F0;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;line-height:16px;text-align:center;white-space:nowrap">TikTok</span></a></td></tr></table></div></div></td></tr>`;
  const executiveHtml = adminExecutiveEscalationHtml(supportEmail);
  const heading = mailEscape(shipment ? shipment.title : message.subject), preheader = mailEscape(shipment ? shipment.title + ' · ' + shipment.trackingNumber : labelText + ' · ' + message.subject);
  const statusText = shipment ? ({ prepared: 'BELUM DIKIRIM', shipped: 'DISERAHKAN KE KURIR', in_transit: 'DALAM PERJALANAN', delivered: 'DITERIMA', cancelled: 'DIBATALKAN' }[shipment.status] || 'STATUS BELUM TERSEDIA') : labelText.toUpperCase();
  const target = shipment ? mailEscape(shipmentCustomerOriginV450(message.origin) + '/cekresi.html') : '';
  let detailRows = '', routeTimeline = '', correspondence = '', shipmentNote = '';
  if (shipment) {
    const journey = shipmentJourneyV452(shipment.journey), currentPoint = journey ? journey.stops[journey.position] : shipment.location, nextPoint = journey && journey.position < journey.stops.length - 1 && shipment.status !== 'delivered' ? journey.stops[journey.position + 1] : '';
    const row = (title, value, last) => '<tr><td style="padding:16px 20px;' + (last ? '' : 'border-bottom:1px solid #2c3544;') + '"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">' + mailEscape(title) + '</div><div style="margin-top:6px;font-size:15px;line-height:1.55;font-weight:700;word-break:break-word;overflow-wrap:anywhere;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">' + mailEscape(value || 'Belum dicatat') + '</div></div></div></td></tr>';
    detailRows = row('NOMOR RESI', shipment.trackingNumber, false) + row('NOMOR PESANAN', shipment.orderCode, false) + row('KURIR', shipment.courier, false) + row('TITIK TERAKHIR', currentPoint, false);
    if (nextPoint) detailRows += row('BERIKUTNYA · RENCANA', nextPoint, false);
    detailRows += journey && journey.eta_start && shipment.status !== 'delivered' ? row('ESTIMASI PETUGAS · BUKAN JAMINAN', journey.eta_start + ' s.d. ' + journey.eta_end, true) : row('STATUS', statusText, true);
    if (journey) {
      const routeStop = index => {
        if (index >= journey.stops.length) return '';
        const current = index === journey.position, stop = journey.stops[index], number = String(index + 1).padStart(2, '0');
        return '<tr><td width="58" valign="top" style="width:58px;padding:14px 10px 14px 16px;border-right:1px solid #2c3544;border-left:4px solid ' + (current ? '#9a741f' : '#5276e8') + '"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:13px;line-height:1.45;font-weight:800;color:#c5ccd6!important;-webkit-text-fill-color:#c5ccd6!important;mso-color-alt:#c5ccd6">' + number + '</div></div></div></td><td valign="top" style="padding:14px 16px"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:15px;line-height:1.5;font-weight:700;word-break:break-word;overflow-wrap:anywhere;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">' + mailEscape(stop) + '</div>' + (current ? '<div style="margin-top:5px;font-size:10px;line-height:1.45;font-weight:800;letter-spacing:.12em;color:#f0c86c!important;-webkit-text-fill-color:#f0c86c!important;mso-color-alt:#f0c86c">TITIK LAPORAN TERAKHIR</div>' : '') + '</div></div></td></tr>';
      };
      routeTimeline = '<div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="margin:24px 0 11px;font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">URUTAN RENCANA RUTE</div></div></div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10151e" style="width:100%;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:14px;overflow:hidden;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)">' + routeStop(0) + routeStop(1) + routeStop(2) + routeStop(3) + routeStop(4) + routeStop(5) + routeStop(6) + routeStop(7) + routeStop(8) + routeStop(9) + routeStop(10) + routeStop(11) + '</table><div class="gmail-blend-screen"><div class="gmail-blend-difference"><p style="margin:11px 0 0;font-size:12px;line-height:1.6;color:#8f99a7!important;-webkit-text-fill-color:#8f99a7!important;mso-color-alt:#8f99a7">Titik beraksen emas adalah laporan terakhir yang dicatat admin. Titik lain adalah urutan rencana dan bukan bukti bahwa paket telah melewati lokasi tersebut.</p></div></div>';
    }
    if (shipment.description) correspondence = '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10151e" style="width:100%;margin:22px 0 0;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:14px;overflow:hidden;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)"><tr><td style="padding:18px 20px;border-left:4px solid #148ba4"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">CATATAN TERBARU</div><div style="margin-top:8px;font-size:14px;line-height:1.65;word-break:break-word;overflow-wrap:anywhere;color:#c5ccd6!important;-webkit-text-fill-color:#c5ccd6!important;mso-color-alt:#c5ccd6">' + mailEscape(shipment.description) + '</div></div></div></td></tr></table>';
    correspondence = routeTimeline + correspondence;
    shipmentNote = 'Status, titik, dan estimasi dicatat manual oleh petugas. Informasi ini bukan pelacakan GPS atau data langsung dari kurir.';
  } else {
    detailRows = '<tr><td style="padding:20px"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">ISI KORESPONDENSI</div><div style="margin-top:10px;font-size:15px;line-height:1.72;word-break:break-word;overflow-wrap:anywhere;color:#c5ccd6!important;-webkit-text-fill-color:#c5ccd6!important;mso-color-alt:#c5ccd6">' + mailEscape(String(message.body || '').replace(/\r\n?/g, '\n')).replace(/\n/g, '<br>') + '</div></div></div></td></tr>';
  }
  const attachment = message.attachment ? '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10151e" style="width:100%;margin:13px 0 0;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:14px;overflow:hidden;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)"><tr><td style="padding:16px 20px"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.13em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">LAMPIRAN</div><div style="margin-top:6px;font-size:15px;line-height:1.55;font-weight:700;word-break:break-word;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">' + mailEscape(message.attachment.name) + '</div></div></div></td></tr></table>' : '';
  const actionButton = target ? '<table class="dirac-button" role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;margin:0 0 9px;border-collapse:separate"><tr><td align="center" bgcolor="#5276e8" style="border-radius:10px;background:#5276e8;background-color:#5276e8"><a href="' + target + '" style="display:block;padding:17px 18px;font-size:15px;line-height:1.2;font-weight:800;letter-spacing:.04em;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;text-decoration:none;border-radius:10px">LIHAT RINCIAN PENGIRIMAN</a></td></tr></table>' : '';
  const targetHost = target ? mailEscape(new URL(target).hostname) : '';
  const warningTitle = shipment ? 'CATATAN PENGIRIMAN' : 'PERTANYAAN TENTANG EMAIL INI';
  const warningText = shipment ? shipmentNote : (privateKind ? 'Dokumen ini hanya untuk penerima yang tercantum. Jika ada pertanyaan tentang transaksi, balas email ini.' : 'Jika ada pertanyaan, balas email ini. Untuk berhenti menerima penawaran, sampaikan permintaan Anda melalui balasan email.');
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>Pemberitahuan PT Dirac Inovasi Nusantara</title>
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
  <div class="dirac-preheader">${preheader}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#090c12" style="width:100%;margin:0;padding:0;background:#090c12;background-color:#090c12;background-image:linear-gradient(#090c12,#090c12)">
    <tr><td class="dirac-outer-pad" align="center" bgcolor="#090c12" style="padding:18px 12px;background:#090c12;background-color:#090c12;background-image:linear-gradient(#090c12,#090c12)">
      <table class="dirac-shell" role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" bgcolor="#141820" data-dirac-customer-mail-shell="v465" style="width:100%;max-width:600px;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:18px;overflow:hidden;box-shadow:0 18px 48px rgba(0,0,0,.24);background:#141820;background-color:#141820;background-image:linear-gradient(#141820,#141820)">
        <tr><td style="padding:0;line-height:0;font-size:0"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td width="50%" height="4" bgcolor="#5276e8" style="height:4px;line-height:4px;font-size:0;background:#5276e8;background-color:#5276e8">&nbsp;</td><td width="30%" height="4" bgcolor="#148ba4" style="height:4px;line-height:4px;font-size:0;background:#148ba4;background-color:#148ba4">&nbsp;</td><td width="20%" height="4" bgcolor="#9a741f" style="height:4px;line-height:4px;font-size:0;background:#9a741f;background-color:#9a741f">&nbsp;</td></tr></table></td></tr>
        ${banner}
        <tr><td class="dirac-pad" bgcolor="#141820" style="padding:27px 32px 13px;background:#141820;background-color:#141820;background-image:linear-gradient(#141820,#141820)"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:21px;line-height:1.2;font-weight:800;letter-spacing:.14em;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">PT Dirac Inovasi Nusantara</div><div style="margin-top:7px;font-size:11px;line-height:1.4;font-weight:700;letter-spacing:.2em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">LAYANAN PELANGGAN</div></div></div></td></tr>
        <tr><td class="dirac-pad" bgcolor="#141820" style="padding:24px 32px 32px;background:#141820;background-color:#141820;background-image:linear-gradient(#141820,#141820)">
          <div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#9eb6ff!important;-webkit-text-fill-color:#9eb6ff!important;mso-color-alt:#9eb6ff">${shipment ? 'PEMBARUAN PENGIRIMAN' : 'KORESPONDENSI RESMI'}</div><div class="dirac-title" style="margin-top:13px;font-size:38px;line-height:1.16;font-weight:800;word-break:break-word;overflow-wrap:anywhere;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">${heading}</div>${shipment ? '<p style="margin:25px 0 0;font-size:17px;line-height:1.55;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">Yth. ' + mailEscape(shipment.customerName) + ',</p><p style="margin:12px 0 0;font-size:16px;line-height:1.65;color:#c5ccd6!important;-webkit-text-fill-color:#c5ccd6!important;mso-color-alt:#c5ccd6">Berikut pembaruan terbaru untuk pengiriman Anda.</p>' : '<p style="margin:25px 0 0;font-size:16px;line-height:1.65;color:#c5ccd6!important;-webkit-text-fill-color:#c5ccd6!important;mso-color-alt:#c5ccd6">Pesan resmi dari PT Dirac Inovasi Nusantara.</p>'}</div></div>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#1a1f29" style="width:100%;margin:24px 0 18px;border-collapse:separate;border-spacing:0;border:1px solid #303a49;border-radius:14px;overflow:hidden;box-shadow:0 8px 22px rgba(0,0,0,.12);background:#1a1f29;background-color:#1a1f29;background-image:linear-gradient(#1a1f29,#1a1f29)"><tr><td style="padding:18px 20px;border-left:4px solid #5276e8"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#9eb6ff!important;-webkit-text-fill-color:#9eb6ff!important;mso-color-alt:#9eb6ff">${shipment ? 'STATUS PENGIRIMAN' : 'JENIS KORESPONDENSI'}</div><div style="margin-top:8px;font-size:19px;line-height:1.45;font-weight:800;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9">${mailEscape(statusText)}</div><div style="margin-top:7px;font-size:13px;line-height:1.55;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">${shipment ? 'Pembaruan berasal dari pencatatan administrasi perusahaan.' : 'Korespondensi dikirim melalui kanal resmi perusahaan.'}</div></div></div></td></tr></table>
          ${actionButton}
          ${targetHost ? '<div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="margin:0 0 25px;text-align:center;font-size:12px;line-height:1.5;color:#8f99a7!important;-webkit-text-fill-color:#8f99a7!important;mso-color-alt:#8f99a7">Tujuan resmi: ' + targetHost + '</div><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">DETAIL INFORMASI</div></div></div>' : '<div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">DETAIL INFORMASI</div></div></div>'}
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10151e" style="width:100%;margin:13px 0 0;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:14px;overflow:hidden;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)">${detailRows}</table>
          ${correspondence}${attachment}
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#1d1b17" style="width:100%;margin:28px 0;border-collapse:separate;border-spacing:0;border:1px solid #4a4030;border-radius:14px;overflow:hidden;background:#1d1b17;background-color:#1d1b17;background-image:linear-gradient(#1d1b17,#1d1b17)"><tr><td style="padding:18px 20px;border-left:4px solid #9a741f"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.14em;color:#f0c86c!important;-webkit-text-fill-color:#f0c86c!important;mso-color-alt:#f0c86c">${warningTitle}</div><p style="margin:10px 0 0;font-size:14px;line-height:1.65;color:#e8ebef!important;-webkit-text-fill-color:#e8ebef!important;mso-color-alt:#e8ebef">${mailEscape(warningText)}</p></div></div></td></tr></table>
          <div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:12px;line-height:1.4;font-weight:800;letter-spacing:.16em;color:#aeb7c4!important;-webkit-text-fill-color:#aeb7c4!important;mso-color-alt:#aeb7c4">BANTUAN RESMI PT Dirac Inovasi Nusantara</div><p style="margin:9px 0 13px;font-size:14px;line-height:1.6;color:#9aa4b2!important;-webkit-text-fill-color:#9aa4b2!important;mso-color-alt:#9aa4b2">Butuh bantuan atau klarifikasi? Gunakan kanal resmi perusahaan.</p></div></div>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10151e" style="width:100%;margin:0 0 13px;border-collapse:separate;border-spacing:0;border:1px solid #2c3544;border-radius:14px;overflow:hidden;background:#10151e;background-color:#10151e;background-image:linear-gradient(#10151e,#10151e)">
            ${websiteUrl ? '<tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">WEBSITE RESMI</div><a href="' + websiteUrl + '" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;word-break:break-all;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">' + websiteUrl + '</a></div></div></td></tr>' : ''}
            <tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">WHATSAPP</div><a href="https://wa.me/6287892523968" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">0878 9252 3968</a></div></div></td></tr>
            ${supportEmail ? '<tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">EMAIL SUPPORT</div><a href="mailto:' + supportEmail + '" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;word-break:break-all;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">' + supportEmail + '</a></div></div></td></tr>' : ''}
            ${careEmail ? '<tr><td style="padding:15px 20px;border-left:4px solid #148ba4;border-bottom:1px solid #2c3544"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:11px;line-height:1.4;font-weight:800;letter-spacing:.12em;color:#7f8a99!important;-webkit-text-fill-color:#7f8a99!important;mso-color-alt:#7f8a99">EMAIL PERUSAHAAN</div><a href="mailto:' + careEmail + '" style="display:inline-block;margin-top:5px;font-size:15px;line-height:1.5;font-weight:700;word-break:break-all;color:#f4f6f9!important;-webkit-text-fill-color:#f4f6f9!important;mso-color-alt:#f4f6f9;text-decoration:none">' + careEmail + '</a></div></div></td></tr>' : ''}
            ${socialSupportRowHtml}
          </table>
          <div class="gmail-blend-screen"><div class="gmail-blend-difference"><p style="margin:0;font-size:12px;line-height:1.65;color:#8f99a7!important;-webkit-text-fill-color:#8f99a7!important;mso-color-alt:#8f99a7">Tim PT Dirac Inovasi Nusantara tidak pernah meminta kata sandi, kode verifikasi, PIN, CVV, atau data akses akun melalui WhatsApp, Instagram, telepon, maupun balasan email.</p></div></div>
        </td></tr>
        <tr><td class="dirac-footer-pad" bgcolor="#b9dcff" style="padding:24px 26px 26px;border-top:1px solid #79aee5;background:#b9dcff;background-color:#b9dcff;background-image:linear-gradient(#b9dcff,#b9dcff)"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#10213a" style="width:100%;border-collapse:separate;border-spacing:0;border:1px solid #24466c;border-radius:16px;overflow:hidden;box-shadow:0 10px 24px rgba(14,42,72,.18);background:#10213a;background-color:#10213a;background-image:linear-gradient(#10213a,#10213a)"><tr><td style="padding:22px 24px 23px;border-left:4px solid #27a2bd"><div class="gmail-blend-screen"><div class="gmail-blend-difference"><div style="font-size:18px;line-height:1.3;font-weight:800;letter-spacing:.14em;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;mso-color-alt:#ffffff">PT Dirac Inovasi Nusantara</div><div style="margin-top:7px;font-size:11px;line-height:1.5;font-weight:700;letter-spacing:.13em;color:#d9e8ff!important;-webkit-text-fill-color:#d9e8ff!important;mso-color-alt:#d9e8ff">AKUN &bull; PRIVASI &bull; BANTUAN</div><div style="margin-top:14px;font-size:13px;line-height:1.55;color:#d7e7f8!important;-webkit-text-fill-color:#d7e7f8!important;mso-color-alt:#d7e7f8">Layanan PT Dirac Inovasi Nusantara</div><p style="margin:17px 0 0;font-size:11px;line-height:1.65;color:#bfd0e3!important;-webkit-text-fill-color:#bfd0e3!important;mso-color-alt:#bfd0e3">Jangan bagikan kode verifikasi atau data akses akun kepada orang lain.</p></div></div></td></tr></table></td></tr>
        <tr><td style="padding:0 0 18px">${executiveHtml}</td></tr>
        <tr><td style="padding:0;line-height:0;font-size:0"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse"><tr><td width="50%" height="4" bgcolor="#5276e8" style="height:4px;line-height:4px;font-size:0;background:#5276e8;background-color:#5276e8">&nbsp;</td><td width="30%" height="4" bgcolor="#148ba4" style="height:4px;line-height:4px;font-size:0;background:#148ba4;background-color:#148ba4">&nbsp;</td><td width="20%" height="4" bgcolor="#9a741f" style="height:4px;line-height:4px;font-size:0;background:#9a741f;background-color:#9a741f">&nbsp;</td></tr></table></td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
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
  return { owner: ADMIN_OWNER_V466, binding: identity.binding, origin: identity.origin, rpId: origin.hostname };
}
function configKey(scope) { return PREFIX + 'enrollment:' + digest(scope.owner + ':' + scope.origin); }
async function stored(ops, key) { ops.assertFullGuard(); const result = await ops.read(key); ops.assertFullGuard(); if (!result || result.ok !== true) fail('ADMIN_STORE_UNAVAILABLE', 503); return result.found === true ? result.record : null; }
async function config(ops, scope) {
  const key = configKey(scope); let value = await stored(ops, key);
  if (!value) {
    const legacyOwner = legacyAdminOwnerV466(), legacyKey = configKey({ owner: legacyOwner, origin: scope.origin });
    if (legacyKey !== key) {
      const legacy = await stored(ops, legacyKey);
      if (legacy) {
        const migrated = { ...legacy, owner: scope.owner, revision: randomToken(), legacyConfigKeyV466: legacyKey };
        if (await ops.claim(key, migrated, migrated.enrollmentState === 'pending_totp' ? PENDING_ENROLLMENT_SECONDS : ENROLLMENT_SECONDS) === true) value = migrated;
        else value = await stored(ops, key);
      }
    }
  }
  if (!value) return null;
  const enrollmentState = value.enrollmentState === undefined ? 'active' : value.enrollmentState;
  if (value.version !== VERSION || value.owner !== scope.owner || value.origin !== scope.origin || !exactToken(value.revision) || !value.passkey || !exactToken(value.userHandle) || !Number.isSafeInteger(value.passkey.signCount) || value.passkey.signCount < 0 || typeof value.totp !== 'string' || !['active', 'pending_totp'].includes(enrollmentState)) fail('ADMIN_ENROLLMENT_INVALID', 503);
  return value.enrollmentState === enrollmentState ? value : { ...value, enrollmentState };
}
// v466: bind the fixed admin destination, both admin-only environment secrets, and the encrypted TOTP state.
// The binding contains no raw secret and may only be created/refreshed after a successful passkey ceremony.
function adminFactorGuardV466(enrolled) {
  const primary = adminSecretState(), recovery = adminPasskeyRecoverySecretState();
  if (!primary.configured || !recovery.configured || !enrolled || typeof enrolled.totp !== 'string') fail('ADMIN_FACTOR_GUARD_UNAVAILABLE', 503);
  const key = deriveSecret('admin-factor-immutability-v466');
  try {
    return crypto.createHmac('sha512', key).update(stableJson({ version: 466, owner: ADMIN_OWNER_V466, email: ADMIN_EMAIL, admin_secret: secretBinding(primary.secret), recovery_secret: secretBinding(recovery.secret), totp: digest(enrolled.totp), totp_key: enrolled.totpKeyV466 === true ? 466 : 405 })).digest('base64url');
  } finally { key.fill(0); }
}
function sealAdminFactorGuardV466(enrolled) { return { ...enrolled, factorGuardV466: adminFactorGuardV466(enrolled) }; }
function assertAdminFactorGuardV466(enrolled) {
  if (!enrolled || typeof enrolled.factorGuardV466 !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(enrolled.factorGuardV466) || !safeEqual(enrolled.factorGuardV466, adminFactorGuardV466(enrolled))) fail('ADMIN_FACTOR_GUARD_MISMATCH', 403);
  return true;
}
function totpKeyPurposeV466(enrolled) { return enrolled && enrolled.totpKeyV466 === true ? 'totp-storage' : 'totp-storage-legacy'; }
function migrateTotpKeyAfterPasskeyV466(ops, scope, enrolled) {
  if (!enrolled || enrolled.totpKeyV466 === true) return enrolled;
  const legacyContext = typeof enrolled.legacyConfigKeyV466 === 'string' ? enrolled.legacyConfigKeyV466 : configKey(scope);
  const secret = open(ops, enrolled.totp, legacyContext, 'totp-storage-legacy');
  try { const next = { ...enrolled, totp: seal(ops, secret, configKey(scope)), totpKeyV466: true }; delete next.legacyConfigKeyV466; return next; } finally { secret.fill(0); }
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
async function session(ops, scope, must = true, enforceFactorGuard = true) {
  const raw = ops.readSession(); if (!exactToken(raw)) { if (must) fail('ADMIN_THREE_FACTORS_REQUIRED', 401); return null; }
  try { const entry = await ticket(ops, scope, raw, 'session'); if (entry.value.factors !== 'email+passkey+totp') fail('ADMIN_THREE_FACTORS_REQUIRED', 401); if (enforceFactorGuard) assertAdminFactorGuardV466(await config(ops, scope)); return entry; }
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
  const secret = open(ops, enrolled.totp, configKey(scope), totpKeyPurposeV466(enrolled)); let accepted = null;
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
    return { ok: true, email: ADMIN_EMAIL_MASKED, credentials_required: true, credentials_configured: configured, passkey_recovery_configured: adminPasskeyRecoverySecretState().configured, factor_count: 3, email_code_min: EMAIL_CODE_MIN, email_code_max: EMAIL_CODE_MAX, email_code_seconds: EMAIL_CODE_SECONDS, totp_period: 30 };
  }
  if (action === 'admin_security_report') {
    await throttle(ops, scope, 'security-report', 3, 60);
    const report = validateSecurityReport(body), result = await ops.securityReport(report);
    if (!result || !Number.isSafeInteger(result.blockedUntil) || result.blockedUntil <= Date.now()) fail('ADMIN_SECURITY_STORE_UNAVAILABLE', 503);
    fail('ADMIN_SECURITY_BLOCKED', 403);
  }
  if (action === 'admin_login') {
    await throttle(ops, scope, 'password-login', 5, FACTOR_SECONDS);
    if (String(body.email || '').trim().toLowerCase() !== ADMIN_EMAIL_MASKED || typeof body.password !== 'string' || body.password.length > 4096 || !ops.verifySecret(body.password)) fail('ADMIN_CREDENTIALS_INVALID', 401);
    await ops.publishPassword();
    return { ok: true, stage: 'email', credentials_verified: true, email: ADMIN_EMAIL_MASKED };
  }
  if (action === 'admin_status') {
    const nonceTarget = body._dirac_page_nonce_for;
    if (typeof nonceTarget === 'string' && Object.prototype.hasOwnProperty.call(CONTRACTS, nonceTarget) && CONTRACTS[nonceTarget].methods.includes('POST')) return { ok: true };
    const [enrolled, active] = await Promise.all([config(ops, scope), session(ops, scope, false)]);
    return { ok: true, email: ADMIN_EMAIL_MASKED, enrolled: !!enrolled, enrollment_state: enrolled ? enrolled.enrollmentState : 'none', passkey_storage: ADMIN_PASSKEY_TABLE, authenticated: !!active, passkey_recovery_configured: adminPasskeyRecoverySecretState().configured, factor_count: 3, email_code_min: EMAIL_CODE_MIN, email_code_max: EMAIL_CODE_MAX, email_code_seconds: EMAIL_CODE_SECONDS, totp_period: 30, expires_at: null, persistent_session: !!active, action_email_required: false, action_passkey_required: true };
  }
  if (action === 'admin_email_start') {
    await adminEmailRateTakeV491(ops, scope);
    const code = adminEmailCode(), codeLength = code.length, salt = randomToken(), reference = crypto.randomBytes(12).toString('hex');
    const token = await issue(ops, scope, 'email', { salt, codeHash: digest(salt + ':' + code), reference, codeLength }, EMAIL_CODE_SECONDS); const delivered = await ops.mail({ to: ADMIN_EMAIL, code, reference, expiresAt: Date.now() + EMAIL_CODE_SECONDS * 1000, kind: 'login', operation: '' });
    if (!delivered || delivered.ok !== true) fail('ADMIN_EMAIL_DELIVERY_UNCONFIRMED', 503); return { ok: true, ticket: token, stage: 'email', email: ADMIN_EMAIL_MASKED, code_length: codeLength, min_chars: EMAIL_CODE_MIN, max_chars: EMAIL_CODE_MAX, expires_in: EMAIL_CODE_SECONDS, one_time: true };
  }
  if (action === 'admin_email_verify') {
    const entry = await ticket(ops, scope, body.ticket, 'email'); await throttle(ops, scope, 'email-verify:' + digest(body.ticket), 5, FACTOR_SECONDS);
    if (!Number.isInteger(entry.value.codeLength) || entry.value.codeLength < EMAIL_CODE_MIN || entry.value.codeLength > EMAIL_CODE_MAX || !validAdminEmailCode(body.code) || body.code.length !== entry.value.codeLength || !safeEqual(digest(entry.value.salt + ':' + body.code), entry.value.codeHash)) fail('ADMIN_EMAIL_CODE_INVALID', 401);
    await consume(ops, entry); await adminEmailRateResetV491(ops, scope); return { ok: true, ticket: await issue(ops, scope, 'passkey-start'), stage: 'passkey' };
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
    const next = sealAdminFactorGuardV466({ ...migrateTotpKeyAfterPasskeyV466(ops, scope, enrolled), passkey: { ...enrolled.passkey, signCount: verified.signCount }, revision: randomToken() });
    if (await ops.replace(configKey(scope), enrolled.revision, next, ENROLLMENT_SECONDS) !== true) fail('ADMIN_PASSKEY_STATE_CHANGED', 409);
    await consume(ops, entry); const approval = await issue(ops, scope, 'action-approval', { operation: proof.operation, payloadHash: proof.payloadHash }, EMAIL_CODE_SECONDS);
    return { ok: true, approval, operation: proof.operation, expires_in: EMAIL_CODE_SECONDS, one_time: true };
  }
  if (action === 'admin_passkey_start') {
    const entry = await ticket(ops, scope, body.ticket, 'passkey-start'), enrolled = await config(ops, scope); await consume(ops, entry);
    const challenge = randomToken(), userHandle = enrolled ? enrolled.userHandle : randomToken(), mode = enrolled ? 'authentication' : 'registration';
    const token = await issue(ops, scope, 'passkey', { challenge, mode, userHandle, revision: enrolled ? enrolled.revision : null });
    const publicKey = mode === 'registration' ? { challenge, rp: { id: scope.rpId, name: 'PT DIRAC INOVASI NUSANTARA' }, user: { id: userHandle, name: ADMIN_EMAIL_MASKED, displayName: 'Administrator DIRAC' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' }, timeout: 60000, attestation: 'none' } : { challenge, rpId: scope.rpId, userVerification: 'required', timeout: 60000, allowCredentials: [{ id: enrolled.passkey.credentialId, type: 'public-key' }] };
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
        const encrypted = seal(ops, secret, configKey(scope));
        provisioning = { secret: base32(secret) };
        const pending = sealAdminFactorGuardV466({ version: VERSION, owner: scope.owner, origin: scope.origin, enrollmentState: 'pending_totp', revision: randomToken(), passkey, userHandle: proof.userHandle, totp: encrypted, totpKeyV466: true, createdAt: Date.now() });
        if (await ops.claim(configKey(scope), pending, PENDING_ENROLLMENT_SECONDS) !== true) fail('ADMIN_ALREADY_ENROLLED', 409); enrolled = pending;
      } finally { secret.fill(0); }
    } else {
      if (!enrolled || proof.revision !== enrolled.revision || credential.id !== enrolled.passkey.credentialId) fail('ADMIN_PASSKEY_STATE_CHANGED', 409); const handle = credential.response.userHandle;
      if (handle !== null && handle !== undefined && handle !== '' && handle !== enrolled.userHandle) fail('ADMIN_PASSKEY_USER_MISMATCH', 403); const verified = await ops.verifyAssertion({ credential, clientData, rpId: scope.rpId, passkey: enrolled.passkey });
      if (!verified || verified.ok !== true) fail('ADMIN_PASSKEY_INVALID', 403); passkey = { ...enrolled.passkey, signCount: verified.signCount }; const next = sealAdminFactorGuardV466({ ...migrateTotpKeyAfterPasskeyV466(ops, scope, enrolled), passkey, revision: randomToken() });
      if (await ops.replace(configKey(scope), enrolled.revision, next, next.enrollmentState === 'pending_totp' ? PENDING_ENROLLMENT_SECONDS : ENROLLMENT_SECONDS) !== true) fail('ADMIN_PASSKEY_STATE_CHANGED', 409); enrolled = next;
      if (enrolled.enrollmentState === 'pending_totp') { const secret = open(ops, enrolled.totp, configKey(scope), totpKeyPurposeV466(enrolled)); try { provisioning = { secret: base32(secret) }; } finally { secret.fill(0); } }
    }
    await consume(ops, entry); const pending = enrolled.enrollmentState === 'pending_totp';
    const token = await issue(ops, scope, 'totp', { enroll: pending, totpBinding: digest(enrolled.totp), revision: enrolled.revision }); return { ok: true, ticket: token, stage: 'totp', enrollment: pending ? provisioning : null, period: 30 };
  }
  if (action === 'admin_passkey_recovery_start') {
    const recoveryState = adminPasskeyRecoverySecretState(); if (!recoveryState.configured) fail('ADMIN_PASSKEY_RECOVERY_NOT_CONFIGURED', 503);
    const entry = await adminPasskeyRecoveryTicket(ops, scope, body.ticket), enrolled = await config(ops, scope);
    await throttle(ops, scope, 'passkey-recovery-hour', 2, 3600);
    if (!verifyAdminPasskeyRecoverySecret(body.recovery_secret)) fail('ADMIN_PASSKEY_RECOVERY_INVALID', 403);
    if (!enrolled || enrolled.enrollmentState !== 'active') fail('ADMIN_ENROLLMENT_STATE_CHANGED', 409);
    assertAdminFactorGuardV466(enrolled);
    await adminVerifyRecoveryTotp(ops, scope, enrolled, body.totp_code);
    await consume(ops, entry);
    const reference = crypto.randomBytes(12).toString('hex'), delivered = await ops.recoveryAlert({ to: ADMIN_EMAIL, kind: 'recovery', event: 'started', reference, origin: scope.origin });
    if (!delivered || delivered.ok !== true) fail('ADMIN_EMAIL_DELIVERY_UNCONFIRMED', 503);
    const challenge = randomToken(), token = await issue(ops, scope, 'passkey-recovery', { challenge, mode: 'registration', userHandle: enrolled.userHandle, revision: enrolled.revision, reference }, FACTOR_SECONDS);
    return { ok: true, ticket: token, stage: 'passkey-recovery', mode: 'registration', publicKey: { challenge, rp: { id: scope.rpId, name: 'PT DIRAC INOVASI NUSANTARA' }, user: { id: enrolled.userHandle, name: ADMIN_EMAIL_MASKED, displayName: 'Administrator DIRAC' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' }, timeout: 60000, attestation: 'none' }, alert_reference: reference };
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
    // Existing short-lived tickets remain valid only with their exact encrypted value; new tickets carry a digest.
    const bound = enrolled && (Object.prototype.hasOwnProperty.call(proof, 'totpBinding')
      ? typeof proof.totpBinding === 'string' && /^[a-f0-9]{64}$/.test(proof.totpBinding) && safeEqual(digest(enrolled.totp), proof.totpBinding)
      : typeof proof.totp === 'string' && safeEqual(enrolled.totp, proof.totp));
    if (!enrolled || enrolled.revision !== proof.revision || !bound || (proof.enroll ? enrolled.enrollmentState !== 'pending_totp' : enrolled.enrollmentState !== 'active')) fail('ADMIN_ENROLLMENT_STATE_CHANGED', 409);
    assertAdminFactorGuardV466(enrolled);
    const secret = open(ops, enrolled.totp, configKey(scope), totpKeyPurposeV466(enrolled)); let accepted = null;
    try { const current = Math.floor(Date.now() / 30000), match = [current, current - 1, current + 1].find(counter => safeEqual(totp(secret, counter), body.code)); accepted = Number.isSafeInteger(match) ? match : null; } finally { secret.fill(0); }
    if (accepted === null) fail('ADMIN_TOTP_INVALID', 401); if (await ops.claim(PREFIX + 'totp-used:' + digest(scope.owner + ':' + scope.origin + ':' + enrolled.totp + ':' + accepted), { version: VERSION }, 120) !== true) fail('ADMIN_TOTP_ALREADY_USED', 409); await consume(ops, entry);
    if (proof.enroll) { const active = { ...enrolled, enrollmentState: 'active', revision: randomToken(), activatedAt: Date.now() }; if (await ops.replace(configKey(scope), enrolled.revision, active, ENROLLMENT_SECONDS) !== true) fail('ADMIN_ENROLLMENT_STATE_CHANGED', 409); }
    const token = await issue(ops, scope, 'session', { factors: 'email+passkey+totp' }, SESSION_SECONDS); ops.setSession(token, SESSION_SECONDS); return { ok: true, stage: 'complete', authenticated: true, expires_in: null, persistent_session: true, action_email_required: false, action_passkey_required: true };
  }
  if (action === 'admin_logout') { const active = await session(ops, scope, false, false); if (active) await consume(ops, active); await ops.clearSession(); return { ok: true }; }
  await session(ops, scope); const operation = { admin_orders: 'orders', admin_shipment_update: 'shipment_update', admin_shipment_cancel: 'shipment_cancel', admin_blocks: 'blocks', admin_banned_data: 'banned_data', admin_unban: 'unban', admin_banned_pdf: 'banned_pdf', admin_account_create: 'account_create', admin_account_disable: 'account_create', admin_account_enable: 'account_create', admin_account_delete: 'account_create', admin_account_password_reset: 'account_create', admin_account_passkey_reset: 'account_create', admin_partner_requests: 'partner_requests', admin_partner_request_update: 'partner_request_update', admin_smtp_send: 'smtp_send', admin_local_authorize: 'local_authorize', admin_document_prepare: 'document_prepare', admin_document_seal: 'document_seal', admin_document_verify: 'document_verify', admin_monitor: 'monitor' }[action];
  if (!operation) fail('ADMIN_ACTION_INVALID', 400);
  if (Object.prototype.hasOwnProperty.call(ADMIN_APPROVAL_MUTATIONS, action)) { const approval = await ticket(ops, scope, body.approval, 'action-approval'); if (approval.value.operation !== action || approval.value.payloadHash !== approvalPayloadHash(action, body)) fail('ADMIN_ACTION_APPROVAL_MISMATCH', 403); await consume(ops, approval); }
  if (action === 'admin_smtp_send') { await throttle(ops, scope, 'smtp-send-minute', 2, 60); await throttle(ops, scope, 'smtp-send-hour', 5, 3600); }
  if (Object.prototype.hasOwnProperty.call(ADMIN_ACCOUNT_ACTION_MODES, action)) { await throttle(ops, scope, 'account-create-minute', 3, 60); await throttle(ops, scope, 'account-create-hour', 5, 3600); }
  if (action === 'admin_partner_request_update') { await throttle(ops, scope, 'partner-request-update-minute', 6, 60); await throttle(ops, scope, 'partner-request-update-hour', 30, 3600); }
  if (action === 'admin_banned_pdf') { await throttle(ops, scope, 'banned-pdf-minute', 3, 60); await throttle(ops, scope, 'banned-pdf-hour', 5, 3600); }
  const businessBody = Object.prototype.hasOwnProperty.call(ADMIN_ACCOUNT_ACTION_MODES, action) ? { ...body, mode: ADMIN_ACCOUNT_ACTION_MODES[action] } : body;
  ops.assertFullGuard(); return ops.business(operation, businessBody);
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
function shipmentEnvelopeTimeV457(recordUpdatedAt, rowUpdatedAt) {
  const recordTime = shipmentTimestamp(recordUpdatedAt), rowTime = shipmentTimestamp(rowUpdatedAt);
  return recordTime !== null && rowTime !== null && rowTime >= recordTime && rowTime - recordTime <= 5000000n;
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
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schema !== 'dirac.admin_shipment.v406' || !['active', 'cancelled'].includes(value.state) || !isUuid(value.customer_id) || !isUuid(value.updated_by) || !Number.isSafeInteger(value.revision) || value.revision < 1 || !['prepared', 'shipped', 'in_transit', 'delivered', 'cancelled'].includes(value.status) || (value.state === 'cancelled') !== (value.status === 'cancelled') || shipmentTimestamp(value.updated_at) === null || !shipmentEnvelopeTimeV457(value.updated_at, row.updated_at) || !Array.isArray(value.events) || value.events.length < 1 || value.events.length > 50) return null;
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
// V482: bounded read-only summary/finance pages. Shipment/customer payload is never fetched for these views.
async function businessSummaryV456(body) {
  const kind = String(body.kind || 'regular'), rawOffset = String(body.offset || '0'), view = String(body.view || '');
  const from = String(body.from || ''), until = String(body.until || '');
  const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
  const start = Date.parse(from), end = Date.parse(until);
  if (!['summary','finance'].includes(view) || !Object.prototype.hasOwnProperty.call(ORDER_SELECT, kind) || !/^(0|[1-9][0-9]{0,4})$/.test(rawOffset) || Number(rawOffset) > 49800 || Number(rawOffset) % 200 !== 0) fail(view === 'finance' ? 'ADMIN_FINANCE_RANGE_INVALID' : 'ADMIN_SUMMARY_RANGE_INVALID', 400);
  if (!iso.test(from) || !iso.test(until) || !Number.isFinite(start) || !Number.isFinite(end) || new Date(start).toISOString() !== from || new Date(end).toISOString() !== until || start < Date.UTC(1999, 11, 31, 10) || start >= end || end > Date.now() + 60000) fail(view === 'finance' ? 'ADMIN_FINANCE_RANGE_INVALID' : 'ADMIN_SUMMARY_RANGE_INVALID', 400);
  const table = kind === 'domain' ? 'domain_orders' : 'orders';
  const select = kind === 'domain' ? 'id,total_price,currency,payment_status,created_at' : 'id,total,payment_status,created_at';
  const suffix = '&created_at=gte.' + encodeURIComponent(from) + '&created_at=lt.' + encodeURIComponent(until) + '&order=created_at.desc,id.desc&limit=201&offset=' + Number(rawOffset);
  let result = await dbFetch('/rest/v1/' + table + '?select=' + encodeURIComponent(select) + suffix, { method: 'GET' }, kind === 'laboratorium' ? 'security' : '');
  let implicitCurrency = kind !== 'domain';
  if (kind === 'domain' && domainOrderUndefinedColumn(result)) {
    result = await dbFetch('/rest/v1/domain_orders?select=' + encodeURIComponent('id,total_price,payment_status,created_at') + suffix, { method: 'GET' });
    implicitCurrency = true;
  }
  if (!result.ok || !Array.isArray(result.data) || result.data.length > 201) fail('ADMIN_DATA_UNAVAILABLE', 503);
  const seen = new Set(), financeRows = []; let lastTime = Infinity;
  const totals = result.data.slice(0, 200).reduce((out, row) => {
    if (!row || typeof row !== 'object' || !isUuid(row.id) || seen.has(row.id)) fail(view === 'finance' ? 'ADMIN_FINANCE_DATA_INVALID' : 'ADMIN_SUMMARY_DATA_INVALID', 503);
    const time = Date.parse(row.created_at), raw = kind === 'domain' ? row.total_price : row.total;
    if ((typeof raw !== 'number' && typeof raw !== 'string') || !/^[0-9]+(?:\.[0-9]{1,2})?$/.test(String(raw))) fail(view === 'finance' ? 'ADMIN_FINANCE_DATA_INVALID' : 'ADMIN_SUMMARY_DATA_INVALID', 503);
    const minor = Math.round(Number(raw) * 100), currency = implicitCurrency || row.currency == null || row.currency === '' ? 'IDR' : String(row.currency).toUpperCase();
    if (!Number.isFinite(time) || time < start || time >= end || time > lastTime || !Number.isSafeInteger(minor) || minor < 0 || !/^[A-Z]{3}$/.test(currency) || (row.payment_status != null && (typeof row.payment_status !== 'string' || row.payment_status.length > 80))) fail(view === 'finance' ? 'ADMIN_FINANCE_DATA_INVALID' : 'ADMIN_SUMMARY_DATA_INVALID', 503);
    seen.add(row.id); lastTime = time;
    const status = String(row.payment_status || '').trim().toLowerCase();
    const paid = ['paid', 'sudah bayar'].includes(status), refunded = ['refunded', 'refund'].includes(status), open = ['unpaid', 'pending', 'created', 'belum bayar'].includes(status);
    if (view === 'finance') financeRows.push({ id: row.id, kind, total: minor / 100, currency, payment_status: status, created_at: String(row.created_at || '') });
    else {
      out.orders += 1; out.paid += Number(paid); out.refunded += Number(refunded); out.open += Number(open); out.other += Number(!paid && !refunded && !open);
      if (kind === 'domain' && (implicitCurrency || row.currency == null || row.currency === '')) out.implicit_idr += 1;
      if (currency !== 'IDR') out.non_idr += 1;
      else {
        out.paid_minor += paid ? minor : 0; out.refunded_minor += refunded ? minor : 0; out.open_minor += open ? minor : 0;
        if (![out.paid_minor, out.refunded_minor, out.open_minor].every(Number.isSafeInteger)) fail('ADMIN_SUMMARY_DATA_INVALID', 503);
      }
    }
    return out;
  }, { orders: 0, paid: 0, refunded: 0, open: 0, other: 0, non_idr: 0, implicit_idr: 0, paid_minor: 0, refunded_minor: 0, open_minor: 0 });
  const common = { ok: true, view, kind, offset: Number(rawOffset), page_size: 200, from, until, has_more: result.data.length === 201, time: new Date().toISOString() };
  return view === 'finance' ? { ...common, orders: financeRows } : { ...common, totals };
}

async function businessOrdersSingleV480(body) {
  const kind = String(body.kind || 'regular'), offsetRaw = String(body.offset || '0'); if (!Object.prototype.hasOwnProperty.call(ORDER_SELECT, kind) || !/^(0|[1-9][0-9]{0,4})$/.test(offsetRaw) || Number(offsetRaw) > 50000) fail('ADMIN_PAGE_INVALID', 400);
  const table = kind === 'domain' ? 'domain_orders' : 'orders', suffix = '&order=created_at.desc,id.desc&limit=41&offset=' + Number(offsetRaw), path = '/rest/v1/' + table + '?select=' + encodeURIComponent(ORDER_SELECT[kind]) + suffix; let result = await dbFetch(path, { method: 'GET' }, kind === 'laboratorium' ? 'security' : '');
  if (kind === 'domain' && domainOrderUndefinedColumn(result)) result = await dbFetch('/rest/v1/domain_orders?select=' + encodeURIComponent(DOMAIN_ORDER_COMPAT_SELECT) + suffix, { method: 'GET' });
  if (!result.ok || !Array.isArray(result.data) || result.data.length > 41) fail('ADMIN_DATA_UNAVAILABLE', 503); const rows = result.data, orders = rows.slice(0, 40).map(row => orderPublic(row, kind)), keys = orders.map(row => shipmentKey(kind, row.id));
  let shipments = []; if (keys.length) { const shipped = await dbFetch('/rest/v1/dirac_s2s_security?select=' + encodeURIComponent(SHIPMENT_SELECT) + '&security_key=in.(' + keys.map(encodeURIComponent).join(',') + ')&limit=' + keys.length, { method: 'GET' }, 'security'); if (!shipped.ok || !Array.isArray(shipped.data) || shipped.data.length > keys.length) fail('ADMIN_SHIPMENT_RECORD_INVALID', 503); shipments = shipped.data; }
  const map = new Map(); shipments.forEach(row => { if (!keys.includes(row && row.security_key) || map.has(row.security_key)) fail('ADMIN_SHIPMENT_RECORD_INVALID', 503); const value = validateShipmentRow(row, row.security_key), order = orders.find(item => item.id === (value && value.order_id)); if (!value || !order || (order.customer_id !== value.customer_id && value.updated_by !== ADMIN_USER_ID)) fail('ADMIN_SHIPMENT_OWNER_MISMATCH', 503); map.set(row.security_key, value); });
  return { ok: true, kind, offset: Number(offsetRaw), has_more: rows.length === 41, orders: orders.map(row => ({ ...row, shipment: shipmentPublic(map.get(shipmentKey(kind, row.id))) })), time: new Date().toISOString() };
}
function businessOrdersBundleSourceV480(result, kind) {
  return result && result.ok === true && result.data && result.data.kind === kind ? { ok: true, kind, data: result.data } : { ok: false, kind };
}
function businessFinancePairV484(first, second, kind) {
  if (!first || !second || first.ok !== true || second.ok !== true || first.view !== 'finance' || second.view !== 'finance' || first.kind !== kind || second.kind !== kind || first.page_size !== 200 || second.page_size !== 200 || second.offset !== first.offset + 200 || first.from !== second.from || first.until !== second.until || !Array.isArray(first.orders) || !Array.isArray(second.orders) || first.orders.length > 200 || second.orders.length > 200 || (first.has_more === true && first.orders.length !== 200) || (second.has_more === true && second.orders.length !== 200) || (first.has_more === false && (second.orders.length !== 0 || second.has_more !== false))) fail('ADMIN_FINANCE_DATA_INVALID', 503);
  return { ...first, page_size: 400, has_more: second.has_more, orders: [...first.orders, ...second.orders], time: new Date().toISOString() };
}
async function businessOrders(body) {
  const kind = String(body.kind || 'regular');
  if (body.view !== undefined || body.from !== undefined || body.until !== undefined) {
    if (kind !== 'all') return businessSummaryV456(body);
    const view = String(body.view || '');
    if (view === 'finance') {
      const offsetRaw = String(body.offset || '0');
      if (!/^(0|[1-9][0-9]{0,4})$/.test(offsetRaw) || Number(offsetRaw) > 49600 || Number(offsetRaw) % 400 !== 0) fail('ADMIN_FINANCE_RANGE_INVALID', 400);
      const offsetNext = String(Number(offsetRaw) + 200), financePages = await Promise.all([
        businessSummaryV456({ ...body, kind: 'regular', offset: offsetRaw }),
        businessSummaryV456({ ...body, kind: 'laboratorium', offset: offsetRaw }),
        businessSummaryV456({ ...body, kind: 'domain', offset: offsetRaw }),
        businessSummaryV456({ ...body, kind: 'regular', offset: offsetNext }),
        businessSummaryV456({ ...body, kind: 'laboratorium', offset: offsetNext }),
        businessSummaryV456({ ...body, kind: 'domain', offset: offsetNext })
      ]);
      const pages = [
        businessFinancePairV484(financePages[0], financePages[3], 'regular'),
        businessFinancePairV484(financePages[1], financePages[4], 'laboratorium'),
        businessFinancePairV484(financePages[2], financePages[5], 'domain')
      ];
      return { ok: true, view, kind: 'all', offset: Number(offsetRaw), page_size: 400, from: pages[0].from, until: pages[0].until, pages, time: new Date().toISOString() };
    }
    const pages = await Promise.all([
      businessSummaryV456({ ...body, kind: 'regular' }),
      businessSummaryV456({ ...body, kind: 'laboratorium' }),
      businessSummaryV456({ ...body, kind: 'domain' })
    ]);
    return { ok: true, view, kind: 'all', offset: pages[0].offset, page_size: 200, from: pages[0].from, until: pages[0].until, pages, time: new Date().toISOString() };
  }
  if (kind !== 'all') return businessOrdersSingleV480(body);
  const offsetRaw = String(body.offset || '0');
  if (!/^(0|[1-9][0-9]{0,4})$/.test(offsetRaw) || Number(offsetRaw) > 50000) fail('ADMIN_PAGE_INVALID', 400);
  const bundled = await Promise.all([
    businessOrdersSingleV480({ kind: 'regular', offset: offsetRaw }).then(data => ({ ok: true, data })).catch(error => { if (error && error.code === 'ADMIN_DATA_UNAVAILABLE') return { ok: false, data: null }; throw error; }),
    businessOrdersSingleV480({ kind: 'laboratorium', offset: offsetRaw }).then(data => ({ ok: true, data })).catch(error => { if (error && error.code === 'ADMIN_DATA_UNAVAILABLE') return { ok: false, data: null }; throw error; }),
    businessOrdersSingleV480({ kind: 'domain', offset: offsetRaw }).then(data => ({ ok: true, data })).catch(error => { if (error && error.code === 'ADMIN_DATA_UNAVAILABLE') return { ok: false, data: null }; throw error; })
  ]);
  const sources = [businessOrdersBundleSourceV480(bundled[0], 'regular'), businessOrdersBundleSourceV480(bundled[1], 'laboratorium'), businessOrdersBundleSourceV480(bundled[2], 'domain')];
  if (!sources[0].ok && !sources[1].ok && !sources[2].ok) fail('ADMIN_DATA_UNAVAILABLE', 503);
  return { ok: true, kind: 'all', offset: Number(offsetRaw), sources, time: new Date().toISOString() };
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
  const order = await loadOrder(kind, id), current = await loadShipment(key); if (current.value && current.value.customer_id !== order.customer_id && current.value.updated_by !== ADMIN_USER_ID) fail('ADMIN_SHIPMENT_OWNER_MISMATCH', 503); if (revision !== (current.value ? current.value.revision : 0)) fail('ADMIN_VERSION_CONFLICT', 409); if (cancel && (!current.value || current.value.state === 'cancelled')) fail('ADMIN_SHIPMENT_NOT_ACTIVE', 409);
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
  if (value.status === 'delivered') { if (a.mail.initial === 'pending') a.mail.initial = 'skipped'; if (a.mail.transit === 'pending') a.mail.transit = 'skipped'; return 'delivered'; }
  if (value.status === 'in_transit') { if (a.mail.initial === 'pending') a.mail.initial = 'skipped'; return 'transit'; }
  return 'initial';
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
  return { provider: 'auto', recipients: [order.customer_email], subject: label + ' | ' + value.tracking_number, body, kind: 'delivery', attachment: null, origin: site, shipmentNotice: true, shipmentDetails: { title: label, customerName: String(order.customer_name || 'Pelanggan').replace(/[\r\n]/g, ' ').slice(0, 160), orderCode: order.order_id, courier: value.courier, trackingNumber: value.tracking_number, status: value.status, location: value.location, description: latest ? latest.description : '', journey } };
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
  const legacyAccountIndex = Array.isArray(record.storage_keys) && record.storage_keys.length === 4;
  const keys = [event, legacyAccountIndex && account && 'customer-access-block-v325:account:' + account + ':' + id, ip && 'customer-access-block-v325:ip:' + ip + ':' + id, device && 'customer-access-block-v325:device:' + device + ':' + id].filter(Boolean).sort(); return event && ip && device && keys.length === (record.customer_id && legacyAccountIndex ? 4 : 3) ? keys : [];
}
function validateAccessBlock(row, canonicalOnly = false) {
  if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).sort().join(',') !== 'blocked_until_ms,expires_at,record_json,security_key') return null; const record = row.record_json;
  if (!record || typeof record !== 'object' || Array.isArray(record) || Object.keys(record).sort().join(',') !== ACCESS_BLOCK_RECORD_KEYS.join(',')) return null;
  const id = String(record.block_id || '').trim().toLowerCase(), customer = record.customer_id === null ? null : String(record.customer_id || '').trim().toLowerCase(), ip = String(record.ip_hash || '').toLowerCase(), device = String(record.device_hash || '').toLowerCase(), blocked = Number(row.blocked_until_ms), expires = Date.parse(String(row.expires_at || ''));
  if (record.schema !== 'dirac.customer_access_block' || record.version !== 325 || !isUuid(id) || record.block_id !== id || (customer !== null && (!isUuid(customer) || record.customer_id !== customer)) || !/^[a-f0-9]{64}$/.test(ip) || !/^[a-f0-9]{64}$/.test(device) || record.ip_hash !== ip || record.device_hash !== device || !Number.isSafeInteger(blocked) || record.blocked_until_ms !== blocked || !Number.isSafeInteger(record.created_at_ms) || !Number.isSafeInteger(record.updated_at_ms) || record.created_at_ms <= 0 || record.updated_at_ms < record.created_at_ms || !Number.isFinite(expires) || expires < blocked || expires < record.updated_at_ms || record.fail_count !== 1 || !/^[a-z0-9_:-]{1,120}$/i.test(String(record.action || '')) || typeof record.reason !== 'string' || !record.reason.trim() || record.reason.length > 500 || /[\u0000-\u001f\u007f]/.test(record.reason) || !['active', 'revoked'].includes(record.state)) return null;
  const meta = record.metadata, metaKeys = meta && typeof meta === 'object' && !Array.isArray(meta) ? Object.keys(meta).sort().join(',') : ''; if (!meta || !['origin,source,user_agent_hash', 'identity_email,identity_email_source,identity_email_verified,origin,source,user_agent_hash', 'account_binding,identity_email,identity_email_source,identity_email_verified,origin,source,user_agent_hash'].includes(metaKeys) || (Object.prototype.hasOwnProperty.call(meta, 'account_binding') && (!customer || typeof meta.account_binding !== 'string' || !safeEqual(meta.account_binding, accessBlockDigest('account', customer)))) || (customer && Array.isArray(record.storage_keys) && record.storage_keys.length === 3 && !Object.prototype.hasOwnProperty.call(meta, 'account_binding')) || meta.source !== 'customer_security_gate' || !/^[a-f0-9]{64}$/.test(String(meta.user_agent_hash || '')) || (Object.prototype.hasOwnProperty.call(meta, 'identity_email') && meta.identity_email !== null && !isEmail(meta.identity_email)) || (Object.prototype.hasOwnProperty.call(meta, 'identity_email_verified') && typeof meta.identity_email_verified !== 'boolean') || (Object.prototype.hasOwnProperty.call(meta, 'identity_email_source') && !/^[a-z_]{3,64}$/.test(String(meta.identity_email_source || ''))) || (meta.origin !== null && (typeof meta.origin !== 'string' || meta.origin.length > 320 || /[\u0000-\u001f\u007f]/.test(meta.origin)))) return null;
  if (record.state === 'active' && record.revocation !== null) return null; if (record.state === 'revoked') { const rev = record.revocation; if (!rev || typeof rev !== 'object' || Array.isArray(rev) || Object.keys(rev).sort().join(',') !== 'admin_email,admin_role,admin_user_id,revoked_at_ms,source' || rev.source !== 'admin_security_center_supabase' || !isEmail(rev.admin_email) || !/^[A-Za-z0-9._:@-]{1,160}$/.test(String(rev.admin_user_id || '')) || !/^[A-Za-z0-9._:@-]{1,80}$/.test(String(rev.admin_role || '')) || !Number.isSafeInteger(rev.revoked_at_ms) || rev.revoked_at_ms !== blocked || record.updated_at_ms !== blocked) return null; }
  const expected = accessBlockStorageKeys(record), stored = Array.isArray(record.storage_keys) ? record.storage_keys.slice() : []; if (!expected.length || stored.length !== expected.length || new Set(stored).size !== stored.length || stored.some((key, index) => key !== expected[index]) || !expected.includes(row.security_key) || (canonicalOnly && row.security_key !== accessBlockKey(id))) return null;
  return { ...record, security_key: row.security_key, storage_keys: expected };
}

function persistentBanRecord(record, securityKey) {
  const source = record && typeof record === 'object' && !Array.isArray(record) ? record : {}, type = String(source.type || '').trim(), eventType = String(source.event_type || '').trim(), key = String(securityKey || '').trim(), blocked = Number(source.blocked_until_ms || source.blockedUntilMs || 0);
  const loginBan = /^domain-login-(?:account|ip|device):[a-f0-9]{64}$/i.test(key) && (source.permanent === true || (Number.isSafeInteger(blocked) && blocked > 0));
  return loginBan || (source.schema === 'dirac.customer_access_block' && source.state === 'active') || ['central_guard_transient_lockout_v335', 'global_hard_ban_v107', 'xss_one_strike_permanent_block_v3', 'global_api_threat_ban_v143', 'recovery_one_strike_persistent_ban_v201', 'central_guard_global_ban_v146', 'central_guard_transient_persistent_ban_v284', 'central_external_ban_v354', 'dirac_s2s_key_revocation_v206'].includes(type) || ['bola_idor_global_hard_ban', 'sqlmap_or_sqli_block'].includes(eventType);
}

const ADMIN_BANNED_EXPORT_PATCH_V476 = 'dirac-admin-banned-export-v476';
const ADMIN_BANNED_EXPORT_MAX_ROWS_V476 = 250;
const ADMIN_BANNED_EXPORT_MAX_BYTES_V476 = 220000;
const ADMIN_BANNED_PDF_MAX_RAW_V476 = 3 * 1024 * 1024;
const ADMIN_BANNED_PDF_MAX_EMAIL_V476 = 2 * 1024 * 1024;
const ADMIN_BANNED_EXPORT_FIELDS_V476 = Object.freeze({
  customers: 'id,name,email,phone',
  orders: 'id,order_id,customer_id,customer_name,customer_email,customer_phone,shipping_address,service_type,subtotal,shipping_cost,discount,taxable_amount,tax_amount,tax_effective_rate_bps,tax_statutory_rate_bps,tax_dpp_numerator,tax_dpp_denominator,shipping_origin_code,shipping_distance_km,shipping_actual_weight_grams,shipping_volumetric_weight_grams,shipping_billable_weight_grams,shipping_mode,total,payment_method,payment_status,order_status,created_at',
  domain_orders: 'id,customer_id,created_at,customer_name,customer_whatsapp,customer_email,owner_email,dns_method,nameserver_1,nameserver_2,target_platform,customer_note,domain_name,total_price,currency,order_status,status,payment_status',
  security_customer_account_requests: 'id,customer_id,request_type,status,reason,created_at,expires_at',
  payment_transactions: 'id,customer_id,order_id,domain_order_id,gateway_name,gateway_reference,payment_status,amount,currency,expired_at,created_at',
  order_items: 'id,order_id,customer_id,product_title,quantity,unit_price,created_at',
  laboratory_items: 'order_id,product_title,quantity,unit_price',
  domain_order_items: 'order_id,domain_name,extension,years,register_price,renewal_price,subtotal'
});
function adminBannedExportRefV476(securityKey) {
  const value = String(securityKey || '');
  if (!/^[A-Za-z0-9:._-]{1,500}$/.test(value)) return '';
  const encoded = Buffer.from(value, 'utf8').toString('base64url'), key = deriveSecret('admin-banned-export-ref-v476');
  try { return encoded + '.' + crypto.createHmac('sha256', key).update(encoded).digest('base64url'); }
  finally { key.fill(0); }
}
function adminBannedExportRefParseV476(reference) {
  const match = /^([A-Za-z0-9_-]{1,700})\.([A-Za-z0-9_-]{43})$/.exec(String(reference || ''));
  if (!match) return '';
  const key = deriveSecret('admin-banned-export-ref-v476'); let expected = '';
  try { expected = crypto.createHmac('sha256', key).update(match[1]).digest('base64url'); }
  finally { key.fill(0); }
  if (!safeEqual(expected, match[2])) return '';
  let value = ''; try { value = Buffer.from(match[1], 'base64url').toString('utf8'); } catch (_) { return ''; }
  return /^[A-Za-z0-9:._-]{1,500}$/.test(value) && Buffer.from(value, 'utf8').toString('base64url') === match[1] ? value : '';
}
function adminBannedExportRefValidV476(reference) { return !!adminBannedExportRefParseV476(reference); }
async function adminBannedIdentityV476(reference) {
  const securityKey = adminBannedExportRefParseV476(reference); if (!securityKey) fail('ADMIN_BANNED_EXPORT_REFERENCE_INVALID', 400);
  const result = await dbFetch('/rest/v1/dirac_persistent_bans?select=' + encodeURIComponent(ACCESS_BLOCK_SELECT) + '&security_key=eq.' + encodeURIComponent(securityKey) + '&limit=2', { method: 'GET' }, 'security');
  if (!result.ok || !Array.isArray(result.data) || result.data.length !== 1) fail('ADMIN_BANNED_EXPORT_BLOCK_UNAVAILABLE', 409);
  const source = result.data[0], now = Date.now();
  if (!Number.isSafeInteger(Number(source.blocked_until_ms)) || Number(source.blocked_until_ms) <= now) fail('ADMIN_BANNED_EXPORT_BLOCK_INACTIVE', 409);
  const access = validateAccessBlock(source, false);
  let email = '', verified = false, customerId = '', family = '', reason = '', createdAt = '';
  if (access) {
    if (access.state !== 'active' || access.blocked_until_ms <= now) fail('ADMIN_BANNED_EXPORT_BLOCK_INACTIVE', 409);
    const meta = access.metadata || {}; email = String(meta.identity_email || '').trim().toLowerCase(); verified = meta.identity_email_verified === true;
    customerId = access.customer_id || ''; family = 'customer_access'; reason = String(access.reason || '').slice(0,300); createdAt = new Date(access.created_at_ms).toISOString();
  } else {
    const record = source && source.record_json;
    if (!persistentBanRecord(record, securityKey)) fail('ADMIN_BANNED_EXPORT_BLOCK_INVALID', 409);
    email = String(record && (record.identity_email || record.identityEmail || record.email) || '').trim().toLowerCase(); verified = record && record.identity_email_verified === true;
    customerId = String(record && (record.customer_id || record.customerId) || '').trim().toLowerCase(); family = String(record && (record.type || record.event_type) || 'persistent').slice(0,80);
    reason = String(record && (record.reason || record.ban_reason || record.reason_code) || '').slice(0,300); createdAt = String(record && (record.created_at || record.createdAt) || '').slice(0,48);
  }
  if (!verified || !isEmail(email)) fail('ADMIN_BANNED_EXPORT_EMAIL_NOT_VERIFIED', 409);
  const profilePath = '/rest/v1/customers?select=' + encodeURIComponent(ADMIN_BANNED_EXPORT_FIELDS_V476.customers) + '&email=eq.' + encodeURIComponent(email) + '&limit=2';
  const profileResult = await dbFetch(profilePath, { method: 'GET' });
  if (!profileResult.ok || !Array.isArray(profileResult.data) || profileResult.data.length !== 1) fail('ADMIN_BANNED_EXPORT_OWNER_UNAVAILABLE', 409);
  const profile = profileResult.data[0]; if (!profile || !isUuid(profile.id) || String(profile.email || '').trim().toLowerCase() !== email) fail('ADMIN_BANNED_EXPORT_OWNER_INVALID', 409);
  if (customerId && (!isUuid(customerId) || customerId !== String(profile.id).toLowerCase())) fail('ADMIN_BANNED_EXPORT_OWNER_MISMATCH', 409);
  return Object.freeze({ reference, securityKey, email, customerId: String(profile.id).toLowerCase(), profile, family, reason, createdAt });
}
async function adminBannedRowsV476(table, customerId, target, parentIds) {
  const fields = ADMIN_BANNED_EXPORT_FIELDS_V476[table]; if (!fields || !isUuid(customerId)) fail('ADMIN_BANNED_EXPORT_QUERY_INVALID', 503);
  const actualTable = table === 'laboratory_items' ? 'order_items' : table;
  let filter = '';
  if (table === 'laboratory_items' || table === 'domain_order_items') {
    const ids = Array.isArray(parentIds) ? parentIds : [];
    if (!ids.length) return [];
    if (ids.length > 100 || ids.some(id => !isUuid(id))) fail('ADMIN_BANNED_EXPORT_TOO_LARGE', 413);
    filter = '&order_id=in.(' + ids.map(encodeURIComponent).join(',') + ')';
  } else filter = '&customer_id=eq.' + encodeURIComponent(customerId);
  const order = table === 'laboratory_items' || table === 'domain_order_items' ? 'order_id.asc' : 'id.asc';
  const path = '/rest/v1/' + actualTable + '?select=' + encodeURIComponent(fields) + filter + '&order=' + order + '&limit=' + (ADMIN_BANNED_EXPORT_MAX_ROWS_V476 + 1);
  const result = await dbFetch(path, { method: 'GET' }, target || '');
  if (!result.ok || !Array.isArray(result.data) || result.data.length > ADMIN_BANNED_EXPORT_MAX_ROWS_V476) fail('ADMIN_BANNED_EXPORT_TOO_LARGE', result && result.ok ? 413 : 503);
  const parents = new Set(parentIds || []);
  if (result.data.some(row => !row || typeof row !== 'object' || Array.isArray(row)
      || Object.keys(row).some(field => !fields.split(',').includes(field))
      || (table === 'laboratory_items' || table === 'domain_order_items' ? !parents.has(String(row.order_id || '')) : String(row.customer_id || '') !== customerId))) fail('ADMIN_BANNED_EXPORT_OWNER_MISMATCH', 409);
  return result.data;
}
async function businessBannedDataV476(body) {
  const identity = await adminBannedIdentityV476(body && body.export_ref);
  const customerId = identity.customerId;
  const first = await Promise.allSettled([
    adminBannedRowsV476('orders', customerId, ''),
    adminBannedRowsV476('orders', customerId, 'security'),
    adminBannedRowsV476('domain_orders', customerId, ''),
    adminBannedRowsV476('security_customer_account_requests', customerId, ''),
    adminBannedRowsV476('payment_transactions', customerId, ''),
    adminBannedRowsV476('order_items', customerId, '')
  ]);
  if (first.some(item => item.status !== 'fulfilled')) { const failed = first.find(item => item.status !== 'fulfilled'); throw failed.reason; }
  const orders = first[0].value, laboratoryOrders = first[1].value, domainOrders = first[2].value;
  const second = await Promise.allSettled([
    adminBannedRowsV476('laboratory_items', customerId, 'security', laboratoryOrders.map(row => row.id)),
    adminBannedRowsV476('domain_order_items', customerId, '', domainOrders.map(row => row.id))
  ]);
  if (second.some(item => item.status !== 'fulfilled')) { const failed = second.find(item => item.status !== 'fulfilled'); throw failed.reason; }
  const payload = {
    schema: 'dirac.admin.banned-data-export.v1', exported_at: new Date().toISOString(), complete: true,
    block: { family: identity.family, reason: identity.reason, created_at: identity.createdAt },
    account: { customer_id: customerId, email: identity.email }, profile: identity.profile,
    orders, laboratory_orders: laboratoryOrders, domain_orders: domainOrders, order_items: first[5].value,
    laboratory_items: second[0].value, domain_order_items: second[1].value,
    account_requests: first[3].value, payments: first[4].value,
    security_notice: 'Arsip tidak memuat password, hash password, token, cookie, kunci MFA, passkey privat, atau catatan internal keamanan.'
  };
  const collections = [orders,laboratoryOrders,domainOrders,first[5].value,second[0].value,second[1].value,first[3].value,first[4].value];
  const totalRows = collections.reduce((sum, rows) => sum + rows.length, 0);
  const serialized = JSON.stringify(payload);
  if (totalRows > ADMIN_BANNED_EXPORT_MAX_ROWS_V476 || Buffer.byteLength(serialized,'utf8') > ADMIN_BANNED_EXPORT_MAX_BYTES_V476) fail('ADMIN_BANNED_EXPORT_TOO_LARGE', 413);
  return { ok: true, export_ref: identity.reference, customer_email: identity.email, data_export: payload, row_count: totalRows };
}
function adminBannedPdfHexV476(bytes) { return Buffer.from(bytes).toString('hex').toUpperCase(); }
function adminBannedPdfSha256V476(...parts) { const hash = crypto.createHash('sha256'); parts.forEach(part => hash.update(part)); return hash.digest(); }
function adminBannedPdfAesNoPadV476(key, data) { const cipher = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16)); cipher.setAutoPadding(false); return Buffer.concat([cipher.update(data), cipher.final()]); }
function adminBannedPdfStreamV476(key, data) { const iv = crypto.randomBytes(16), cipher = crypto.createCipheriv('aes-256-cbc', key, iv); return Buffer.concat([iv, cipher.update(data), cipher.final()]); }
function adminBannedPdfEncryptV476(raw, password) {
  if (!Buffer.isBuffer(raw) || raw.length < 100 || raw.length > ADMIN_BANNED_PDF_MAX_RAW_V476 || !/^%PDF-1\.4\n/.test(raw.subarray(0,9).toString('ascii')) || !/%%EOF\n$/.test(raw.subarray(-40).toString('ascii'))) fail('ADMIN_BANNED_PDF_INVALID', 400);
  const xrefMarker = Buffer.from('xref\n'), xref = raw.indexOf(xrefMarker); if (xref < 9) fail('ADMIN_BANNED_PDF_INVALID', 400);
  const xrefText = raw.subarray(xref).toString('latin1'); if (xrefText.includes('/Encrypt')) fail('ADMIN_BANNED_PDF_INVALID',400); const header = /^xref\n0 (\d+)\n0000000000 65535 f \n/.exec(xrefText);
  if (!header) fail('ADMIN_BANNED_PDF_INVALID',400);
  const size=Number(header[1]); if (!Number.isInteger(size) || size < 4 || size > 1000) fail('ADMIN_BANNED_PDF_INVALID',400);
  const lines=xrefText.slice(header[0].length).split('\n'), offsetLines=lines.slice(0,size-1);
  if (offsetLines.length !== size-1 || offsetLines.some(line=>!/^\d{10} 00000 n $/.test(line))) fail('ADMIN_BANNED_PDF_INVALID',400);
  const offsets=offsetLines.map(line=>Number(line.slice(0,10)));
  if (offsets.some((value,index)=>!Number.isInteger(value) || value < 9 || value >= xref || (index>0 && value<=offsets[index-1]))) fail('ADMIN_BANNED_PDF_INVALID',400);
  const fileKey = crypto.randomBytes(32), userPassword = Buffer.from(String(password || ''),'utf8').subarray(0,127), ownerPassword = Buffer.from(crypto.randomBytes(48).toString('base64url'),'utf8').subarray(0,127);
  if (userPassword.length < 12) fail('ADMIN_BANNED_PDF_PASSWORD_INVALID',503);
  const uv=crypto.randomBytes(8), uk=crypto.randomBytes(8), U=Buffer.concat([adminBannedPdfSha256V476(userPassword,uv),uv,uk]), UE=adminBannedPdfAesNoPadV476(adminBannedPdfSha256V476(userPassword,uk),fileKey);
  const ov=crypto.randomBytes(8), ok=crypto.randomBytes(8), O=Buffer.concat([adminBannedPdfSha256V476(ownerPassword,ov,U),ov,ok]), OE=adminBannedPdfAesNoPadV476(adminBannedPdfSha256V476(ownerPassword,ok,U),fileKey);
  const permissions=-4, permissionBlock=Buffer.alloc(16); permissionBlock.writeInt32LE(permissions,0); permissionBlock.fill(0xff,4,8); permissionBlock[8]=70; permissionBlock.write('adb',9,'ascii'); crypto.randomBytes(4).copy(permissionBlock,12);
  const permissionCipher=crypto.createCipheriv('aes-256-ecb',fileKey,null); permissionCipher.setAutoPadding(false); const Perms=Buffer.concat([permissionCipher.update(permissionBlock),permissionCipher.final()]);
  const rebuilt=offsets.map((objectOffset,index)=>{
    const objectEnd=index+1<offsets.length?offsets[index+1]:xref, objectBytes=raw.subarray(objectOffset,objectEnd), expectedId=index+1, head=new RegExp('^'+expectedId+' 0 obj\\n').exec(objectBytes.subarray(0,64).toString('latin1'));
    if (!head) fail('ADMIN_BANNED_PDF_INVALID',400);
    const contentStart=head[0].length, streamMarker=Buffer.from('\nstream\n'), streamAt=objectBytes.indexOf(streamMarker,contentStart);
    if (streamAt<0) { if (!/\nendobj\n$/.test(objectBytes.toString('latin1'))) fail('ADMIN_BANNED_PDF_INVALID',400); return {id:expectedId,bytes:objectBytes}; }
    const dictionary=objectBytes.subarray(contentStart,streamAt).toString('latin1'), lengthMatch=/\/Length (\d+)/.exec(dictionary); if (!lengthMatch) fail('ADMIN_BANNED_PDF_INVALID',400);
    const length=Number(lengthMatch[1]), dataStart=streamAt+streamMarker.length, dataEnd=dataStart+length, tail=objectBytes.subarray(dataEnd).toString('latin1');
    if (!Number.isInteger(length) || length<0 || dataEnd>objectBytes.length || !(tail==='endstream\nendobj\n'||tail==='\nendstream\nendobj\n')) fail('ADMIN_BANNED_PDF_INVALID',400);
    const encrypted=adminBannedPdfStreamV476(fileKey,objectBytes.subarray(dataStart,dataEnd)), nextDictionary=dictionary.replace('/Length '+length,'/Length '+encrypted.length);
    return {id:expectedId,bytes:Buffer.concat([Buffer.from(expectedId+' 0 obj\n'+nextDictionary+'\nstream\n','latin1'),encrypted,Buffer.from('\nendstream\nendobj\n','latin1')])};
  });
  const maximum=rebuilt.length, encryptId=maximum+1;
  const dictionary=encryptId+' 0 obj\n<< /Filter /Standard /V 5 /Length 256 /O <'+adminBannedPdfHexV476(O)+'> /U <'+adminBannedPdfHexV476(U)+'> /OE <'+adminBannedPdfHexV476(OE)+'> /UE <'+adminBannedPdfHexV476(UE)+'> /P '+permissions+' /R 5 /Perms <'+adminBannedPdfHexV476(Perms)+'> /EncryptMetadata false /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV3 /Length 32 >> >> /StmF /StdCF /StrF /StdCF >>\nendobj\n';
  const all=rebuilt.concat([{id:encryptId,bytes:Buffer.from(dictionary,'latin1')}]), prefix=Buffer.from('%PDF-1.7\n','latin1');
  const built=all.reduce((state,item)=>{ state.offsets[item.id]=state.offset; state.parts.push(item.bytes); state.offset+=item.bytes.length; return state; },{parts:[prefix],offset:prefix.length,offsets:Array(encryptId+1).fill(0)}), xrefAt=built.offset;
  const xrefRows=Array.from({length:encryptId},(_unused,index)=>String(built.offsets[index+1]).padStart(10,'0')+' 00000 n \n').join('');
  const documentId=adminBannedPdfSha256V476(raw,crypto.randomBytes(32)).subarray(0,16), table='xref\n0 '+(encryptId+1)+'\n0000000000 65535 f \n'+xrefRows+'trailer\n<< /Size '+(encryptId+1)+' /Root 1 0 R /Encrypt '+encryptId+' 0 R /ID [<'+adminBannedPdfHexV476(documentId)+'><'+adminBannedPdfHexV476(documentId)+'>] >>\nstartxref\n'+xrefAt+'\n%%EOF\n';
  built.parts.push(Buffer.from(table,'latin1')); fileKey.fill(0); ownerPassword.fill(0); return Buffer.concat(built.parts);
}
async function businessBannedPdfV476(body, origin, assertContext) {
  const identity = await adminBannedIdentityV476(body && body.export_ref); assertContext();
  const mode = String(body && body.mode || ''); if (!['download','email'].includes(mode) || typeof body.raw_pdf_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(body.raw_pdf_sha256)) fail('ADMIN_BANNED_PDF_INPUT_INVALID',400);
  const raw = documentBytesV464(body.raw_pdf_base64, ADMIN_BANNED_PDF_MAX_RAW_V476); if (crypto.createHash('sha256').update(raw).digest('hex') !== body.raw_pdf_sha256) { raw.fill(0); fail('ADMIN_BANNED_PDF_HASH_MISMATCH',400); }
  const password='DG-'+crypto.randomBytes(18).toString('base64url'); let encrypted=null;
  try { encrypted=adminBannedPdfEncryptV476(raw,password); } finally { raw.fill(0); }
  assertContext(); const digestHex=crypto.createHash('sha256').update(encrypted).digest('hex'), safeReference=crypto.createHash('sha256').update(identity.reference).digest('hex').slice(0,12), filename='data-akun-terblokir-'+safeReference+'.pdf';
  if (mode === 'email') {
    try {
      if (encrypted.length > ADMIN_BANNED_PDF_MAX_EMAIL_V476) fail('ADMIN_BANNED_PDF_EMAIL_TOO_LARGE',413);
      const host=new URL(origin).hostname, subject='Arsip data akun terenkripsi · '+host, content='Arsip data akun Anda terlampir dalam PDF terenkripsi. Password PDF tidak dikirim melalui email ini dan harus disampaikan administrator melalui kanal terpisah yang telah diverifikasi.';
      const sent=await sendCustomerMail({ origin, provider:'auto', recipients:[identity.email], subject, body:content, kind:'document', attachment:{name:filename,type:'application/pdf',bytes:encrypted} }, assertContext); assertContext();
      if (!customerMailAcceptedV451(sent,'auto',1)) fail('ADMIN_SMTP_DELIVERY_UNCONFIRMED',503);
      return { ok:true, mode, emailed:true, customer_email:identity.email, provider:sent.provider, filename, file_sha256:digestHex, pdf_password:password, password_delivery:'admin_separate_verified_channel' };
    } finally { encrypted.fill(0); }
  }
  try { return { ok:true, mode, customer_email:identity.email, filename, file_sha256:digestHex, file_base64:encrypted.toString('base64'), pdf_password:password, password_delivery:'admin_separate_verified_channel' }; }
  finally { encrypted.fill(0); }
}

async function businessBlocks(body) {
  const raw = String(body.offset || '0'); if (!/^(0|[1-9][0-9]{0,4})$/.test(raw) || Number(raw) > 50000) fail('ADMIN_PAGE_INVALID', 400); const result = await dbFetch('/rest/v1/dirac_persistent_bans?select=' + encodeURIComponent(ACCESS_BLOCK_SELECT) + '&blocked_until_ms=gt.0&order=security_key.asc&limit=41&offset=' + Number(raw), { method: 'GET' }, 'security'); if (!result.ok || !Array.isArray(result.data) || result.data.length > 41) fail('ADMIN_DATA_UNAVAILABLE', 503);
  const blocks = [], seen = new Set(); result.data.slice(0, 40).forEach(row => {
    const value = validateAccessBlock(row, false);
    if (value) {
      if (seen.has(value.block_id) || value.state !== 'active' || value.blocked_until_ms <= Date.now()) return;
      seen.add(value.block_id); const meta = value.metadata || {}, mirrored = /^(central_guard_|wrong_password_rate_limit_)/.test(value.reason);
      const exportable = meta.identity_email_verified === true && isEmail(meta.identity_email);
      blocks.push({ id: value.block_id, customer_email: isEmail(meta.identity_email) ? String(meta.identity_email).toLowerCase() : '', email_verified: meta.identity_email_verified === true, family: 'customer_access', reason: value.reason.slice(0, 300), created_at: new Date(value.created_at_ms).toISOString(), active: true, can_unban: !mirrored, can_export_data: exportable, export_ref: exportable ? adminBannedExportRefV476(row.security_key) : '', review_note: mirrored ? 'Blokir ini terkait otoritas guard asal. Membuka salinan akses saja tidak memulihkan akses akun.' : 'Membuka catatan akses ini; blokir lain tetap diperiksa.' });
      return;
    }
    const record = row && row.record_json;
    if (!persistentBanRecord(record, row && row.security_key)) return;
    const logicalKey = String(record && record.type || '') === 'central_external_ban_v354'
      ? ['central_external_ban_v354', String(record.identity_email || record.identityEmail || record.email || '').trim().toLowerCase(), String(record.reason || ''), String(record.created_at || record.createdAt || ''), String(record.blocked_until_ms || record.blockedUntilMs || '')].join('|')
      : String(row.security_key || '');
    const id = digest(logicalKey); if (seen.has(id)) return; seen.add(id);
    const email = String(record.identity_email || record.identityEmail || record.email || '').trim().toLowerCase();
    const exportable = record.identity_email_verified === true && isEmail(email) && Number(row.blocked_until_ms) > Date.now();
    blocks.push({ id, customer_email: isEmail(email) ? email : '', email_verified: record.identity_email_verified === true, family: String(record.type || record.event_type || 'persistent').slice(0, 80), reason: String(record.reason || record.ban_reason || record.reason_code || '').slice(0, 300), created_at: String(record.created_at || record.createdAt || '').slice(0, 48), active: true, can_unban: false, can_export_data: exportable, export_ref: exportable ? adminBannedExportRefV476(row.security_key) : '', review_note: 'Blokir ini terkait otoritas guard asal dan hanya ditampilkan sebagai baca-saja.' });
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
  'ADMIN_BODY_TOO_COMPLEX', 'ADMIN_BODY_TOO_LARGE', 'ADMIN_CLIENT_HEADERS_INVALID', 'ADMIN_CONTENT_TYPE_INVALID', 'ADMIN_CREDENTIALS_INVALID', 'ADMIN_FACTOR_GUARD_MISMATCH',
  'ADMIN_EMAIL_CODE_INVALID', 'ADMIN_ENCODING_INVALID', 'ADMIN_FIXED_OWNER_REQUIRED', 'ADMIN_METHOD_NOT_ALLOWED', 'ADMIN_ORIGIN_INVALID',
  'ADMIN_PASSKEY_ALGORITHM_INVALID', 'ADMIN_PASSKEY_ATTESTATION_INVALID', 'ADMIN_PASSKEY_ATTESTED_DATA_REQUIRED', 'ADMIN_PASSKEY_AUTHDATA_INVALID',
  'ADMIN_PASSKEY_BACKUP_STATE_INVALID', 'ADMIN_PASSKEY_CBOR_INVALID', 'ADMIN_PASSKEY_CLIENT_INVALID', 'ADMIN_PASSKEY_CLIENT_MISMATCH',
  'ADMIN_PASSKEY_COUNTER_REPLAY', 'ADMIN_PASSKEY_CREDENTIAL_INVALID', 'ADMIN_PASSKEY_CREDENTIAL_MISMATCH', 'ADMIN_PASSKEY_INVALID',
  'ADMIN_PASSKEY_KEY_INVALID', 'ADMIN_PASSKEY_RECOVERY_INVALID', 'ADMIN_PASSKEY_RPID_MISMATCH', 'ADMIN_PASSKEY_SCOPE_INVALID',
  'ADMIN_PASSKEY_SIGNATURE_INVALID', 'ADMIN_PASSKEY_USER_MISMATCH', 'ADMIN_PASSKEY_UV_REQUIRED', 'ADMIN_PREFLIGHT_INVALID', 'ADMIN_PROOF_INVALID',
  'ADMIN_PROOF_REPLAYED', 'ADMIN_QUERY_DUPLICATE', 'ADMIN_REFERER_INVALID', 'ADMIN_REQUEST_INVALID', 'ADMIN_SECURITY_REPORT_INVALID',
  'ADMIN_SECURITY_REPORT_ONE_STRIKE', 'ADMIN_SMTP_REQUEST_PERMANENT_BAN', 'ADMIN_TICKET_ALREADY_USED', 'ADMIN_TICKET_INVALID', 'ADMIN_TOTP_ALREADY_USED', 'ADMIN_TOTP_INVALID'
]);
function adminCentralBanRequired(error) {
  const code = String(error && error.code || ''), status = Number(error && (error.status || error.statusCode) || 0);
  return [400, 401, 403, 405, 409, 413, 415].includes(status) && ADMIN_CENTRAL_BAN_FAILURE_CODES.includes(code);
}
function adminGuardSelfTest() {
  try {
    const expected = ['admin_entry','admin_security_report','admin_login','admin_status','admin_email_start','admin_email_verify','admin_action_passkey_start','admin_action_passkey_verify','admin_passkey_start','admin_passkey_verify','admin_passkey_recovery_start','admin_passkey_recovery_verify','admin_totp_verify','admin_logout','admin_orders','admin_shipment_update','admin_shipment_cancel','admin_blocks','admin_banned_data','admin_unban','admin_banned_pdf','admin_account_create','admin_account_disable','admin_account_enable','admin_account_delete','admin_account_password_reset','admin_account_passkey_reset','admin_partner_requests','admin_partner_request_update','admin_smtp_send','admin_local_authorize','admin_document_prepare','admin_document_seal','admin_document_verify','admin_monitor'];
    return Object.isFrozen(CONTRACTS) && Object.isFrozen(ACTIONS) && ACTIONS.length === expected.length && expected.every((name, index) => ACTIONS[index] === name && Object.isFrozen(CONTRACTS[name]) && Object.isFrozen(CONTRACTS[name].methods) && Object.isFrozen(CONTRACTS[name].allowed) && Object.isFrozen(CONTRACTS[name].required))
      && exactToken(randomToken()) && PASSWORD_COOKIE.startsWith('__Host-') && SESSION_COOKIE.startsWith('__Host-') && adminSecretState().configured === true;
  } catch (_) { return false; }
}
const ADMIN_STATIC_GATE = Object.freeze({ ok: Object.isFrozen(CONTRACTS) && Object.isFrozen(ACTIONS) && Object.isFrozen(ADMIN_CENTRAL_BAN_FAILURE_CODES) && !ACTIONS.includes('__proto__') && !ACTIONS.includes('constructor') });

// V464: immutable, MAC-authenticated document records in the existing security store.
// A copied QR identifies the same document; only an exact registered file hash proves integrity.
const DOCUMENT_VERSION_V464 = 'dirac-document-v464';
const DOCUMENT_PREFIX_V464 = 's2s-document-v464:';
const DOCUMENT_MAX_V464 = 3 * 1024 * 1024;
const DOCUMENT_KINDS_V464 = Object.freeze(['invoice','proforma','quotation','delivery','receipt','statement','cancellation','handover','purchase','authorization','tax_letter','tax_summary','letter']);
function documentErrorV464(code, status = 503) { fail('ADMIN_DOCUMENT_' + code, status); }
function documentMacV464(value) {
  const key = deriveSecret('document-authenticity-v464');
  try { return crypto.createHmac('sha512', key).update(stableJson(value)).digest('base64url'); }
  finally { key.fill(0); }
}
function documentSignedV464(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record) || typeof record.mac !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(record.mac)) return false;
  const unsigned = { ...record }; delete unsigned.mac;
  return safeEqual(record.mac, documentMacV464(unsigned));
}
// V495: seven invoice geometry markers are derived from the existing server secret and signed issuance identity.
function documentInvoicePatternsV495(value) {
  const key = deriveSecret('invoice-visual-pattern-v495');
  let seed;
  try {
    seed = crypto.createHmac('sha512', key).update(stableJson({ version: value.version, issuer: value.issuer, owner_scope: value.owner_scope, kind: value.kind,
      reference: value.reference, content_sha256: value.content_sha256, page_count: value.page_count })).digest();
    return { version: 'dirac-invoice-pattern-v495', din_tracking: 6 + seed[0] % 13, din_font: seed[1] % 2 ? 'bold' : 'regular',
      din_size: 30 + seed[2] % 3, logo_size: 193 + seed[3] % 7, social_pitch: 292 + seed[4] % 5,
      social_size: 22 + seed[5] % 3, footer_rule: 88 + seed[6] % 9 };
  } finally { key.fill(0); if (seed) seed.fill(0); }
}
function documentIdentityValidV464(value) {
  return !!(value && (Object.keys(value).sort().join(',') === 'content_sha256,created_at,id,issuer,kind,mac,owner_scope,page_count,reference,version'
      || (Object.keys(value).sort().join(',') === 'content_sha256,created_at,id,issuer,kind,mac,owner_scope,page_count,reference,version,visual_patterns'
        && value.kind === 'invoice' && value.visual_patterns && typeof value.visual_patterns === 'object' && !Array.isArray(value.visual_patterns)
        && stableJson(value.visual_patterns) === stableJson(documentInvoicePatternsV495(value))))
    && value.version === DOCUMENT_VERSION_V464 && /^DV-[a-f0-9]{48}$/.test(value.id)
    && value.issuer === 'PT Dirac Inovasi Nusantara' && DOCUMENT_KINDS_V464.includes(value.kind)
    && typeof value.reference === 'string' && value.reference.length >= 1 && value.reference.length <= 253 && !/[\u0000-\u001f\u007f]/.test(value.reference)
    && /^[a-f0-9]{64}$/.test(value.content_sha256) && /^[a-f0-9]{64}$/.test(value.owner_scope)
    && Number.isSafeInteger(value.created_at) && value.created_at > 0 && value.created_at <= Date.now() + 1000
    && Number.isInteger(value.page_count) && value.page_count >= 1 && value.page_count <= 64 && documentSignedV464(value));
}
const DOCUMENT_QR_VERSION_V470 = 'dirac-document-qr-v470';
function documentQrProofV470(identity) {
  if (!documentIdentityValidV464(identity)) documentErrorV464('IDENTITY_INVALID');
  return crypto.createHash('sha256').update(DOCUMENT_QR_VERSION_V470 + '\n' + identity.id + '\n' + identity.content_sha256 + '\n' + identity.mac).digest('base64url');
}
function documentQrProofMatchesV470(identity, proof) {
  return typeof proof === 'string' && /^[A-Za-z0-9_-]{43}$/.test(proof) && safeEqual(proof, documentQrProofV470(identity));
}
function documentQrV464(identity, origin, route = '/admin.html') {
  if (!documentIdentityValidV464(identity) || !['/admin.html','/invoice.html'].includes(route)) documentErrorV464('IDENTITY_INVALID');
  const url = new URL(origin);
  if ((url.protocol !== 'https:' && !loopbackHost(url.hostname)) || url.origin !== origin || url.username || url.password) documentErrorV464('ORIGIN_INVALID');
  const proof = documentQrProofV470(identity);
  const code = require('qrcode').create(origin + route + '#verify=' + identity.id + '&proof=' + proof, { errorCorrectionLevel: 'H' });
  if (!code.modules || code.modules.size > 81) documentErrorV464('QR_LIMIT');
  return { size: code.modules.size, data: Array.from(code.modules.data), quiet: 4, proof };
}
async function documentPrepareV464(meta, ownerScope, origin, claim, assertContext, route = '/admin.html') {
  assertContext();
  if (!meta || Object.keys(meta).sort().join(',') !== 'content_sha256,kind,page_count,reference' || !DOCUMENT_KINDS_V464.includes(meta.kind)
      || typeof meta.reference !== 'string' || meta.reference !== meta.reference.trim() || !meta.reference || meta.reference.length > 253
      || /[\u0000-\u001f\u007f]/.test(meta.reference) || !/^[a-f0-9]{64}$/.test(meta.content_sha256)
      || !/^[a-f0-9]{64}$/.test(ownerScope) || !Number.isInteger(meta.page_count) || meta.page_count < 1 || meta.page_count > 64) documentErrorV464('META_INVALID', 400);
  const value = { version: DOCUMENT_VERSION_V464, id: 'DV-' + crypto.randomBytes(24).toString('hex'), issuer: 'PT Dirac Inovasi Nusantara',
    owner_scope: ownerScope, kind: meta.kind, reference: meta.reference, content_sha256: meta.content_sha256, page_count: meta.page_count, created_at: Date.now() };
  if (value.kind === 'invoice') value.visual_patterns = documentInvoicePatternsV495(value);
  const identity = { ...value, mac: documentMacV464(value) };
  if (await claim(DOCUMENT_PREFIX_V464 + 'id:' + identity.id, identity) !== true) documentErrorV464('IDENTITY_WRITE_UNCONFIRMED');
  assertContext();
  return { identity, qr: documentQrV464(identity, origin, route) };
}
function documentCrcV464(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
  return (crc ^ 0xffffffff) >>> 0;
}
function documentPngEndV464(bytes) {
  if (bytes.length < 45 || !bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) documentErrorV464('PNG_INVALID', 400);
  let offset = 8, end = -1, header = false, image = false;
  for (let count = 0; offset + 12 <= bytes.length && count < 10000; count++) {
    const length = bytes.readUInt32BE(offset), next = offset + length + 12;
    if (length > DOCUMENT_MAX_V464 || next > bytes.length) documentErrorV464('PNG_INVALID', 400);
    const type = bytes.toString('ascii', offset + 4, offset + 8);
    if (bytes.readUInt32BE(next - 4) !== documentCrcV464(bytes.subarray(offset + 4, next - 4))) documentErrorV464('PNG_INVALID', 400);
    if (type === 'IHDR') { if (header || offset !== 8 || length !== 13 || bytes.readUInt32BE(offset + 8) !== 1240 || bytes.readUInt32BE(offset + 12) !== 1754) documentErrorV464('PNG_INVALID', 400); header = true; }
    if (type === 'IDAT') image = true;
    if (type === 'tEXt' && bytes.toString('ascii',offset+8,Math.min(next-4,offset+31)).startsWith('DIRAC-DOCUMENT-V464\0')) documentErrorV464('ALREADY_SEALED', 400);
    if (type === 'IEND') { if (length !== 0 || next !== bytes.length || !header || !image) documentErrorV464('PNG_INVALID', 400); end = offset; break; }
    offset = next;
  }
  if (end < 0) documentErrorV464('PNG_INVALID', 400);
  return end;
}
function documentBytesV464(base64, maximum = DOCUMENT_MAX_V464) {
  if (typeof base64 !== 'string' || base64.length < 20 || base64.length > Math.ceil(maximum / 3) * 4 || base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) documentErrorV464('FILE_INVALID', 400);
  const bytes = Buffer.from(base64, 'base64');
  if (bytes.length < 10 || bytes.length > maximum || bytes.toString('base64') !== base64) documentErrorV464('FILE_INVALID', 400);
  return bytes;
}
async function documentSealV464(bytes, identity, format, page, ownerScope, read, claim, assertContext) {
  assertContext();
  if (!Buffer.isBuffer(bytes) || bytes.length < 10 || bytes.length > DOCUMENT_MAX_V464 || !documentIdentityValidV464(identity)
      || identity.owner_scope !== ownerScope || !['png','pdf'].includes(format) || !Number.isInteger(page)
      || (format === 'png' ? page < 1 || page > identity.page_count : page !== 0)) documentErrorV464('SEAL_INVALID', 400);
  const registered = await read(DOCUMENT_PREFIX_V464 + 'id:' + identity.id);
  if (!registered || stableJson(registered) !== stableJson(identity)) documentErrorV464('IDENTITY_UNAVAILABLE');
  assertContext();
  let pngEnd = -1;
  if (format === 'png') pngEnd = documentPngEndV464(bytes);
  else if (!/^%PDF-1\.[47]\n/.test(bytes.subarray(0,9).toString('ascii')) || !/%%EOF\n$/.test(bytes.subarray(-40).toString('ascii')) || bytes.includes(Buffer.from('%DIRAC-DOCUMENT-V464:'))) documentErrorV464('PDF_INVALID', 400);
  const unsigned = { version: DOCUMENT_VERSION_V464, identity, artifact_id: crypto.randomBytes(24).toString('hex'), format, page,
    raw_sha256: crypto.createHash('sha256').update(bytes).digest('hex'), raw_bytes: bytes.length, created_at: Date.now() };
  const seal = { ...unsigned, mac: documentMacV464(unsigned) };
  const token = Buffer.from(stableJson(seal), 'utf8').toString('base64url');
  let file;
  if (format === 'png') {
    const data = Buffer.from('DIRAC-DOCUMENT-V464\0' + token, 'ascii'), chunk = Buffer.alloc(data.length + 12);
    chunk.writeUInt32BE(data.length,0); chunk.write('tEXt',4,'ascii'); data.copy(chunk,8); chunk.writeUInt32BE(documentCrcV464(chunk.subarray(4,-4)),chunk.length-4);
    file = Buffer.concat([bytes.subarray(0,pngEnd),chunk,bytes.subarray(pngEnd)]);
  } else file = Buffer.concat([bytes, Buffer.from('%DIRAC-DOCUMENT-V464:' + token + '\n','ascii')]);
  if (file.length > DOCUMENT_MAX_V464) documentErrorV464('FILE_LIMIT', 413);
  const fileSha = crypto.createHash('sha256').update(file).digest('hex');
  const data = { version: DOCUMENT_VERSION_V464, file_sha256: fileSha, file_bytes: file.length, seal };
  const record = { ...data, mac: documentMacV464(data) };
  if (await claim(DOCUMENT_PREFIX_V464 + 'file:' + fileSha, record) !== true) documentErrorV464('FILE_WRITE_UNCONFIRMED');
  assertContext();
  return { file, file_sha256: fileSha, document_id: identity.id, format };
}
async function documentVerifyV464(input, read, assertContext, ownerScope = '') {
  assertContext();
  const fileSha = input.file_sha256 || '', id = input.document_id || '', qrProof = input.qr_proof || '';
  if ((!fileSha && !id) || (fileSha && !/^[a-f0-9]{64}$/.test(fileSha)) || (id && !/^DV-[a-f0-9]{48}$/.test(id)) || (qrProof && !/^[A-Za-z0-9_-]{43}$/.test(qrProof))) documentErrorV464('VERIFY_INVALID', 400);
  const record = await read(DOCUMENT_PREFIX_V464 + (fileSha ? 'file:' + fileSha : 'id:' + id));
  assertContext();
  if (!record) {
    if (fileSha && id) {
      const identity = await read(DOCUMENT_PREFIX_V464 + 'id:' + id);
      assertContext();
      if (identity) {
        if (!documentIdentityValidV464(identity)) documentErrorV464('RECORD_INVALID');
        if (ownerScope && identity.owner_scope !== ownerScope) return { ok: true, verified: false, status: 'mismatch', integrity_verified: false, qr_authentic: false, message: 'Pemilik dokumen tidak cocok.' };
        const qrAuthentic = documentQrProofMatchesV470(identity, qrProof);
        return { ok: true, verified: false, status: qrAuthentic ? 'qr_reuse_or_modified_file' : 'unregistered_file_with_id', integrity_verified: false,
          qr_authentic: qrAuthentic, qr_reuse_suspected: qrAuthentic, issuer: identity.issuer, document_id: identity.id, reference: identity.reference,
          kind: identity.kind, page_count: identity.page_count, issued_at: new Date(identity.created_at).toISOString(), content_sha256: identity.content_sha256,
          message: qrAuthentic
            ? 'Kode QR terdaftar, tetapi berkas ini berbeda dari berkas asli. Foto, hasil scan, atau kode QR yang disalin belum membuktikan keaslian. Unggah berkas asli untuk pemeriksaan.'
            : 'Nomor penerbitan ditemukan, tetapi keaslian kode QR dan berkas belum terverifikasi.' };
      }
    }
    return { ok: true, verified: false, status: 'unregistered', integrity_verified: false, qr_authentic: false,
      message: 'Berkas tidak cocok dengan catatan penerbitan. Foto, hasil scan, dokumen lama, atau berkas yang diubah belum dapat diverifikasi; hasil ini tidak menentukan kebenaran isinya.' };
  }
  if (fileSha) {
    const seal = record.seal;
    if (Object.keys(record).sort().join(',') !== 'file_bytes,file_sha256,mac,seal,version' || record.version !== DOCUMENT_VERSION_V464
        || record.file_sha256 !== fileSha || !Number.isSafeInteger(record.file_bytes) || record.file_bytes < 10 || record.file_bytes > DOCUMENT_MAX_V464
        || !documentSignedV464(record) || !seal || Object.keys(seal).sort().join(',') !== 'artifact_id,created_at,format,identity,mac,page,raw_bytes,raw_sha256,version'
        || seal.version !== DOCUMENT_VERSION_V464 || !documentSignedV464(seal) || !/^[a-f0-9]{48}$/.test(seal.artifact_id)
        || !/^[a-f0-9]{64}$/.test(seal.raw_sha256) || !Number.isSafeInteger(seal.raw_bytes) || seal.raw_bytes < 10 || seal.raw_bytes >= record.file_bytes
        || !Number.isSafeInteger(seal.created_at) || seal.created_at > Date.now() + 1000 || !['png','pdf'].includes(seal.format)
        || !documentIdentityValidV464(seal.identity) || !Number.isInteger(seal.page)
        || (seal.format === 'png' ? seal.page < 1 || seal.page > seal.identity.page_count : seal.page !== 0)) documentErrorV464('RECORD_INVALID');
    if ((id && seal.identity.id !== id) || (ownerScope && seal.identity.owner_scope !== ownerScope) || (qrProof && !documentQrProofMatchesV470(seal.identity, qrProof))) return { ok: true, verified: false, status: 'mismatch', integrity_verified: false, qr_authentic: false, message: 'ID, QR, atau pemilik dokumen tidak cocok.' };
    return { ok: true, verified: true, status: 'authentic_file', integrity_verified: true, qr_authentic: qrProof ? true : undefined, issuer: seal.identity.issuer,
      document_id: seal.identity.id, reference: seal.identity.reference, kind: seal.identity.kind, format: seal.format, page: seal.page,
      page_count: seal.identity.page_count, issued_at: new Date(seal.created_at).toISOString(), file_sha256: fileSha, content_sha256: seal.identity.content_sha256,
      ...(seal.identity.visual_patterns ? { pattern_verification: { version: seal.identity.visual_patterns.version, verified: true, count: 7,
        checks: ['din_tracking','din_font','din_size','logo_size','social_pitch','social_size','footer_rule'], method: 'registered_file_sha256_hmac_sha512' } } : {}),
      identical_copies_possible: true, message: 'Berkas ini sesuai dengan dokumen asli yang diterbitkan. Kode QR yang disalin ke berkas lain tidak membuktikan keaslian berkas tersebut.' };
  }
  if (!documentIdentityValidV464(record)) documentErrorV464('RECORD_INVALID');
  if (ownerScope && record.owner_scope !== ownerScope) return { ok: true, verified: false, status: 'mismatch', integrity_verified: false, qr_authentic: false, message: 'Pemilik dokumen tidak cocok.' };
  const qrAuthentic = documentQrProofMatchesV470(record, qrProof);
  return { ok: true, verified: false, status: qrAuthentic ? 'qr_only_authentic' : 'issued_id', integrity_verified: false, qr_authentic: qrAuthentic,
    issuer: record.issuer, document_id: record.id, reference: record.reference, kind: record.kind, page_count: record.page_count,
    issued_at: new Date(record.created_at).toISOString(), content_sha256: record.content_sha256,
    message: qrAuthentic
      ? 'Kode QR terdaftar untuk dokumen ini. Karena kode QR dapat disalin, unggah berkas asli untuk memastikan keasliannya.'
      : 'Nomor verifikasi terdaftar. Nomor saja tidak membuktikan keaslian dokumen. Unggah berkas asli untuk pemeriksaan.' };
}

function documentAdminScopeV464() { return digest('document-admin-v464:' + ADMIN_USER_ID); }
async function documentInvoiceOrderV471(reference, assertContext) {
  if (!/^ORD-\d{8}-[A-F0-9]{8}$/.test(String(reference || ''))) return null;
  const suffix = '&order_id=eq.' + encodeURIComponent(reference) + '&limit=2', path = '/rest/v1/orders?select=' + encodeURIComponent(ORDER_SELECT.regular) + suffix;
  assertContext(); const result = await Promise.all([dbFetch(path, { method: 'GET' }), dbFetch(path, { method: 'GET' }, 'security')]); assertContext();
  const regular = result[0], laboratory = result[1];
  if (!regular || !laboratory || !regular.ok || !laboratory.ok || !Array.isArray(regular.data) || !Array.isArray(laboratory.data) || regular.data.length > 1 || laboratory.data.length > 1 || regular.data.length + laboratory.data.length !== 1) return null;
  try { return orderPublic(regular.data.length ? regular.data[0] : laboratory.data[0], regular.data.length ? 'regular' : 'laboratorium'); } catch (_) { return null; }
}
async function businessDocumentV464(operation, body, origin, assertContext) {
  const read = async key => { assertContext(); const result = await securityRead(key); assertContext(); if (!result || !result.ok) documentErrorV464('STORE_UNAVAILABLE'); return result.found ? result.record : null; };
  const claim = async (key, record) => { assertContext(); const ok = await securityClaim(key, record, ENROLLMENT_SECONDS); assertContext(); return ok; };
  if (operation === 'document_verify') {
    const verified = await documentVerifyV464(body, read, assertContext);
    if (verified && verified.integrity_verified === true && verified.kind === 'invoice') { const order = await documentInvoiceOrderV471(verified.reference, assertContext); if (order) verified.order = order; }
    return verified;
  }
  if (operation === 'document_prepare') return { ok: true, verification: await documentPrepareV464({ kind: body.document_kind, reference: body.reference,
    page_count: body.page_count, content_sha256: body.content_sha256 }, documentAdminScopeV464(), origin, claim, assertContext) };
  if (operation === 'document_seal') {
    const bytes = documentBytesV464(body.file_base64), identity = body.identity;
    if (crypto.createHash('sha256').update(bytes).digest('hex') !== body.raw_sha256) documentErrorV464('HASH_MISMATCH', 400);
    const result = await documentSealV464(bytes, identity, body.format, body.page, documentAdminScopeV464(), read, claim, assertContext);
    return { ok: true, file_base64: result.file.toString('base64'), file_sha256: result.file_sha256, document_id: result.document_id, format: result.format };
  }
  documentErrorV464('OPERATION_INVALID', 400);
}
const DOCUMENT_SERVICE_V464 = Object.freeze({ version: DOCUMENT_VERSION_V464, prepare: documentPrepareV464, seal: documentSealV464, verify: documentVerifyV464, same: (left,right) => stableJson(left) === stableJson(right) });

const ADMIN_PARTNER_REQUEST_TYPES_V478 = Object.freeze(['partner_customer_referral','partner_support']);
function adminPartnerRequestTypeV478(value) {
  const type = String(value || '').trim().toLowerCase();
  return ADMIN_PARTNER_REQUEST_TYPES_V478.includes(type) ? type : '';
}
function adminPartnerRequestNoteV478(value) {
  const note = String(value || '').trim();
  if (note.length > 1200 || /[\u0000-\u001f\u007f\u202A-\u202E\u2066-\u2069]/.test(note)) fail('ADMIN_PARTNER_REQUEST_INPUT_INVALID', 400);
  return note;
}
function adminPartnerRequestUpdatePayloadV478(value) {
  const row = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const requestId = String(row.request_id || '').trim().toLowerCase(), status = String(row.status || '').trim().toLowerCase(), note = adminPartnerRequestNoteV478(row.note || '');
  if (!isUuid(requestId) || !['processing','completed','rejected'].includes(status)) fail('ADMIN_PARTNER_REQUEST_INPUT_INVALID', 400);
  return { request_id: requestId, status, note };
}
function adminPartnerRequestMetaV478(value) {
  const meta = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  return {
    source: String(meta.source || '').slice(0, 80),
    partner_auth_user_id: isUuid(meta.partner_auth_user_id) ? String(meta.partner_auth_user_id).toLowerCase() : '',
    partner_email: isEmail(meta.partner_email) ? String(meta.partner_email).trim().toLowerCase() : '',
    email: isEmail(meta.email) ? String(meta.email).trim().toLowerCase() : '',
    name: String(meta.name || '').slice(0, 120), phone: String(meta.phone || '').slice(0, 24),
    message: String(meta.message || '').slice(0, 1200),
    admin_note: String(meta.admin_note || '').slice(0, 1200), reseller_auth_user_id: isUuid(meta.reseller_auth_user_id) ? String(meta.reseller_auth_user_id).toLowerCase() : ''
  };
}
async function businessPartnerRequestsV478(assertContext) {
  assertContext();
  const path = '/rest/v1/security_customer_account_requests?select=' + encodeURIComponent('id,customer_id,request_type,status,reason,metadata,created_at,updated_at,completed_at,expires_at') + '&request_type=in.(' + ADMIN_PARTNER_REQUEST_TYPES_V478.join(',') + ')&order=created_at.desc&limit=12';
  const reads = await Promise.all([dbFetch(path, { method: 'GET' }), authAdminUserRequest('/auth/v1/admin/users', 'GET').catch(() => null)]);
  assertContext();
  const result = reads[0], accountResult = reads[1];
  if (!result || !result.ok || !Array.isArray(result.data) || result.data.length > 12) fail('ADMIN_PARTNER_REQUEST_STORE_UNAVAILABLE', 503);
  const users = accountResult && accountResult.data && Array.isArray(accountResult.data.users) ? accountResult.data.users : Array.isArray(accountResult && accountResult.data) ? accountResult.data : null;
  const accountsReady = !!(accountResult && accountResult.ok === true && users && users.length <= 1000);
  const accounts = accountsReady ? users.map(adminBusinessAccountPublicV479).filter(Boolean).slice(0, 12) : [];
  return { ok: true, requests: result.data, accounts_ready: accountsReady, accounts, time: new Date().toISOString() };
}
async function businessPartnerRequestUpdateV478(body, assertContext) {
  const input = adminPartnerRequestUpdatePayloadV478(body);
  assertContext();
  const readPath = '/rest/v1/security_customer_account_requests?select=' + encodeURIComponent('id,customer_id,request_type,status,reason,metadata,created_at,updated_at,completed_at,expires_at') + '&id=eq.' + encodeURIComponent(input.request_id) + '&limit=2';
  const read = await dbFetch(readPath, { method: 'GET' });
  assertContext();
  if (!read || !read.ok || !Array.isArray(read.data) || read.data.length !== 1) fail('ADMIN_PARTNER_REQUEST_NOT_FOUND', 404);
  const current = read.data[0], type = adminPartnerRequestTypeV478(current && current.request_type), currentStatus = String(current && current.status || '').trim().toLowerCase();
  if (!type || !isUuid(current && current.customer_id) || !['pending','processing'].includes(currentStatus) || (type === 'partner_reseller_invite' && input.status === 'completed')) fail('ADMIN_PARTNER_REQUEST_STATE_INVALID', 409);
  const nowIso = new Date().toISOString(), priorMeta = current.metadata && typeof current.metadata === 'object' && !Array.isArray(current.metadata) ? current.metadata : {};
  const patchPath = '/rest/v1/security_customer_account_requests?id=eq.' + encodeURIComponent(input.request_id) + '&status=eq.' + encodeURIComponent(currentStatus) + '&select=' + encodeURIComponent('id,customer_id,request_type,status,reason,metadata,created_at,updated_at,completed_at,expires_at');
  const patched = await dbFetch(patchPath, { method: 'PATCH', prefer: 'return=representation', body: { status: input.status, updated_at: nowIso, completed_at: input.status === 'processing' ? null : nowIso, metadata: { ...priorMeta, admin_note: input.note, admin_updated_at: nowIso, admin_updated_by: 'owner' } } });
  assertContext();
  if (!patched || !patched.ok || !Array.isArray(patched.data) || patched.data.length !== 1 || String(patched.data[0] && patched.data[0].id || '').toLowerCase() !== input.request_id || String(patched.data[0] && patched.data[0].status || '').toLowerCase() !== input.status || adminPartnerRequestTypeV478(patched.data[0] && patched.data[0].request_type) !== type) fail('ADMIN_PARTNER_REQUEST_UPDATE_UNCONFIRMED', 503);
  return { ok: true, request: patched.data[0] };
}
async function adminPartnerInviteForAccountCreateV478(account, assertContext) {
  if (!account || account.role !== 'reseller' || !isUuid(account.partner_request_id)) fail('ADMIN_ACCOUNT_PARTNER_REQUEST_INVALID', 400);
  assertContext();
  const path = '/rest/v1/security_customer_account_requests?select=' + encodeURIComponent('id,customer_id,request_type,status,reason,metadata,created_at') + '&id=eq.' + encodeURIComponent(account.partner_request_id) + '&request_type=eq.partner_reseller_invite&status=in.(pending,processing)&limit=2';
  const result = await dbFetch(path, { method: 'GET' });
  assertContext();
  if (!result || !result.ok || !Array.isArray(result.data) || result.data.length !== 1) fail('ADMIN_ACCOUNT_PARTNER_REQUEST_INVALID', 409);
  const row = result.data[0], meta = adminPartnerRequestMetaV478(row && row.metadata);
  if (!isUuid(row && row.id) || !isUuid(row && row.customer_id) || meta.source !== 'partner_portal_v478' || !isUuid(meta.partner_auth_user_id) || !isEmail(meta.partner_email) || meta.email !== account.email || meta.name !== account.name || String(meta.phone || '') !== String(account.phone || '')) fail('ADMIN_ACCOUNT_PARTNER_REQUEST_MISMATCH', 409);
  return { id: String(row.id).toLowerCase(), customer_id: String(row.customer_id).toLowerCase(), status: String(row.status || '').toLowerCase(), metadata: row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata) ? row.metadata : {} };
}
async function adminPartnerInviteCompleteV478(invite, user, assertContext) {
  const nowIso = new Date().toISOString(), currentStatus = String(invite && invite.status || '').toLowerCase(), priorMeta = invite && invite.metadata && typeof invite.metadata === 'object' && !Array.isArray(invite.metadata) ? invite.metadata : {};
  if (!invite || !isUuid(invite.id) || !isUuid(invite.customer_id) || !['pending','processing'].includes(currentStatus) || !user || !isUuid(user.id)) fail('ADMIN_ACCOUNT_PARTNER_REQUEST_INVALID', 409);
  assertContext();
  const path = '/rest/v1/security_customer_account_requests?id=eq.' + encodeURIComponent(invite.id) + '&status=eq.' + encodeURIComponent(currentStatus) + '&select=' + encodeURIComponent('id,status,request_type,metadata,completed_at');
  const result = await dbFetch(path, { method: 'PATCH', prefer: 'return=representation', body: { status: 'completed', updated_at: nowIso, completed_at: nowIso, metadata: { ...priorMeta, reseller_auth_user_id: String(user.id).toLowerCase(), completed_by_admin: true, admin_updated_at: nowIso } } });
  assertContext();
  const row = result && Array.isArray(result.data) && result.data.length === 1 ? result.data[0] : null, meta = adminPartnerRequestMetaV478(row && row.metadata);
  if (!result || !result.ok || !row || String(row.id || '').toLowerCase() !== invite.id || String(row.status || '').toLowerCase() !== 'completed' || String(row.request_type || '') !== 'partner_reseller_invite' || meta.reseller_auth_user_id !== String(user.id).toLowerCase()) fail('ADMIN_ACCOUNT_PARTNER_REQUEST_COMPLETE_FAILED', 503);
  return true;
}
async function adminRollbackBusinessAccountV478(userId, email, assertContext) {
  if (!isUuid(userId) || !isEmail(email)) return false;
  assertContext();
  const removed = await authAdminUserRequest('/auth/v1/admin/users/' + String(userId).toLowerCase(), 'DELETE');
  assertContext();
  if (!removed || removed.ok !== true) return false;
  const verify = await authAdminUserRequest('/auth/v1/admin/users/' + String(userId).toLowerCase(), 'GET');
  assertContext();
  return !!verify && verify.status === 404;
}

async function businessMonitor(body) {
  const input = body && typeof body === 'object' && !Array.isArray(body) ? body : {}, view = String(input.view || '');
  if (view && view !== 'overview') fail('ADMIN_MONITOR_VIEW_INVALID', 400);
  const eventRead = dbFetch('/rest/v1/security_customer_events?select=id,event_type,status,risk_level,description,created_at&order=created_at.desc&limit=20', { method: 'GET' }).catch(() => null);
  const summaryRead = view === 'overview' ? businessOrders({ kind: 'all', offset: 0, view: 'summary', from: String(input.from || ''), until: String(input.until || '') }) : Promise.resolve(null);
  const reads = await Promise.all([eventRead, summaryRead]), result = reads[0], summary = reads[1];
  let rows = [], ready = false; if (result && result.ok && Array.isArray(result.data) && result.data.length <= 20) { rows = result.data; ready = true; }
  const memory = process.memoryUsage(); return { ok: true, time: new Date().toISOString(), guard: { self_test_ok: adminGuardSelfTest(), static_gate_ok: ADMIN_STATIC_GATE.ok, scope: 'Guard internal handler admin mandiri yang menangani permintaan ini.' }, runtime: { uptime_seconds: Math.floor(process.uptime()), rss_bytes: memory.rss, heap_used_bytes: memory.heapUsed, heap_total_bytes: memory.heapTotal }, events_ready: ready, events: ready ? rows.map(row => ({ event_type: String(row && row.event_type || '').slice(0, 100), status: String(row && row.status || '').slice(0, 40), risk_level: String(row && row.risk_level || '').slice(0, 40), description: String(row && row.description || '').slice(0, 240), created_at: String(row && row.created_at || '').slice(0, 48) })) : [], ...(view === 'overview' ? { overview_summary: summary } : {}) };
}
async function business(operation, body, origin, assertContext) { if (['document_prepare','document_seal','document_verify'].includes(operation)) return businessDocumentV464(operation,body,origin,assertContext); if (operation === 'local_authorize') { const checked = approvalPayload('admin_local_authorize', body); assertContext(); return { ok: true, authorized: true, purpose: checked.purpose, content_sha256: checked.content_sha256, one_time: true }; } if (operation === 'orders') return businessOrders(body); if (operation === 'shipment_update') return businessShipment(body, false, origin, assertContext); if (operation === 'shipment_cancel') return businessShipment(body, true, origin, assertContext); if (operation === 'blocks') return businessBlocks(body); if (operation === 'banned_data') return businessBannedDataV476(body); if (operation === 'unban') return businessUnban(body); if (operation === 'banned_pdf') return businessBannedPdfV476(body, origin, assertContext); if (operation === 'account_create') return businessAccountManage(body, origin, assertContext); if (operation === 'partner_requests') return businessPartnerRequestsV478(assertContext); if (operation === 'partner_request_update') return businessPartnerRequestUpdateV478(body, assertContext); if (operation === 'smtp_send') return businessSmtpSend(body, origin, assertContext); if (operation === 'monitor') return businessMonitor(body); fail('ADMIN_OPERATION_INVALID', 400); }

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
    deriveKey: purpose => { assertFullGuard(); if (!['totp-storage', 'totp-storage-legacy'].includes(purpose)) fail('ADMIN_KEY_PURPOSE_INVALID', 503); const key = deriveSecret('admin-v405-totp-storage'); try { return crypto.createHmac('sha256', key).update(purpose === 'totp-storage' ? ADMIN_OWNER_V466 : ADMIN_USER_ID).digest(); } finally { key.fill(0); } },
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
    business: async (operation, body) => { assertFullGuard(); if (!state.passwordAuthority || !['orders', 'shipment_update', 'shipment_cancel', 'blocks', 'banned_data', 'unban', 'banned_pdf', 'account_create', 'partner_requests', 'partner_request_update', 'smtp_send', 'local_authorize', 'document_prepare', 'document_seal', 'document_verify', 'monitor'].includes(operation)) fail('ADMIN_THREE_FACTORS_REQUIRED', 403); const result = await business(operation, body, state.origin, assertFullGuard); assertFullGuard(); return result; }
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
  const result = { status, body: { ok: false, code: known ? error.code : 'ADMIN_OPERATION_UNAVAILABLE', message: status === 503 ? 'Layanan admin belum dapat diverifikasi. Periksa konfigurasi yang diwajibkan lalu coba kembali.' : status === 429 ? 'Batas percobaan tercapai. Tunggu sebelum mencoba lagi.' : 'Verifikasi admin belum valid atau sudah kedaluwarsa.' } };
  if (status === 429 && error && error.code === 'ADMIN_EMAIL_REQUEST_RATE_LIMITED'
    && Number.isSafeInteger(error.retryAfterSeconds) && error.retryAfterSeconds > 0
    && typeof error.resetAt === 'string' && Number.isFinite(Date.parse(error.resetAt))) {
    result.body.message = 'Permintaan kode email dibatasi. Tunggu hingga waktu reset yang ditampilkan.';
    result.body.retry_after_seconds = error.retryAfterSeconds;
    result.body.reset_at = error.resetAt;
  }
  if (status === 403 && error && error.code === 'ADMIN_SMTP_REQUEST_PERMANENT_BAN') {
    result.body.message = 'Batas permintaan kode admin tercapai. Sumber permintaan diblokir permanen oleh sistem keamanan.';
  }
  return result;
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
  __diracDocumentAuthenticityV464: { value: DOCUMENT_SERVICE_V464 },
  __diracAdminContractsV405: { value: CONTRACTS },
  __diracAdminActionsV405: { value: ACTIONS },
  __diracAdminEmailV405: { value: ADMIN_EMAIL },
  __diracAdminVersionV405: { value: VERSION },
  __diracAdminStandaloneV411: { value: true },
  __diracAdminSelfTestV411: { value: Object.freeze({ ok: true, healthDependency: true, adminTableDependency: true, newEnvironmentNames: false, durablePasskeyTable: ADMIN_PASSKEY_TABLE }) }
});
module.exports = Object.freeze(adminHandler);

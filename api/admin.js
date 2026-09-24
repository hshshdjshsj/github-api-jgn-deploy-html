'use strict';

// This module has no database, SMTP or HTTP escape hatch. Every operation is
// supplied by the live health.js dispatcher after its complete central guard.
const crypto = require('node:crypto');
const ADMIN_EMAIL = 'dinzganteng888999@gmail.com';
const VERSION = 'dirac-admin-v405';
const PREFIX = 's2s-admin-v405:';
const EMAIL_DIGITS = 768;
const FACTOR_SECONDS = 600;
const SESSION_SECONDS = 600;
const ENROLLMENT_SECONDS = 100 * 365 * 24 * 60 * 60;
const COMMON_PROOF = ['csrf', 'nonce', 'idempotency_key'];
const PASSKEY_FIELDS = ['credential', 'id', 'rawId', 'type', 'response', 'clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle', 'clientExtensionResults', 'credProps', 'rk', 'transports', 'authenticatorAttachment'];
const post = (fields, required = [], max = 16384) => Object.freeze({ methods: Object.freeze(['POST']), allowed: Object.freeze(['action', ...COMMON_PROOF, ...fields]), required: Object.freeze(required), maxBodyBytes: max, maxFieldBytes: max === 98304 ? 81920 : 4096, mutation: true, allowArrayItems: max === 98304 });
const get = (fields = []) => Object.freeze({ methods: Object.freeze(['GET', 'HEAD']), allowed: Object.freeze(['action', '_csrf_boot', '_csrf_bootstrap', '_dirac_page_nonce_for', '_page_nonce_for', 'page_nonce_for', '_ts', '_t', '_', ...fields]), required: Object.freeze([]), maxBodyBytes: 1024, maxFieldBytes: 3000, mutation: false });
const CONTRACTS = Object.freeze({
  admin_status: get(),
  admin_email_start: post([]),
  admin_email_verify: post(['ticket', 'code'], ['ticket', 'code']),
  admin_passkey_start: post(['ticket'], ['ticket']),
  admin_passkey_verify: post(['ticket', ...PASSKEY_FIELDS], ['ticket', 'credential'], 98304),
  admin_totp_verify: post(['ticket', 'code'], ['ticket', 'code']),
  admin_logout: post([]),
  admin_orders: get(['kind', 'offset']),
  admin_shipment_update: post(['kind', 'order_id', 'expected_revision', 'tracking_number', 'courier', 'status', 'location', 'origin', 'destination', 'estimated_delivery', 'description'], ['kind', 'order_id', 'expected_revision', 'tracking_number', 'courier', 'status']),
  admin_shipment_cancel: post(['kind', 'order_id', 'expected_revision', 'description'], ['kind', 'order_id', 'expected_revision']),
  admin_blocks: get(['offset']),
  admin_unban: post(['block_id'], ['block_id']),
  admin_monitor: get()
});
const ACTIONS = Object.freeze(Object.keys(CONTRACTS));

function fail(code, status = 400) { throw Object.assign(new Error(code), { code, status }); }
function digest(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function randomToken() { return crypto.randomBytes(32).toString('base64url'); }
function exactToken(value) { return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value); }
function safeEqual(a, b) { const aa = Buffer.from(String(a)), bb = Buffer.from(String(b)); return aa.length === bb.length && crypto.timingSafeEqual(aa, bb); }
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
    const parts = value.split('.').map(v => Buffer.from(v, 'base64url'));
    if (parts[0].length !== 12 || parts[1].length !== 32 || parts[2].length !== 16) fail('ADMIN_STATE_INVALID', 503);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, parts[0]);
    decipher.setAAD(Buffer.from(VERSION + ':' + context)); decipher.setAuthTag(parts[2]);
    return Buffer.concat([decipher.update(parts[1]), decipher.final()]);
  } finally { key.fill(0); }
}
function checkOperations(ops) {
  if (!ops || !Object.isFrozen(ops) || ops.version !== VERSION || typeof ops.assertFullGuard !== 'function') fail('ADMIN_FULL_CENTRAL_GUARD_REQUIRED', 503);
  ops.assertFullGuard();
  const identity = ops.identity;
  if (!identity || !Object.isFrozen(identity) || identity.email !== ADMIN_EMAIL || identity.active !== true
      || !['owner', 'super_admin', 'security_admin'].includes(identity.role)
      || !/^[A-Za-z0-9._:@-]{1,160}$/.test(String(identity.userId || ''))
      || !/^[a-f0-9]{64}$/.test(String(identity.binding || ''))) fail('ADMIN_FIXED_OWNER_REQUIRED', 403);
  let origin; try { origin = new URL(identity.origin); } catch (_) { fail('ADMIN_ORIGIN_INVALID', 403); }
  if (origin.protocol !== 'https:' || origin.origin !== identity.origin || origin.username || origin.password || origin.port) fail('ADMIN_ORIGIN_INVALID', 403);
  if (!ACTIONS.includes(ops.action) || !CONTRACTS[ops.action].methods.includes(ops.method)) fail('ADMIN_ACTION_INVALID', 400);
  for (const name of ['read', 'claim', 'replace', 'takeRate', 'deriveKey', 'mail', 'verifyRegistration', 'verifyAssertion', 'readSession', 'setSession', 'clearSession', 'business']) {
    if (typeof ops[name] !== 'function') fail('ADMIN_OPERATION_UNAVAILABLE', 503);
  }
  return { owner: digest(ADMIN_EMAIL + ':' + identity.userId), binding: identity.binding, origin: identity.origin, rpId: origin.hostname };
}
function configKey(scope) { return PREFIX + 'enrollment:' + digest(scope.owner + ':' + scope.origin); }
async function stored(ops, key) {
  ops.assertFullGuard(); const result = await ops.read(key); ops.assertFullGuard();
  if (!result || result.ok !== true) fail('ADMIN_STORE_UNAVAILABLE', 503);
  return result.found === true ? result.record : null;
}
async function config(ops, scope) {
  const value = await stored(ops, configKey(scope));
  if (!value) return null;
  if (value.version !== VERSION || value.owner !== scope.owner || value.origin !== scope.origin
      || !exactToken(value.revision) || !value.passkey || !exactToken(value.userHandle)
      || !Number.isSafeInteger(value.passkey.signCount) || value.passkey.signCount < 0
      || typeof value.totp !== 'string') fail('ADMIN_ENROLLMENT_INVALID', 503);
  return value;
}
async function issue(ops, scope, stage, values = {}, seconds = FACTOR_SECONDS) {
  const token = randomToken(), now = Date.now();
  const record = { version: VERSION, owner: scope.owner, binding: scope.binding, origin: scope.origin, stage, ...values, expiresAt: now + seconds * 1000 };
  if (await ops.claim(PREFIX + 'ticket:' + digest(token), record, seconds) !== true) fail('ADMIN_STORE_UNAVAILABLE', 503);
  return token;
}
async function ticket(ops, scope, token, stage) {
  if (!exactToken(token)) fail('ADMIN_TICKET_INVALID', 401);
  const key = PREFIX + 'ticket:' + digest(token), value = await stored(ops, key);
  if (!value || value.version !== VERSION || value.owner !== scope.owner || value.origin !== scope.origin || value.binding !== scope.binding
      || value.stage !== stage || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()) fail('ADMIN_TICKET_EXPIRED', 401);
  if (await stored(ops, key + ':used')) fail('ADMIN_TICKET_ALREADY_USED', 409);
  return { key, value };
}
async function consume(ops, entry) {
  const remaining = Math.max(60, Math.ceil((entry.value.expiresAt - Date.now()) / 1000));
  if (await ops.claim(entry.key + ':used', { version: VERSION, usedAt: Date.now() }, remaining) !== true) fail('ADMIN_TICKET_ALREADY_USED', 409);
}
async function throttle(ops, scope, name, limit, seconds) {
  if (await ops.takeRate(PREFIX + 'rate:' + digest(scope.owner + ':' + scope.origin + ':' + name), limit, seconds) !== true) fail('ADMIN_RATE_LIMITED', 429);
}
async function session(ops, scope, must = true) {
  const raw = ops.readSession();
  if (!exactToken(raw)) { if (must) fail('ADMIN_THREE_FACTORS_REQUIRED', 401); return null; }
  try {
    const entry = await ticket(ops, scope, raw, 'session');
    if (entry.value.factors !== 'email+passkey+totp') fail('ADMIN_THREE_FACTORS_REQUIRED', 401);
    return entry;
  } catch (error) { if (!must && [401, 409].includes(error.status)) return null; throw error; }
}
function validateClientData(credential, proof, scope) {
  if (!credential || typeof credential !== 'object' || Array.isArray(credential) || credential.type !== 'public-key'
      || typeof credential.id !== 'string' || typeof credential.rawId !== 'string' || credential.id !== credential.rawId
      || !/^[A-Za-z0-9_-]{22,1364}$/.test(credential.id) || !credential.response || typeof credential.response !== 'object') fail('ADMIN_PASSKEY_INVALID', 400);
  const encoded = credential.response.clientDataJSON;
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{1,8192}$/.test(encoded)) fail('ADMIN_PASSKEY_CLIENT_INVALID', 400);
  const bytes = Buffer.from(encoded, 'base64url'); let data;
  try { data = JSON.parse(bytes.toString('utf8')); } catch (_) { fail('ADMIN_PASSKEY_CLIENT_INVALID', 400); }
  if (!data || data.type !== (proof.mode === 'registration' ? 'webauthn.create' : 'webauthn.get') || data.challenge !== proof.challenge
      || data.origin !== scope.origin || (data.crossOrigin !== undefined && data.crossOrigin !== false) || data.topOrigin !== undefined) fail('ADMIN_PASSKEY_CLIENT_MISMATCH', 403);
  return data;
}
async function execute(ops) {
  const scope = checkOperations(ops), body = ops.body || {}, action = ops.action;
  if (ops.method === 'HEAD') return { ok: true };
  if (action === 'admin_status') {
    const nonceTarget = body._dirac_page_nonce_for;
    if (typeof nonceTarget === 'string' && Object.prototype.hasOwnProperty.call(CONTRACTS, nonceTarget)
        && CONTRACTS[nonceTarget].methods.includes('POST')) return { ok: true };
    const [enrolled, active] = await Promise.all([config(ops, scope), session(ops, scope, false)]);
    return { ok: true, email: ADMIN_EMAIL, enrolled: !!enrolled, authenticated: !!active, factor_count: 3, email_digits: EMAIL_DIGITS, totp_period: 30, expires_at: active ? new Date(active.value.expiresAt).toISOString() : null };
  }
  if (action === 'admin_email_start') {
    await throttle(ops, scope, 'email-start-minute', 1, 60);
    await throttle(ops, scope, 'email-start-hour', 5, 3600);
    const code = Array.from({ length: EMAIL_DIGITS }, () => String(crypto.randomInt(0, 10))).join('');
    const salt = randomToken(), reference = crypto.randomBytes(12).toString('hex');
    const token = await issue(ops, scope, 'email', { salt, codeHash: digest(salt + ':' + code), reference });
    const delivered = await ops.mail({ to: ADMIN_EMAIL, code, reference, expiresAt: Date.now() + FACTOR_SECONDS * 1000 });
    if (!delivered || delivered.ok !== true) fail('ADMIN_EMAIL_DELIVERY_UNCONFIRMED', 503);
    return { ok: true, ticket: token, stage: 'email', email: ADMIN_EMAIL, digits: EMAIL_DIGITS, expires_in: FACTOR_SECONDS };
  }
  if (action === 'admin_email_verify') {
    const entry = await ticket(ops, scope, body.ticket, 'email');
    await throttle(ops, scope, 'email-verify:' + digest(body.ticket), 5, FACTOR_SECONDS);
    if (typeof body.code !== 'string' || !new RegExp('^[0-9]{' + EMAIL_DIGITS + '}$').test(body.code)
        || !safeEqual(digest(entry.value.salt + ':' + body.code), entry.value.codeHash)) fail('ADMIN_EMAIL_CODE_INVALID', 401);
    await consume(ops, entry);
    return { ok: true, ticket: await issue(ops, scope, 'passkey-start'), stage: 'passkey' };
  }
  if (action === 'admin_passkey_start') {
    const entry = await ticket(ops, scope, body.ticket, 'passkey-start');
    const enrolled = await config(ops, scope); await consume(ops, entry);
    const challenge = randomToken(), userHandle = enrolled ? enrolled.userHandle : randomToken(), mode = enrolled ? 'authentication' : 'registration';
    const token = await issue(ops, scope, 'passkey', { challenge, mode, userHandle, revision: enrolled ? enrolled.revision : null });
    const publicKey = mode === 'registration' ? {
      challenge, rp: { id: scope.rpId, name: 'PT DIRAC INOVASI NUSANTARA' },
      user: { id: userHandle, name: ADMIN_EMAIL, displayName: 'Administrator DIRAC' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' }, timeout: 60000, attestation: 'none'
    } : { challenge, rpId: scope.rpId, userVerification: 'required', timeout: 60000, allowCredentials: [{ id: enrolled.passkey.credentialId, type: 'public-key' }] };
    return { ok: true, ticket: token, stage: 'passkey', mode, publicKey };
  }
  if (action === 'admin_passkey_verify') {
    const entry = await ticket(ops, scope, body.ticket, 'passkey');
    await throttle(ops, scope, 'passkey-verify:' + digest(body.ticket), 5, FACTOR_SECONDS);
    const proof = entry.value, credential = body.credential, clientData = validateClientData(credential, proof, scope);
    let enrolled = await config(ops, scope), passkey;
    if (proof.mode === 'registration') {
      if (enrolled) fail('ADMIN_ALREADY_ENROLLED', 409);
      const verified = await ops.verifyRegistration({ credential, clientData, rpId: scope.rpId });
      if (!verified || verified.ok !== true || verified.credentialId !== credential.id || !verified.publicKeyJwk) fail('ADMIN_PASSKEY_INVALID', 403);
      passkey = { credentialId: verified.credentialId, publicKeyJwk: verified.publicKeyJwk, signCount: verified.signCount, backupEligible: verified.backupEligible };
    } else {
      if (!enrolled || proof.revision !== enrolled.revision || credential.id !== enrolled.passkey.credentialId) fail('ADMIN_PASSKEY_STATE_CHANGED', 409);
      const handle = credential.response.userHandle;
      if (handle !== null && handle !== undefined && handle !== '' && handle !== enrolled.userHandle) fail('ADMIN_PASSKEY_USER_MISMATCH', 403);
      const verified = await ops.verifyAssertion({ credential, clientData, rpId: scope.rpId, passkey: enrolled.passkey });
      if (!verified || verified.ok !== true) fail('ADMIN_PASSKEY_INVALID', 403);
      passkey = { ...enrolled.passkey, signCount: verified.signCount };
      const next = { ...enrolled, passkey, revision: randomToken() };
      if (await ops.replace(configKey(scope), enrolled.revision, next, ENROLLMENT_SECONDS) !== true) fail('ADMIN_PASSKEY_STATE_CHANGED', 409);
      enrolled = next;
    }
    await consume(ops, entry);
    let provisioning = null, encrypted = enrolled ? enrolled.totp : null;
    if (!enrolled) {
      const secret = crypto.randomBytes(32);
      try {
        encrypted = seal(ops, secret, configKey(scope));
        const manualKey = base32(secret), label = 'DIRAC ' + scope.rpId + ':' + ADMIN_EMAIL;
        provisioning = { secret: manualKey, uri: 'otpauth://totp/' + encodeURIComponent(label) + '?secret=' + manualKey + '&issuer=' + encodeURIComponent('DIRAC ' + scope.rpId) + '&algorithm=SHA1&digits=6&period=30' };
      } finally { secret.fill(0); }
    }
    const token = await issue(ops, scope, 'totp', { enroll: !enrolled, passkey: enrolled ? null : passkey, userHandle: proof.userHandle, totp: encrypted, revision: enrolled ? enrolled.revision : null });
    return { ok: true, ticket: token, stage: 'totp', enrollment: provisioning, period: 30 };
  }
  if (action === 'admin_totp_verify') {
    const entry = await ticket(ops, scope, body.ticket, 'totp');
    await throttle(ops, scope, 'totp-verify', 5, FACTOR_SECONDS);
    if (typeof body.code !== 'string' || !/^[0-9]{6}$/.test(body.code)) fail('ADMIN_TOTP_INVALID', 401);
    const proof = entry.value, enrolled = await config(ops, scope);
    if (proof.enroll ? !!enrolled : (!enrolled || enrolled.revision !== proof.revision || enrolled.totp !== proof.totp)) fail('ADMIN_ENROLLMENT_STATE_CHANGED', 409);
    const secret = open(ops, proof.totp, configKey(scope)); let accepted = null;
    try {
      const current = Math.floor(Date.now() / 30000);
      for (const counter of [current, current - 1, current + 1]) { if (safeEqual(totp(secret, counter), body.code)) { accepted = counter; break; } }
    } finally { secret.fill(0); }
    if (accepted === null) fail('ADMIN_TOTP_INVALID', 401);
    if (await ops.claim(PREFIX + 'totp-used:' + digest(scope.owner + ':' + scope.origin + ':' + proof.totp + ':' + accepted), { version: VERSION }, 120) !== true) fail('ADMIN_TOTP_ALREADY_USED', 409);
    await consume(ops, entry);
    if (proof.enroll) {
      const value = { version: VERSION, owner: scope.owner, origin: scope.origin, revision: randomToken(), passkey: proof.passkey, userHandle: proof.userHandle, totp: proof.totp, createdAt: Date.now() };
      if (await ops.claim(configKey(scope), value, ENROLLMENT_SECONDS) !== true) fail('ADMIN_ALREADY_ENROLLED', 409);
    }
    const token = await issue(ops, scope, 'session', { factors: 'email+passkey+totp' }, SESSION_SECONDS);
    ops.setSession(token, SESSION_SECONDS);
    return { ok: true, stage: 'complete', authenticated: true, expires_in: SESSION_SECONDS };
  }
  if (action === 'admin_logout') {
    const active = await session(ops, scope, false);
    if (active) await consume(ops, active);
    ops.clearSession(); return { ok: true };
  }
  await session(ops, scope);
  const operation = { admin_orders: 'orders', admin_shipment_update: 'shipment_update', admin_shipment_cancel: 'shipment_cancel', admin_blocks: 'blocks', admin_unban: 'unban', admin_monitor: 'monitor' }[action];
  if (!operation) fail('ADMIN_ACTION_INVALID', 400);
  ops.assertFullGuard();
  return ops.business(operation, body);
}

async function adminBusiness(req, res, operations) {
  try { return res.status(200).json(await execute(operations)); }
  catch (error) {
    const known = error && /^ADMIN_[A-Z0-9_]{1,90}$/.test(String(error.code || ''));
    const givenStatus = error && (error.status || error.statusCode);
    const status = known && [400, 401, 403, 404, 409, 429, 503].includes(givenStatus) ? givenStatus : 503;
    return res.status(status).json({ ok: false, code: known ? error.code : 'ADMIN_OPERATION_UNAVAILABLE', message: status === 503 ? 'Layanan admin belum dapat diverifikasi. Coba lagi setelah konfigurasi tersedia.' : status === 429 ? 'Batas percobaan tercapai. Tunggu sebelum mencoba lagi.' : 'Verifikasi admin belum valid atau sudah kedaluwarsa.' });
  }
}
async function adminHandler(req, res) {
  const central = require('./health.js');
  if (!Object.isFrozen(central) || central.__diracCentralSecurityGuardV146 !== true
      || central.__diracCentralHardeningV221 !== true || !central.__diracCentralSelfTestV221 || central.__diracCentralSelfTestV221.ok !== true
      || !central.__diracCentralBackendStaticGateV230 || central.__diracCentralBackendStaticGateV230.ok !== true
      || !central.__diracCentralRuntimeLockV230 || central.__diracCentralRuntimeLockV230.ok !== true
      || typeof central.__diracCentralAdminEntryV405 !== 'function') {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(503).json({ ok: false, code: 'ADMIN_CENTRAL_INTEGRATION_REQUIRED' });
  }
  return central.__diracCentralAdminEntryV405(req, res);
}
Object.defineProperties(adminHandler, {
  config: { value: Object.freeze({ api: Object.freeze({ bodyParser: false }) }), enumerable: true },
  __diracAdminBusinessV405: { value: adminBusiness },
  __diracAdminContractsV405: { value: CONTRACTS },
  __diracAdminActionsV405: { value: ACTIONS },
  __diracAdminEmailV405: { value: ADMIN_EMAIL },
  __diracAdminVersionV405: { value: VERSION }
});
module.exports = Object.freeze(adminHandler);

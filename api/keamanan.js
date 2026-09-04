'use strict';

const crypto = require('crypto');
const subtle = crypto.webcrypto && crypto.webcrypto.subtle;

const SECURITY_ROUTE_PATH = '/api/keamanan';
const CENTRAL_ROUTE_PATH = '/api/health';
const RESET_ACTIONS = Object.freeze(new Set(['request_password_reset', 'confirm_password_reset']));
const PASSWORD_CHANGE_ACTIONS = Object.freeze(new Set(['request_password_change', 'confirm_password_change']));
const RESET_PROFILE_CARRIER = 'd10.profile@recovery.dirac';
const RESET_CONFIRM_MARKER = 'D10_PASSKEY_V1';
const D10 = Object.freeze({
  protocol: 'dirac-lost-password-10-layer-v1',
  inner: 'dirac-lost-password-inner-v1',
  profile: 'dirac-lost-password-key-profile-v1',
  suite: 'X25519+HKDF-SHA512+4xAES-256-GCM+4xAES-256-KW',
  requestTtlMs: 120000,
  profileTtlMs: 300000,
  layers: 4
});
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function resetError(code, statusCode, message) {
  const error = new Error(String(message || code || 'PASSWORD_RESET_FAILED'));
  error.code = String(code || 'PASSWORD_RESET_FAILED');
  error.statusCode = Math.max(400, Math.min(599, Number(statusCode || 503) || 503));
  return error;
}

function canonical(value) {
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (typeof value === 'object') return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}

function exactKeys(object, keys) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) return false;
  const actual = Object.keys(object).sort();
  const expected = keys.slice().sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function b64uEncode(bytes) { return Buffer.from(bytes).toString('base64url'); }
function b64uDecode(value, exactLength, maximumLength) {
  const clean = String(value || '').trim();
  if (!clean || (maximumLength && clean.length > maximumLength) || !/^[A-Za-z0-9_-]+$/.test(clean) || clean.length % 4 === 1) {
    throw resetError('DIRAC_D10_BASE64URL_INVALID', 400);
  }
  let buffer;
  try { buffer = Buffer.from(clean, 'base64url'); } catch (_) { buffer = Buffer.alloc(0); }
  if (!buffer.length || buffer.toString('base64url') !== clean || (exactLength && buffer.length !== exactLength)) {
    throw resetError('DIRAC_D10_BASE64URL_INVALID', 400);
  }
  return buffer;
}
function randomToken(bytes) { return crypto.randomBytes(bytes).toString('base64url'); }
async function sha512(bytes) { return Buffer.from(await subtle.digest('SHA-512', Buffer.from(bytes))); }
async function hkdf(ikm, salt, info, length) {
  const key = await subtle.importKey('raw', Buffer.from(ikm), 'HKDF', false, ['deriveBits']);
  return Buffer.from(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-512', salt: Buffer.from(salt), info: encoder.encode(String(info || '')) }, key, length * 8));
}
async function layerAad(header, direction, layer) {
  const digest = await sha512(encoder.encode(canonical(header)));
  try {
    return Buffer.from(encoder.encode(canonical({
      protocol: D10.protocol,
      suite: D10.suite,
      header_sha512_b64url: b64uEncode(digest),
      direction: String(direction || ''),
      layer: Number(layer)
    })));
  } finally { digest.fill(0); }
}

async function openD10Request(carrier, ops) {
  if (!subtle) throw resetError('DIRAC_D10_CRYPTO_UNAVAILABLE', 503);
  const text = String(carrier || '');
  if (text.length < 80 || text.length > 8100) throw resetError('DIRAC_D10_ENVELOPE_LENGTH_INVALID', 400);
  const parts = text.split('.');
  if (parts.length !== 22 || parts[0] !== 'd10' || parts[1] !== 'v1') throw resetError('DIRAC_D10_ENVELOPE_FIELDS_INVALID', 400);
  const keyId = String(parts[2] || '');
  const requestId = String(parts[3] || '');
  const sentAt = Number(parts[4]);
  const expiresAt = Number(parts[5]);
  const clientNonce = String(parts[6] || '');
  if (!/^[A-Za-z0-9_-]{8,80}$/.test(keyId)
      || !/^[A-Za-z0-9_-]{32}$/.test(requestId)
      || !/^[A-Za-z0-9_-]{43}$/.test(clientNonce)
      || !Number.isSafeInteger(sentAt) || !Number.isSafeInteger(expiresAt)
      || expiresAt - sentAt !== D10.requestTtlMs || sentAt > Date.now() + 30000 || expiresAt <= Date.now()) {
    throw resetError('DIRAC_D10_ENVELOPE_BINDING_INVALID', 403);
  }
  const ephemeralDer = b64uDecode(parts[7], null, 256);
  const salt = b64uDecode(parts[8], 64, 128);
  const descriptors = [];
  let offset = 9;
  for (let layer = 1; layer <= D10.layers; layer += 1) {
    descriptors.push({ nonce: parts[offset], tag: parts[offset + 1], wrapped: parts[offset + 2] });
    offset += 3;
  }
  let current = b64uDecode(parts[21], null, 131000);
  const pkcs8 = Buffer.from(await ops.unsealPrivateKey(keyId));
  let shared = null;
  let requestRoot = null;
  let responseRoot = null;
  let transcriptHash = null;
  try {
    const privateKey = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
    const publicKey = await subtle.importKey('spki', ephemeralDer, { name: 'X25519' }, false, []);
    shared = Buffer.from(await subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256));
    if (shared.length !== 32 || shared.equals(Buffer.alloc(32))) throw resetError('DIRAC_D10_SHARED_SECRET_INVALID', 403);
    const header = {
      v: D10.protocol,
      suite: D10.suite,
      key_id: keyId,
      request_id: requestId,
      sent_at_ms: sentAt,
      expires_at_ms: expiresAt,
      client_nonce: clientNonce,
      x25519_ephemeral_public_key_b64url: parts[7],
      hkdf_salt_b64url: parts[8]
    };
    transcriptHash = await sha512(encoder.encode(canonical(header)));
    requestRoot = await hkdf(shared, salt, 'dirac/d10/v1/request-root\n' + b64uEncode(transcriptHash), 64);
    responseRoot = await hkdf(shared, salt, 'dirac/d10/v1/response-root\n' + b64uEncode(transcriptHash), 64);
    for (let layer = D10.layers; layer >= 1; layer -= 1) {
      const descriptor = descriptors[layer - 1];
      const nonce = b64uDecode(descriptor.nonce, 12, 128);
      const tag = b64uDecode(descriptor.tag, 16, 128);
      const wrapped = b64uDecode(descriptor.wrapped, 40, 128);
      const kekBytes = await hkdf(requestRoot, transcriptHash, 'dirac/d10/v1/request/kek/' + layer, 32);
      const aad = await layerAad(header, 'request', layer);
      try {
        const kek = await subtle.importKey('raw', kekBytes, { name: 'AES-KW' }, false, ['unwrapKey']);
        const dek = await subtle.unwrapKey('raw', wrapped, kek, { name: 'AES-KW' }, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        const sealed = Buffer.concat([current, tag]);
        const opened = Buffer.from(await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, dek, sealed));
        current.fill(0);
        current = opened;
        sealed.fill(0);
      } finally { nonce.fill(0); tag.fill(0); wrapped.fill(0); kekBytes.fill(0); aad.fill(0); }
    }
    let plainText;
    let inner;
    try { plainText = decoder.decode(current); inner = JSON.parse(plainText); }
    catch (_) { throw resetError('DIRAC_D10_INNER_PARSE_FAILED', 403); }
    if (!inner || typeof inner !== 'object' || Array.isArray(inner) || canonical(inner) !== plainText
        || inner.v !== D10.inner || inner.request_id !== requestId || inner.client_nonce !== clientNonce
        || Number(inner.sent_at_ms) !== sentAt || !/^[A-Za-z0-9_-]{43}$/.test(String(inner.browser_binding || ''))
        || !/^(start|verify|commit)$/.test(String(inner.op || ''))) {
      throw resetError('DIRAC_D10_INNER_BINDING_INVALID', 403);
    }
    return {
      inner,
      context: { keyId, requestId, clientNonce, responseRoot: Buffer.from(responseRoot), transcriptHash: Buffer.from(transcriptHash) }
    };
  } catch (error) {
    if (error && error.code) throw error;
    throw resetError('DIRAC_D10_REQUEST_AUTHENTICATION_FAILED', 403);
  } finally {
    ephemeralDer.fill(0); salt.fill(0); pkcs8.fill(0); current.fill(0);
    if (shared) shared.fill(0); if (requestRoot) requestRoot.fill(0); if (responseRoot) responseRoot.fill(0); if (transcriptHash) transcriptHash.fill(0);
  }
}

async function sealD10Response(payload, context) {
  let current = Buffer.from(encoder.encode(canonical(payload)));
  const issuedAt = Date.now();
  const expiresAt = issuedAt + D10.requestTtlMs;
  const header = {
    protocol: D10.protocol,
    suite: D10.suite,
    key_id: context.keyId,
    request_id: context.requestId,
    client_nonce: context.clientNonce,
    issued_at_ms: issuedAt,
    expires_at_ms: expiresAt
  };
  const layers = [];
  try {
    for (let layer = 1; layer <= D10.layers; layer += 1) {
      const dek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
      const nonce = crypto.randomBytes(12);
      const kekBytes = await hkdf(context.responseRoot, context.transcriptHash, 'dirac/d10/v1/response/kek/' + layer, 32);
      const aad = await layerAad(header, 'response', layer);
      try {
        const kek = await subtle.importKey('raw', kekBytes, { name: 'AES-KW' }, false, ['wrapKey']);
        const sealed = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, dek, current));
        if (sealed.length < 16) throw resetError('DIRAC_D10_RESPONSE_LAYER_INVALID', 503);
        const ciphertext = sealed.subarray(0, sealed.length - 16);
        const tag = sealed.subarray(sealed.length - 16);
        const wrapped = Buffer.from(await subtle.wrapKey('raw', dek, kek, { name: 'AES-KW' }));
        if (wrapped.length !== 40) throw resetError('DIRAC_D10_RESPONSE_KEY_WRAP_INVALID', 503);
        layers.push({ nonce: b64uEncode(nonce), tag: b64uEncode(tag), wrapped: b64uEncode(wrapped) });
        const next = Buffer.from(ciphertext);
        current.fill(0);
        current = next;
        sealed.fill(0); wrapped.fill(0);
      } finally { nonce.fill(0); kekBytes.fill(0); aad.fill(0); }
    }
    const parts = ['d10r', 'v1', context.keyId, context.requestId, String(issuedAt), String(expiresAt), context.clientNonce];
    layers.forEach((layer) => parts.push(layer.nonce, layer.tag, layer.wrapped));
    parts.push(b64uEncode(current));
    const carrier = parts.join('.');
    if (carrier.length > 131000) throw resetError('DIRAC_D10_RESPONSE_TOO_LARGE', 503);
    return carrier;
  } finally { current.fill(0); context.responseRoot.fill(0); context.transcriptHash.fill(0); }
}

function resetResponse(res, status, body) {
  try {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
  } catch (_) {}
  return res.status(status).json(body);
}

async function passwordResetEngine(req, res, ops, body) {
  const action = String(req && req.query && req.query.action || '').trim().toLowerCase();
  const input = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  diracResetDiagnosticV335(req, 'engine.enter', 'begin', { body_keys: Object.keys(input).sort() });
  if (action === 'request_password_reset') {
    if (!exactKeys(input, ['action', 'email'])
        || String(input.action || '').trim().toLowerCase().replace(/-/g, '_') !== action
        || String(input.email || '') !== RESET_PROFILE_CARRIER) {
      return resetResponse(res, 400, { ok: false, code: 'PASSWORD_RESET_PROFILE_REQUEST_INVALID' });
    }
    diracResetDiagnosticV335(req, 'profile.issue', 'begin', { carrier_valid: true, subtle_available: Boolean(subtle) });
    const profile = await ops.issueProfile();
    diracResetDiagnosticV335(req, 'profile.issue', 'success', { key_id_length: String(profile && profile.key_id || '').length, x25519_public_key_length: String(profile && profile.x25519_public_key_b64url || '').length, signing_public_key_length: String(profile && profile.profile_signing_public_key_b64url || '').length, signature_length: String(profile && profile.signature_b64url || '').length, expires_in_ms: Number(profile && profile.expires_at_ms || 0) - Number(profile && profile.issued_at_ms || 0) });
    const challenge = 'd10p.' + b64uEncode(Buffer.from(canonical(profile), 'utf8'));
    diracResetDiagnosticV335(req, 'profile.response', 'success', { http_status: 200, encrypted: true, challenge_length: challenge.length });
    return resetResponse(res, 200, { ok: true, encrypted: true, protocol: D10.protocol, challenge });
  }
  if (action !== 'confirm_password_reset') throw resetError('PASSWORD_RESET_ACTION_INVALID', 400);
  if (!exactKeys(input, ['action', 'code', 'resetToken'])
      || String(input.action || '').trim().toLowerCase().replace(/-/g, '_') !== action
      || input.code !== RESET_CONFIRM_MARKER) {
    return resetResponse(res, 400, { ok: false, code: 'PASSWORD_RESET_ENVELOPE_REQUEST_INVALID' });
  }
  diracResetDiagnosticV335(req, 'd10.open', 'begin', { carrier_length: String(input.resetToken || '').length });
  const opened = await openD10Request(input.resetToken, ops);
  const inner = opened.inner;
  diracResetDiagnosticV335(req, 'd10.open', 'success', { op: String(inner && inner.op || ''), request_id_hash: crypto.createHash('sha256').update(String(inner && inner.request_id || '')).digest('hex').slice(0, 20), key_id_length: String(opened && opened.context && opened.context.keyId || '').length });
  let payload;
  try {
    const bindingNow = String(await ops.requestBinding());
    const browserHash = String(await ops.hashBinding('browser', inner.browser_binding));
    const keyId = opened.context.keyId;
    diracResetDiagnosticV335(req, 'confirm.binding', 'success', { op: String(inner.op || ''), request_binding_length: bindingNow.length, browser_hash_length: browserHash.length, key_id_length: String(keyId || '').length });
    if (inner.op === 'start') {
      diracResetDiagnosticV335(req, 'start', 'begin', {});
      if (!exactKeys(inner, ['v','op','request_id','client_nonce','sent_at_ms','browser_binding','email'])) throw resetError('PASSWORD_RESET_START_FIELDS_INVALID', 400);
      const email = String(inner.email || '').trim().toLowerCase();
      if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email) || email.length > 120) throw resetError('PASSWORD_RESET_EMAIL_INVALID', 400);
      const rpId = String(await ops.rpId());
      diracResetDiagnosticV335(req, 'start.challenge_issue', 'begin', { rp_id: rpId, email_binding_hash: diracPasswordResetBindingHashV333('diag-email', email).slice(0, 20) });
      const issued = await ops.issueChallenge({ email, browserHash, requestBinding: bindingNow, keyId, rpId });
      diracResetDiagnosticV335(req, 'start.challenge_issue', 'success', { challenge_id_length: String(issued && issued.challenge_id || '').length, challenge_length: String(issued && issued.challenge || '').length, expires_in_ms: Number(issued && issued.expires_at_ms || 0) - Date.now() });
      if (!issued || !/^[A-Za-z0-9_-]{43,86}$/.test(String(issued.challenge_id || ''))
          || !/^[A-Za-z0-9_-]{43}$/.test(String(issued.challenge || ''))
          || Number(issued.expires_at_ms || 0) <= Date.now()) throw resetError('PASSWORD_RESET_CHALLENGE_ISSUE_FAILED', 503);
      payload = {
        ok: true, op: 'start', challenge_id: String(issued.challenge_id),
        publicKey: {
          challenge: String(issued.challenge),
          rpId,
          timeout: 180000,
          userVerification: 'required',
          device_binding_required: true,
          device_binding_policy: 'webcrypto-nonextractable-v1'
        }
      };
      diracResetDiagnosticV335(req, 'start', 'success', { rp_id: rpId, user_verification: 'required', device_binding_required: true });
    } else if (inner.op === 'verify') {
      diracResetDiagnosticV335(req, 'verify', 'begin', {});
      if (!exactKeys(inner, ['v','op','request_id','client_nonce','sent_at_ms','browser_binding','challenge_id','credential','device_binding'])) throw resetError('PASSWORD_RESET_VERIFY_FIELDS_INVALID', 400);
      const challengeId = String(inner.challenge_id || '');
      diracResetDiagnosticV335(req, 'verify.challenge_read', 'begin', { challenge_id_hash: crypto.createHash('sha256').update(challengeId).digest('hex').slice(0, 20) });
      const state = await ops.readChallenge(challengeId, { browserHash, requestBinding: bindingNow, keyId, rpId: String(await ops.rpId()) });
      diracResetDiagnosticV335(req, 'verify.challenge_read', 'success', { state_kind: String(state && state.kind || ''), expires_in_ms: Number(state && state.expires_at_ms || 0) - Date.now() });
      if (!state || state.kind !== 'challenge' || Number(state.expires_at_ms || 0) <= Date.now()) {
        throw resetError('PASSWORD_RESET_CHALLENGE_BINDING_INVALID', 403);
      }
      diracResetDiagnosticV335(req, 'verify.passkey', 'begin', { credential_present: Boolean(inner.credential), device_binding_present: Boolean(inner.device_binding) });
      const verified = await ops.verifyPasskey(state, {
        challenge_id: challengeId,
        credential: inner.credential,
        device_binding: String(inner.device_binding || '')
      });
      diracResetDiagnosticV335(req, 'verify.passkey', 'success', { owner_bound: true, security_epoch: Number(verified && verified.security_epoch || 0), device_binding_key_id_present: Boolean(verified && verified.device_binding_key_id) });
      diracResetDiagnosticV335(req, 'verify.grant_issue', 'begin', {});
      const grant = await ops.issueGrant(verified, { browserHash, requestBinding: bindingNow, keyId });
      diracResetDiagnosticV335(req, 'verify.grant_issue', 'success', { grant_length: String(grant || '').length });
      if (!/^[A-Za-z0-9_-]{43,256}$/.test(String(grant || ''))) throw resetError('PASSWORD_RESET_GRANT_ISSUE_FAILED', 503);
      payload = { ok: true, op: 'verify', passkey_verified: true, owner_bound: true, reset_grant: String(grant) };
      diracResetDiagnosticV335(req, 'verify', 'success', { passkey_verified: true, owner_bound: true });
    } else if (inner.op === 'commit') {
      diracResetDiagnosticV335(req, 'commit', 'begin', {});
      if (!exactKeys(inner, ['v','op','request_id','client_nonce','sent_at_ms','browser_binding','reset_grant','new_password','confirm_password'])) throw resetError('PASSWORD_RESET_COMMIT_FIELDS_INVALID', 400);
      const grantId = String(inner.reset_grant || '');
      diracResetDiagnosticV335(req, 'commit.grant_read', 'begin', { grant_hash: crypto.createHash('sha256').update(grantId).digest('hex').slice(0, 20) });
      const state = await ops.readGrant(grantId, { browserHash, requestBinding: bindingNow, keyId });
      diracResetDiagnosticV335(req, 'commit.grant_read', 'success', { state_kind: String(state && state.kind || ''), expires_in_ms: Number(state && state.expires_at_ms || 0) - Date.now(), security_epoch: Number(state && state.security_epoch || 0) });
      if (!state || state.kind !== 'grant' || Number(state.expires_at_ms || 0) <= Date.now()) {
        throw resetError('PASSWORD_RESET_GRANT_BINDING_INVALID', 403);
      }
      diracResetDiagnosticV335(req, 'commit.password', 'begin', { password_present: Boolean(inner.new_password), confirmation_present: Boolean(inner.confirm_password) });
      const result = await ops.commitPassword(state, String(inner.new_password || ''), String(inner.confirm_password || ''), grantId);
      diracResetDiagnosticV335(req, 'commit.password', 'success', { password_changed: result && result.password_changed === true, sessions_revoked: result && result.sessions_revoked === true, login_required: result && result.login_required === true });
      payload = { ok: true, op: 'commit', password_changed: result.password_changed === true, passkey_verified: true, owner_bound: true, sessions_revoked: result.sessions_revoked === true, login_required: result.login_required === true };
      if (!payload.password_changed || !payload.sessions_revoked || !payload.login_required) throw resetError('PASSWORD_RESET_COMMIT_POSTCONDITION_FAILED', 503);
      diracResetDiagnosticV335(req, 'commit', 'success', { password_changed: true, sessions_revoked: true, login_required: true });
    } else {
      throw resetError('PASSWORD_RESET_OPERATION_INVALID', 400);
    }
  } catch (error) {
    diracResetDiagnosticV335(req, 'confirm.operation', 'error', { op: String(inner.op || '') }, error);
    payload = { ok: false, op: String(inner.op || ''), code: String(error && error.code || 'PASSWORD_RESET_REQUEST_REJECTED'), message: 'Permintaan lost password tidak dapat diproses.' };
  }
  diracResetDiagnosticV335(req, 'd10.seal', 'begin', { op: String(inner.op || ''), payload_ok: payload && payload.ok === true, payload_code: String(payload && payload.code || '') });
  const challenge = await sealD10Response(payload, opened.context);
  diracResetDiagnosticV335(req, 'd10.seal', 'success', { op: String(inner.op || ''), carrier_length: challenge.length, http_status: 200 });
  return resetResponse(res, 200, { ok: true, encrypted: true, protocol: D10.protocol, challenge });
}

const RESET_GATEWAY_TOKEN = Object.freeze({ version: 'dirac-keamanan-reset-gateway-v333' });
const PASSWORD_CHANGE_GATEWAY_TOKEN = Object.freeze({ version: 'dirac-keamanan-password-change-gateway-v1' });


/* ============================================================
   DIRAC KEAMANAN STANDALONE PASSWORD RESET PRIMITIVES v334
   Scope: request_password_reset / confirm_password_reset only.
   Central health remains byte-identical. No alternate reset route, no new ENV/table/RPC.
   ============================================================ */
const SECURITY_NATIVE_FETCH_V334 = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null;
const SECURITY_RESET_PROFILE_PIN_V334 = 'y1etldCKpbWMPOa-aNEfOiQd60Y_M6R3Sc1xY9sB8rX-GtJPaIG13P5OzxgcRuYOIT98Rcuum4syOhT_Okdmlw';
const SECURITY_RESET_CSRF_TTL_S_V334 = 180;
const SECURITY_RESET_PAGE_NONCE_TTL_S_V334 = 120;
const SECURITY_RESET_MAX_BODY_V334 = 196608;
const DIRAC_PASSKEY_DEVICE_BINDING_VERSION = 'dirac-passkey-device-binding-v1';
const DIRAC_PASSKEY_DEVICE_BINDING_ALGORITHM = 'ECDSA-P256-SHA256';
const DIRAC_PASSWORD_ARGON2ID_ACTIVE_ONLY_PATCH_V120 = 'password-argon2id-active-only-v120';
const DIRAC_PERSISTENT_BAN_TABLE = 'dirac_persistent_bans';

function safeEqual(a, b) {
  const A = Buffer.from(String(a === undefined || a === null ? '' : a));
  const B = Buffer.from(String(b === undefined || b === null ? '' : b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}
function normalizeAuthEmail(value) { return String(value || '').trim().toLowerCase(); }
function isValidAuthEmail(value) {
  const email = normalizeAuthEmail(value);
  return email.length >= 3 && email.length <= 254 && /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email);
}
function customerSecurityLooksLikeUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}
function normalizeDashboardMfaOrigin(value) {
  try {
    const u = new URL(String(value || '').trim());
    if (u.protocol !== 'https:' && !(process.env.NODE_ENV !== 'production' && u.protocol === 'http:')) return '';
    return u.origin.toLowerCase();
  } catch (_) { return ''; }
}
function requestOrigin(req) {
  const h = req && req.headers && typeof req.headers === 'object' ? req.headers : {};
  return normalizeDashboardMfaOrigin(h.origin || h.Origin || h.referer || h.referrer || '');
}
function requestUserAgent(req) {
  const h = req && req.headers && typeof req.headers === 'object' ? req.headers : {};
  return String(h['user-agent'] || h['User-Agent'] || '').slice(0, 1000);
}
function diracBaseDomainV250() {
  const value = String(process.env.DIRAC_BASE_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) {
    throw resetError('DIRAC_BASE_DOMAIN_INVALID', 503);
  }
  return value;
}
function diracRoleOriginV250(role) {
  const base = diracBaseDomainV250();
  return role === 'auth' ? 'https://auth.' + base : 'https://' + base;
}
function diracPasskeyA2FRpId(req) {
  const base = diracBaseDomainV250();
  const explicit = String(process.env.WEBAUTHN_RP_ID || process.env.DIRAC_WEBAUTHN_RP_ID || '').trim().toLowerCase();
  const normalized = explicit.replace(/^https?:\/\//, '').replace(/\/+$/, '').replace(/\.$/, '');
  if (explicit && normalized !== base) throw resetError('DIRAC_WEBAUTHN_RP_ID_CONFIG_INVALID', 503);
  if (process.env.NODE_ENV !== 'production') {
    const h = String(req && req.headers && req.headers.host || '').split(':')[0].toLowerCase();
    if (h === 'localhost' || h === '127.0.0.1') return h;
  }
  return base;
}
function diracCentralRootSecretV146() {
  const value = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '');
  const min = process.env.NODE_ENV === 'production' ? 3000 : 32;
  if (Buffer.byteLength(value, 'utf8') < min) throw resetError('DIRAC_SECURITY_ROOT_SECRET_INVALID', 503);
  return value;
}
function diracCentralDeriveSecretV146(scope) {
  return crypto.createHmac('sha512', diracCentralRootSecretV146()).update('dirac-derived-secret-v146:' + String(scope || '')).digest();
}
function diracCentralHashV146(value) {
  const key = diracCentralDeriveSecretV146('central-v146');
  try { return crypto.createHmac('sha256', key).update(String(value || '')).digest('hex'); }
  finally { key.fill(0); }
}
function diracCentralCurrentContextV149() { return null; }
function securityResetHeaderV334(req, name) {
  const h = req && req.headers && typeof req.headers === 'object' ? req.headers : {};
  const lower = String(name || '').toLowerCase();
  const value = h[lower] !== undefined ? h[lower] : h[name];
  return Array.isArray(value) ? value.join(',') : String(value || '');
}

const DIRAC_RESET_DIAGNOSTIC_VERSION_V335 = 'dirac-reset-diagnostic-v335';
const DIRAC_RESET_DIAGNOSTIC_TRACE_V335 = new WeakMap();
function diracResetDiagnosticTraceIdV335(req) {
  if (!req || typeof req !== 'object') return 'no-request';
  const existing = DIRAC_RESET_DIAGNOSTIC_TRACE_V335.get(req); if (existing) return existing;
  const headers = req.headers && typeof req.headers === 'object' ? req.headers : {};
  const source = String(headers['x-vercel-id'] || headers['x-request-id'] || headers['x-vercel-request-id'] || '').trim();
  const traceId = source ? crypto.createHash('sha256').update(source).digest('hex').slice(0, 20) : crypto.randomBytes(10).toString('hex');
  try { DIRAC_RESET_DIAGNOSTIC_TRACE_V335.set(req, traceId); } catch (_) {}
  return traceId;
}
function diracResetDiagnosticCookieNamesV335(req) {
  return securityResetHeaderV334(req, 'cookie').split(';').map((part) => part.split('=')[0].trim()).filter((name) => /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/.test(name)).slice(0, 32).sort();
}
function diracResetDiagnosticErrorV335(error) {
  if (!error) return null;
  return {
    name: String(error.name || 'Error').slice(0, 120),
    code: String(error.code || 'UNEXPECTED_ERROR').slice(0, 160),
    status: Math.max(0, Math.min(599, Number(error.statusCode || error.status || 0) || 0)),
    stack: String(error.stack || '').split('\n').slice(0, 12).map((line) => line.trim()).filter(Boolean)
  };
}
function diracResetDiagnosticV335(req, stage, outcome, details, error) {
  try {
    const record = {
      v: DIRAC_RESET_DIAGNOSTIC_VERSION_V335,
      ts: new Date().toISOString(),
      trace_id: diracResetDiagnosticTraceIdV335(req),
      stage: String(stage || 'unknown').slice(0, 180),
      outcome: String(outcome || 'info').slice(0, 40),
      action: String(req && req.query && req.query.action || '').slice(0, 80),
      method: String(req && req.method || '').toUpperCase().slice(0, 12),
      runtime: { node: process.version, node_env: String(process.env.NODE_ENV || '') },
      request: req ? {
        host: securityResetHeaderV334(req, 'host').slice(0, 180),
        origin: requestOrigin(req).slice(0, 300),
        referer: securityResetHeaderV334(req, 'referer').slice(0, 500),
        fetch_site: securityResetHeaderV334(req, 'sec-fetch-site').slice(0, 40),
        fetch_mode: securityResetHeaderV334(req, 'sec-fetch-mode').slice(0, 40),
        fetch_dest: securityResetHeaderV334(req, 'sec-fetch-dest').slice(0, 40),
        content_type: securityResetHeaderV334(req, 'content-type').slice(0, 120),
        content_length: securityResetHeaderV334(req, 'content-length').slice(0, 40),
        cookie_names: diracResetDiagnosticCookieNamesV335(req),
        csrf_header_present: Boolean(securityResetHeaderV334(req, 'x-dirac-csrf-token') || securityResetHeaderV334(req, 'x-csrf-token')),
        page_nonce_header_present: Boolean(securityResetHeaderV334(req, 'x-dirac-page-nonce') || securityResetHeaderV334(req, 'x-page-nonce')),
        reset_nonce_cookie_present: Boolean(securityResetCentralCookieValueV334(req, '__Host-dirac_reset_page_nonce_v334'))
      } : null,
      details: details && typeof details === 'object' && !Array.isArray(details) ? details : {},
      error: diracResetDiagnosticErrorV335(error)
    };
    const line = '[dirac-reset-diagnostic-v335] ' + JSON.stringify(record);
    if (outcome === 'error' || outcome === 'rejected') console.error(line); else console.info(line);
  } catch (_) {}
}
function securityResetCookieMapV334(req) {
  const out = Object.create(null);
  const raw = securityResetHeaderV334(req, 'cookie');
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const key = part.slice(0, i).trim();
    if (!key || Object.prototype.hasOwnProperty.call(out, key)) continue;
    try { out[key] = decodeURIComponent(part.slice(i + 1).trim()); } catch (_) { out[key] = part.slice(i + 1).trim(); }
  }
  return out;
}
function securityResetSessionBindingV334(req) {
  const cookies = securityResetCookieMapV334(req);
  const names = [
    String(process.env.DOMAIN_SESSION_COOKIE || 'dirac_domain_session'),
    String(process.env.DOMAIN_REFRESH_COOKIE || 'dirac_domain_refresh'),
    String(process.env.DOMAIN_SIGNED_SESSION_COOKIE || 'dirac_domain_signed_session')
  ];
  const material = names.map((name) => String(cookies[name] || '')).filter(Boolean).join('|');
  return crypto.createHash('sha256').update(material).digest('hex');
}
function securityResetRequestFingerprintV334(req) {
  const origin = requestOrigin(req);
  const ua = requestUserAgent(req);
  const al = securityResetHeaderV334(req, 'accept-language').slice(0, 200);
  const ch = securityResetHeaderV334(req, 'sec-ch-ua').slice(0, 300);
  return crypto.createHash('sha256').update([origin, ua, al, ch].join('\n')).digest('hex');
}
function securityResetTokenSignV334(payload, scope) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const key = diracCentralDeriveSecretV146(scope);
  try { return encoded + '.' + crypto.createHmac('sha256', key).update(encoded).digest('base64url'); }
  finally { key.fill(0); }
}
function securityResetTokenDecodeV334(token, scope) {
  const parts = String(token || '').split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) return null;
  const key = diracCentralDeriveSecretV146(scope);
  let expected;
  try { expected = crypto.createHmac('sha256', key).update(parts[0]).digest('base64url'); }
  finally { key.fill(0); }
  if (!safeEqual(expected, parts[1])) return null;
  try {
    const raw = Buffer.from(parts[0], 'base64url');
    if (raw.toString('base64url') !== parts[0] || raw.length > 4096) return null;
    const value = JSON.parse(raw.toString('utf8'));
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch (_) { return null; }
}
function securityResetBindingPayloadV334(req) {
  const origin = requestOrigin(req);
  return {
    sid: securityResetSessionBindingV334(req),
    oh: crypto.createHash('sha256').update('origin|' + origin).digest('hex'),
    rb: securityResetRequestFingerprintV334(req)
  };
}
function securityResetIssueCsrfV334(req) {
  const now = Math.floor(Date.now() / 1000);
  const b = securityResetBindingPayloadV334(req);
  return securityResetTokenSignV334({ typ:'dirac-keamanan-reset-csrf-v1', iat:now, exp:now + SECURITY_RESET_CSRF_TTL_S_V334, n:randomToken(18), sid:b.sid, oh:b.oh, rb:b.rb }, 'keamanan-reset-csrf-v1');
}
function securityResetIssuePageNonceV334(req, action) {
  const now = Math.floor(Date.now() / 1000);
  const b = securityResetBindingPayloadV334(req);
  return securityResetTokenSignV334({ typ:'dirac-keamanan-reset-page-nonce-v1', iat:now, exp:now + SECURITY_RESET_PAGE_NONCE_TTL_S_V334, jti:randomToken(24), act:String(action), mth:'POST', sid:b.sid, oh:b.oh, rb:b.rb }, 'keamanan-reset-page-nonce-v1');
}
function securityResetCentralCsrfCookieV334(req, token, origin) {
  const raw = securityResetHeaderV334(req, 'cookie');
  const base = String(process.env.DIRAC_CSRF_COOKIE || '__Host-dirac_csrf_hmac').trim();
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/.test(base)) return false;
  const scoped = base + '__' + crypto.createHash('sha256').update('dirac-csrf-origin-scoped-cookie-v327\n' + String(origin || ''), 'utf8').digest('hex').slice(0,16);
  const values = (name) => {
    const found = [];
    for (const part of raw.split(';')) {
      const i = part.indexOf('='); if (i < 1 || part.slice(0,i).trim() !== name) continue;
      let value; try { value = decodeURIComponent(part.slice(i+1).trim()); } catch (_) { value = part.slice(i+1).trim(); }
      if (value && !found.includes(value)) found.push(value);
    }
    return found;
  };
  const scopedValues = values(scoped);
  if (scopedValues.length === 1) return safeEqual(scopedValues[0], token);
  if (scopedValues.length > 1) return false;
  const legacyValues = values(base);
  return legacyValues.length === 1 && safeEqual(legacyValues[0], token);
}
function securityResetVerifyCentralCsrfV334(req, token) {
  const parts = String(token || '').trim().split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) return false;
  const secret = diracCentralDeriveSecretV146('csrf-v119').toString('base64url');
  const expected = crypto.createHmac('sha256', secret).update(parts[0]).digest('base64url');
  if (!safeEqual(expected, parts[1])) return false;
  let payload;
  try { payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); } catch (_) { return false; }
  if (!exactKeys(payload, ['typ','iat','exp','n','sid','oh']) || payload.typ !== 'dirac-csrf-hmac-v1') return false;
  const now = Math.floor(Date.now()/1000);
  const maxAge = Math.max(300, Math.min(86400, Number(process.env.DIRAC_CSRF_MAX_AGE_SECONDS || 7200)));
  if (!Number.isSafeInteger(Number(payload.iat)) || !Number.isSafeInteger(Number(payload.exp)) || Number(payload.exp) <= Number(payload.iat)
      || Number(payload.exp) - Number(payload.iat) !== maxAge || Number(payload.iat) > now + 60 || Number(payload.exp) + 60 < now
      || !/^[A-Za-z0-9_-]{24}$/.test(String(payload.n || '')) || !/^[a-f0-9]{64}$/.test(String(payload.sid || ''))
      || !/^[a-f0-9]{64}$/.test(String(payload.oh || ''))) return false;
  const origin = requestOrigin(req);
  const expectedOriginHash = crypto.createHash('sha256').update('origin|' + origin).digest('hex');
  return safeEqual(String(payload.oh), expectedOriginHash) && securityResetCentralCsrfCookieV334(req, token, origin);
}
function securityResetVerifyCsrfV334(req, token) {
  const p = securityResetTokenDecodeV334(token, 'keamanan-reset-csrf-v1');
  const now = Math.floor(Date.now() / 1000); const b = securityResetBindingPayloadV334(req);
  if (p && p.typ === 'dirac-keamanan-reset-csrf-v1' && Number.isSafeInteger(Number(p.iat)) && Number.isSafeInteger(Number(p.exp))
      && Number(p.iat) <= now + 30 && Number(p.exp) > now && Number(p.exp) <= Number(p.iat) + SECURITY_RESET_CSRF_TTL_S_V334
      && /^[A-Za-z0-9_-]{24}$/.test(String(p.n || '')) && safeEqual(String(p.sid || ''), b.sid)
      && safeEqual(String(p.oh || ''), b.oh) && safeEqual(String(p.rb || ''), b.rb)) return true;
  return securityResetVerifyCentralCsrfV334(req, token);
}
function securityResetCentralCookieValueV334(req, name) {
  const cleanName = String(name || '').trim();
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/.test(cleanName)) return null;
  const values = [];
  for (const part of securityResetHeaderV334(req, 'cookie').split(';')) {
    const index = part.indexOf('=');
    if (index < 1 || part.slice(0, index).trim() !== cleanName) continue;
    let value;
    try { value = decodeURIComponent(part.slice(index + 1).trim()); } catch (_) { value = part.slice(index + 1).trim(); }
    if (!values.includes(value)) values.push(value);
  }
  return values.length <= 1 ? String(values[0] || '') : null;
}
function securityResetCentralSessionHashV334(req) {
  const names = [
    String(process.env.DOMAIN_SESSION_COOKIE || 'dirac_domain_session'),
    String(process.env.DOMAIN_SIGNED_SESSION_COOKIE || 'dirac_domain_signed_session'),
    'sb_access_token'
  ];
  const values = [];
  for (const name of names) {
    const value = securityResetCentralCookieValueV334(req, name);
    if (value === null) return '';
    if (value) values.push(value);
  }
  return diracCentralHashV146(values.join('|'));
}
function securityResetVerifyCentralPageNonceV334(req, token, action) {
  const parts = String(token || '').trim().split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) return null;
  const secret = diracCentralDeriveSecretV146('central-v146');
  let expected;
  try { expected = crypto.createHmac('sha256', secret).update(parts[0]).digest('base64url'); }
  finally { secret.fill(0); }
  if (!safeEqual(expected, parts[1])) return null;
  let payload;
  try {
    const raw = Buffer.from(parts[0], 'base64url');
    if (!raw.length || raw.length > 4096 || raw.toString('base64url') !== parts[0]) return null;
    payload = JSON.parse(raw.toString('utf8'));
  } catch (_) { return null; }
  if (!exactKeys(payload, ['typ','iat','exp','jti','act','mth','sid','oh']) || payload.typ !== 'dirac-page-nonce-v1') return null;
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(Number(payload.iat)) || !Number.isSafeInteger(Number(payload.exp))
      || Number(payload.exp) - Number(payload.iat) !== 300 || Number(payload.iat) > now + 30 || Number(payload.iat) < now - 600
      || Number(payload.exp) <= now || !/^[A-Za-z0-9_-]{32}$/.test(String(payload.jti || ''))
      || String(payload.act || '') !== String(action || '') || String(payload.mth || '').toUpperCase() !== (String(action || '') === 'domain_health' ? 'GET' : 'POST')
      || !/^[a-f0-9]{64}$/.test(String(payload.sid || '')) || !/^[a-f0-9]{64}$/.test(String(payload.oh || ''))) return null;
  const expectedSid = securityResetCentralSessionHashV334(req);
  const expectedOriginHash = diracCentralHashV146(requestOrigin(req));
  if (!/^[a-f0-9]{64}$/.test(expectedSid) || !safeEqual(String(payload.sid), expectedSid) || !safeEqual(String(payload.oh), expectedOriginHash)) return null;
  return { ...payload, __diracPageNonceSourceV334: 'central' };
}
function securityResetVerifyPageNonceV334(req, token, action) {
  const p = securityResetTokenDecodeV334(token, 'keamanan-reset-page-nonce-v1');
  const now = Math.floor(Date.now() / 1000); const b = securityResetBindingPayloadV334(req);
  if (p && p.typ === 'dirac-keamanan-reset-page-nonce-v1' && p.act === action && p.mth === 'POST'
      && Number.isSafeInteger(Number(p.iat)) && Number.isSafeInteger(Number(p.exp)) && Number(p.iat) <= now + 30 && Number(p.exp) > now
      && Number(p.exp) <= Number(p.iat) + SECURITY_RESET_PAGE_NONCE_TTL_S_V334 && /^[A-Za-z0-9_-]{32}$/.test(String(p.jti || ''))
      && safeEqual(String(p.sid || ''), b.sid) && safeEqual(String(p.oh || ''), b.oh) && safeEqual(String(p.rb || ''), b.rb)) {
    return { ...p, __diracPageNonceSourceV334: 'standalone' };
  }
  const central = securityResetVerifyCentralPageNonceV334(req, token, action);
  if (central) return central;
  if (!RESET_ACTIONS.has(String(action || '')) || !securityResetVerifyCentralPageNonceV334(req, token, 'domain_health')) return null;
  const proofToken = securityResetCentralCookieValueV334(req, '__Host-dirac_reset_page_nonce_v334');
  if (!securityResetTokenDecodeV334(proofToken, 'keamanan-reset-page-nonce-v1')) return null;
  return securityResetVerifyPageNonceV334(req, proofToken, action);
}
function securityResetApplyHeadersV334(req, res, origin) {
  const allowed = String(origin || requestOrigin(req) || '');
  try {
    if (allowed) res.setHeader('Access-Control-Allow-Origin', allowed);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Expose-Headers', 'X-Dirac-CSRF-Token, X-CSRF-Token, X-Dirac-Page-Nonce, X-Page-Nonce');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache'); res.setHeader('Expires', '0');
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
  } catch (_) {}
}
function securityResetValidateBrowserV334(req, method) {
  const base = diracBaseDomainV250();
  const origin = requestOrigin(req);
  const allowedOrigins = new Set(['https://' + base, 'https://auth.' + base]);
  if (!allowedOrigins.has(origin)) throw resetError('SECURITY_RESET_ORIGIN_INVALID', 403);
  const host = securityResetHeaderV334(req, 'host').split(',')[0].trim().toLowerCase().replace(/:443$/, '');
  const xhost = securityResetHeaderV334(req, 'x-forwarded-host').split(',')[0].trim().toLowerCase().replace(/:443$/, '');
  if (host !== 'api.' + base || (xhost && xhost !== 'api.' + base)) throw resetError('SECURITY_RESET_HOST_INVALID', 403);
  const proto = securityResetHeaderV334(req, 'x-forwarded-proto').split(',')[0].trim().toLowerCase();
  if (process.env.NODE_ENV === 'production' ? proto !== 'https' : (proto && proto !== 'https')) throw resetError('SECURITY_RESET_HTTPS_REQUIRED', 403);
  const referer = securityResetHeaderV334(req, 'referer').trim();
  if (referer) {
    let ref;
    try { ref = new URL(referer); } catch (_) { throw resetError('SECURITY_RESET_REFERER_INVALID', 403); }
    if (!allowedOrigins.has(ref.origin.toLowerCase()) || !new Set(['/','/masuk.html','/html/masuk.html']).has(ref.pathname)) throw resetError('SECURITY_RESET_REFERER_INVALID', 403);
  }
  const site = securityResetHeaderV334(req, 'sec-fetch-site').trim().toLowerCase();
  const mode = securityResetHeaderV334(req, 'sec-fetch-mode').trim().toLowerCase();
  const dest = securityResetHeaderV334(req, 'sec-fetch-dest').trim().toLowerCase();
  if (site && site !== 'same-site' && site !== 'same-origin') throw resetError('SECURITY_RESET_FETCH_SITE_INVALID', 403);
  if (method === 'POST' && mode && mode !== 'cors' && mode !== 'same-origin') throw resetError('SECURITY_RESET_FETCH_MODE_INVALID', 403);
  if (method === 'POST' && dest && dest !== 'empty') throw resetError('SECURITY_RESET_FETCH_DEST_INVALID', 403);
  if (securityResetHeaderV334(req, 'authorization').trim()) throw resetError('SECURITY_RESET_AUTHORIZATION_HEADER_REJECTED', 403);
  return origin;
}
async function securityResetReadJsonV334(req) {
  if (req && req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body) && !Array.isArray(req.body)) return req.body;
  let raw = '';
  if (req && Buffer.isBuffer(req.body)) raw = req.body.toString('utf8');
  else if (req && typeof req.body === 'string') raw = req.body;
  else if (req && typeof req.on === 'function') {
    raw = await new Promise((resolve, reject) => {
      const chunks = []; let size = 0; let done = false;
      const fail = (e) => { if (!done) { done = true; reject(e); } };
      req.on('data', (chunk) => { if (done) return; const b = Buffer.from(chunk); size += b.length; if (size > SECURITY_RESET_MAX_BODY_V334) return fail(resetError('SECURITY_RESET_BODY_TOO_LARGE', 413)); chunks.push(b); });
      req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks).toString('utf8')); } });
      req.on('error', () => fail(resetError('SECURITY_RESET_BODY_READ_FAILED', 400)));
    });
  }
  if (!raw || Buffer.byteLength(raw, 'utf8') > SECURITY_RESET_MAX_BODY_V334) throw resetError('SECURITY_RESET_BODY_INVALID', 400);
  let parsed; try { parsed = JSON.parse(raw); } catch (_) { throw resetError('SECURITY_RESET_JSON_INVALID', 400); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw resetError('SECURITY_RESET_JSON_INVALID', 400);
  req.body = parsed;
  return parsed;
}

const SECURITY_SUPABASE_TARGETS_V334 = Object.freeze({
  legacy:['DOMAIN_SUPABASE_URL','DOMAIN_SUPABASE_ANON_KEY','DOMAIN_SUPABASE_SERVICE_ROLE_KEY'],
  security:['DIRAC_SECURITY_SUPABASE_URL','DIRAC_SECURITY_SUPABASE_ANON_KEY','DIRAC_SECURITY_SUPABASE_SERVICE_ROLE_KEY'],
  customerSecurity:['DIRAC_CUSTOMER_SECURITY_SUPABASE_URL','DIRAC_CUSTOMER_SECURITY_SUPABASE_ANON_KEY','DIRAC_CUSTOMER_SECURITY_SUPABASE_SERVICE_ROLE_KEY'],
  domain:['DIRAC_DOMAIN_SUPABASE_URL','DIRAC_DOMAIN_SUPABASE_ANON_KEY','DIRAC_DOMAIN_SUPABASE_SERVICE_ROLE_KEY']
});
function securityEnvTrueV334(name) { return /^(1|true|yes|on)$/i.test(String(process.env[name] || '').trim()); }
function securitySupabaseTargetV334(path) {
  if (path === '/rest/v1/rpc/dirac_central_atomic_consume_v230' || path === '/rest/v1/rpc/dirac_central_atomic_rate_limit_v230' || path.startsWith('/rest/v1/dirac_persistent_bans')) return 'security';
  if (path === '/rest/v1/rpc/dirac_passkey_record_assertion_v237') return 'legacy';
  if (path.startsWith('/rest/v1/domain_passkeys')) return securityEnvTrueV334('DIRAC_ENABLE_MULTI_DB_ROUTER') || securityEnvTrueV334('DIRAC_MULTI_DB_ROUTER_ENABLED') ? 'domain' : 'legacy';
  if (/^\/rest\/v1\/security_customer_(auth_links|password_hashes|sessions|settings)/.test(path)) return securityEnvTrueV334('DIRAC_ENABLE_MULTI_DB_ROUTER') || securityEnvTrueV334('DIRAC_MULTI_DB_ROUTER_ENABLED') ? 'customerSecurity' : 'legacy';
  if (path.startsWith('/auth/v1/')) return 'legacy';
  throw resetError('SECURITY_RESET_DB_PATH_NOT_ALLOWED', 403);
}
function securitySupabaseCredentialsV334(target) {
  const legacyNames = SECURITY_SUPABASE_TARGETS_V334.legacy;
  const names = SECURITY_SUPABASE_TARGETS_V334[target] || legacyNames;
  const get = (n) => String(process.env[n] || '').trim();
  let url = get(names[0]), anon = get(names[1]), service = get(names[2]);
  if (target === 'security' && (!url || !anon || !service)) throw resetError('SECURITY_RESET_SECURITY_DB_UNAVAILABLE', 503);
  if ((!url || !anon || !service) && target !== 'legacy') {
    if (securityEnvTrueV334('DIRAC_MULTI_DB_STRICT')) throw resetError('SECURITY_RESET_DB_TARGET_UNAVAILABLE', 503);
    url = get(legacyNames[0]); anon = get(legacyNames[1]); service = get(legacyNames[2]);
  }
  if (!url || !anon || !service) throw resetError('SECURITY_RESET_DB_ENV_MISSING', 503);
  let u; try { u = new URL(url); } catch (_) { throw resetError('SECURITY_RESET_DB_URL_INVALID', 503); }
  if (process.env.NODE_ENV === 'production' && u.protocol !== 'https:') throw resetError('SECURITY_RESET_DB_HTTPS_REQUIRED', 503);
  if (u.username || u.password || u.search || u.hash || (u.port && u.port !== '443')) throw resetError('SECURITY_RESET_DB_URL_INVALID', 503);
  return { url:u.origin, anon, service };
}
function securityResetDiagnosticDbRouteV335(cleanPath) {
  try {
    const u = new URL('https://diag.invalid' + String(cleanPath || ''));
    let pathname = u.pathname;
    pathname = pathname.replace(/^\/auth\/v1\/admin\/users\/[^/]+$/, '/auth/v1/admin/users/:id');
    return { pathname: pathname.slice(0, 240), query_keys: Array.from(new Set(Array.from(u.searchParams.keys()))).sort().slice(0, 40) };
  } catch (_) { return { pathname: 'invalid', query_keys: [] }; }
}
async function supabaseFetch(path, options = {}) {
  if (!SECURITY_NATIVE_FETCH_V334) throw resetError('SECURITY_RESET_NATIVE_FETCH_UNAVAILABLE', 503);
  const cleanPath = String(path || '');
  if ((!cleanPath.startsWith('/rest/v1/') && !cleanPath.startsWith('/auth/v1/')) || cleanPath.startsWith('//') || cleanPath.includes('\\') || /[\r\n\0]/.test(cleanPath)) throw resetError('SECURITY_RESET_DB_PATH_INVALID', 400);
  const method = String(options.method || 'GET').toUpperCase();
  if (!['GET','HEAD','POST','PATCH','PUT','DELETE'].includes(method)) throw resetError('SECURITY_RESET_DB_METHOD_INVALID', 405);
  const target = securitySupabaseTargetV334(cleanPath); const c = securitySupabaseCredentialsV334(target);
  const route = securityResetDiagnosticDbRouteV335(cleanPath); const callId = crypto.randomBytes(6).toString('hex');
  const headers = { Accept:'application/json', apikey: options.auth === 'service' ? c.service : c.anon };
  headers.Authorization = 'Bearer ' + (options.bearer ? String(options.bearer) : (options.auth === 'service' ? c.service : c.anon));
  if (options.prefer) headers.Prefer = String(options.prefer);
  let body;
  if (options.body !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(options.body); if (Buffer.byteLength(body) > 262144) throw resetError('SECURITY_RESET_DB_BODY_TOO_LARGE', 413); }
  diracResetDiagnosticV335(null, 'external.call', 'begin', { call_id: callId, method, target, auth_mode: options.bearer ? 'bearer' : String(options.auth || 'anon'), pathname: route.pathname, query_keys: route.query_keys, body_present: body !== undefined, body_bytes: body === undefined ? 0 : Buffer.byteLength(body), timeout_ms: 6500 });
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 6500); if (timer.unref) timer.unref();
  let response;
  try { response = await SECURITY_NATIVE_FETCH_V334(c.url + cleanPath, { method, headers, body, redirect:'error', signal:controller.signal }); }
  catch (cause) { const error = resetError('SECURITY_RESET_DB_NETWORK_FAILED', 503); diracResetDiagnosticV335(null, 'external.call', 'error', { call_id: callId, method, target, pathname: route.pathname, query_keys: route.query_keys, cause_name: String(cause && cause.name || ''), cause_code: String(cause && cause.code || '') }, error); throw error; }
  finally { clearTimeout(timer); }
  let data = null; const text = await response.text().catch(() => '');
  if (text) { try { data = JSON.parse(text); } catch (_) { data = text.slice(0,1024); } }
  diracResetDiagnosticV335(null, 'external.call', response.ok ? 'success' : 'error', { call_id: callId, method, target, pathname: route.pathname, query_keys: route.query_keys, http_status: Number(response.status || 0), response_ok: response.ok === true, response_bytes: Buffer.byteLength(text || ''), response_type: Array.isArray(data) ? 'array' : (data === null ? 'null' : typeof data), row_count: Array.isArray(data) ? data.length : -1 });
  return { ok:response.ok, status:response.status, data };
}
async function diracCentralAtomicConsumeV230({ namespace, jti, expiresAt, contextHash }) {
  const ns = String(namespace || '').trim().toLowerCase(), id = String(jti || '').trim();
  const now = Math.floor(Date.now()/1000), exp = Number(expiresAt || 0);
  if (!/^[a-z0-9_-]{3,60}$/.test(ns) || !/^[A-Za-z0-9_-]{16,256}$/.test(id) || !Number.isSafeInteger(exp) || exp <= now || exp > now + 900) return {ok:false};
  const securityKey = 's2s-central-atomic-v230:' + diracCentralHashV146([ns,id,String(contextHash||'')].join('|'));
  const r = await supabaseFetch('/rest/v1/rpc/dirac_central_atomic_consume_v230', {method:'POST',auth:'service',body:{p_security_key:securityKey,p_record_json:{type:'dirac_central_atomic_consume_v230',namespace:ns,nonce_hash:diracCentralHashV146(id),context_hash:diracCentralHashV146(String(contextHash||'')),consumed_at_ms:Date.now(),expires_at_s:exp},p_expires_at:new Date(exp*1000).toISOString()}}).catch(()=>null);
  return {ok:Boolean(r && r.ok === true && r.data === true)};
}
async function securityResetRateLimitV334(req, action) {
  const ip = securityResetHeaderV334(req,'x-vercel-forwarded-for').split(',')[0].trim() || String(req && req.socket && req.socket.remoteAddress || 'unknown');
  const key = 's2s-central-rate-v230:' + diracCentralHashV146(['keamanan-reset-v334',action,ip,requestUserAgent(req),requestOrigin(req)].join('|'));
  const r = await supabaseFetch('/rest/v1/rpc/dirac_central_atomic_rate_limit_v230',{method:'POST',auth:'service',body:{p_security_key:key,p_limit:12,p_window_seconds:60,p_block_seconds:60}}).catch(()=>null);
  const row = r && r.ok === true && Array.isArray(r.data) ? r.data[0] : null;
  if (!row || typeof row.allowed !== 'boolean') throw resetError('SECURITY_RESET_RATE_LIMIT_UNAVAILABLE',503);
  if (row.allowed !== true) throw resetError('SECURITY_RESET_RATE_LIMITED',429);
}
function normalizeSupabaseAdminUser(data) { return data && data.user && typeof data.user === 'object' ? data.user : (data && typeof data === 'object' ? data : null); }

function diracPasskeyA2FSafeString(value,maxLen){return String(value||'').trim().slice(0,Math.max(1,Number(maxLen||2048)));}
function diracPasskeyA2FBase64UrlToBuffer(value){const raw=String(value||'').trim();if(!raw)return Buffer.alloc(0);try{const b=Buffer.from(raw,'base64url');return b.toString('base64url')===raw?b:Buffer.alloc(0);}catch(_){return Buffer.alloc(0);}}
function diracPasskeyA2FCredentialId(credential){return diracPasskeyA2FSafeString(credential&&(credential.id||credential.rawId)||'',4096);}
function diracPasskeyA2FSignCount(response){const b=diracPasskeyA2FBase64UrlToBuffer(response&&response.authenticatorData);if(b.length>=37)try{return Math.max(0,b.readUInt32BE(33));}catch(_){return 0;}return 0;}
function diracPasskeyA2FSha256Buffer(value){return crypto.createHash('sha256').update(value).digest();}
function diracPasskeyA2FBufferEqual(a,b){const A=Buffer.isBuffer(a)?a:Buffer.from(a||''),B=Buffer.isBuffer(b)?b:Buffer.from(b||'');return A.length===B.length&&crypto.timingSafeEqual(A,B);}
function diracPasskeyA2FParseAuthData(authData,rpId){const b=Buffer.isBuffer(authData)?authData:Buffer.from(authData||[]);if(b.length<37)return{ok:false,reason:'authenticator_data_too_short'};if(!diracPasskeyA2FBufferEqual(b.subarray(0,32),diracPasskeyA2FSha256Buffer(String(rpId||''))))return{ok:false,reason:'rp_id_hash_mismatch'};const flags=b[32];if((flags&1)!==1)return{ok:false,reason:'user_presence_missing'};if((flags&4)!==4)return{ok:false,reason:'user_verification_missing'};const backupEligible=(flags&8)===8,backupState=(flags&16)===16;if(backupState&&!backupEligible)return{ok:false,reason:'passkey_backup_flags_invalid'};return{ok:true,flags,signCount:b.readUInt32BE(33),backupEligible,backupState,deviceBound:!backupEligible&&!backupState,authData:b};}
function diracPasskeyA2FDecodeClientData(value){const b=diracPasskeyA2FBase64UrlToBuffer(value);if(!b.length||b.length>8192)return null;try{return JSON.parse(b.toString('utf8'));}catch(_){return null;}}
function diracPasskeyA2FStoredPublicKey(row){const j=row&&row.credential_json&&row.credential_json.webauthn&&row.credential_json.webauthn.public_key_jwk;return j&&typeof j==='object'?j:null;}
function diracPasskeyA2FDeviceBindingKeyId(jwk){const x=diracPasskeyA2FSafeString(jwk&&jwk.x,64),y=diracPasskeyA2FSafeString(jwk&&jwk.y,64);if(!jwk||jwk.kty!=='EC'||jwk.crv!=='P-256'||!/^[A-Za-z0-9_-]{43}$/.test(x)||!/^[A-Za-z0-9_-]{43}$/.test(y))return'';const xb=diracPasskeyA2FBase64UrlToBuffer(x),yb=diracPasskeyA2FBase64UrlToBuffer(y);if(xb.length!==32||yb.length!==32)return'';return crypto.createHash('sha256').update('P-256\n'+x+'\n'+y).digest('hex');}
function diracPasskeyA2FStoredDeviceBinding(row){const j=row&&row.credential_json&&typeof row.credential_json==='object'?row.credential_json:{},b=j.device_binding&&typeof j.device_binding==='object'?j.device_binding:null;if(!b||b.required!==true||b.version!==DIRAC_PASSKEY_DEVICE_BINDING_VERSION||b.algorithm!==DIRAC_PASSKEY_DEVICE_BINDING_ALGORITHM||!/^[a-f0-9]{64}$/.test(String(b.key_id||'')))return{ok:false,reason:'stored_device_binding_missing'};const k=diracPasskeyA2FDeviceBindingKeyId(b.public_key_jwk);return k&&safeEqual(k,String(b.key_id))?{ok:true,keyId:k,publicKeyJwk:b.public_key_jwk,binding:b}:{ok:false,reason:'stored_device_binding_key_invalid'};}
function diracPasskeyA2FDeviceBindingSigningInput({setupToken,payload,credentialId,mode}){return['DIRAC_PASSKEY_DEVICE_BINDING_V1',String(mode||'').toLowerCase(),String(payload&&payload.challenge||''),String(credentialId||''),crypto.createHash('sha256').update(String(setupToken||'')).digest('base64url')].join('\n');}
function diracPasskeyA2FValidateAuthenticationDeviceBinding({row,body,setupToken,payload,credentialId}){const stored=diracPasskeyA2FStoredDeviceBinding(row);if(!stored.ok)return stored;const parts=diracPasskeyA2FSafeString(body&&body.response,1024).split('.');if(parts.length!==3||parts[0]!=='dpk1a'||!/^[a-f0-9]{64}$/.test(parts[1])||!/^[A-Za-z0-9_-]{86}$/.test(parts[2]))return{ok:false,reason:'device_binding_authentication_envelope_invalid'};if(!safeEqual(stored.keyId,parts[1]))return{ok:false,reason:'device_binding_key_mismatch'};const sig=diracPasskeyA2FBase64UrlToBuffer(parts[2]);if(sig.length!==64)return{ok:false,reason:'device_binding_signature_format_invalid'};try{const key=crypto.createPublicKey({key:stored.publicKeyJwk,format:'jwk'});const input=diracPasskeyA2FDeviceBindingSigningInput({setupToken,payload,credentialId,mode:'authentication'});const ok=crypto.verify('sha256',Buffer.from(input),{key,dsaEncoding:'ieee-p1363'},sig);return ok?{ok:true,keyId:stored.keyId,publicKeyJwk:stored.publicKeyJwk,binding:stored.binding}:{ok:false,reason:'device_binding_authentication_signature_invalid'};}catch(_){return{ok:false,reason:'device_binding_authentication_signature_invalid'};}}
function diracPasskeyA2FValidateAuthenticationResponse({row,response,payload,clientData,req}){const authData=diracPasskeyA2FBase64UrlToBuffer(response&&response.authenticatorData),sig=diracPasskeyA2FBase64UrlToBuffer(response&&response.signature),clientRaw=diracPasskeyA2FBase64UrlToBuffer(response&&response.clientDataJSON);if(!authData.length||!sig.length||!clientRaw.length)return{ok:false,reason:'assertion_response_incomplete'};let parsed;try{parsed=diracPasskeyA2FParseAuthData(authData,String(payload&&payload.rpId||diracPasskeyA2FRpId(req)));}catch(_){return{ok:false,reason:'authenticator_data_invalid'};}if(!parsed.ok)return parsed;if(String(clientData&&clientData.type||'')!=='webauthn.get')return{ok:false,reason:'client_data_type_invalid'};const sw=row&&row.credential_json&&row.credential_json.webauthn&&typeof row.credential_json.webauthn==='object'?row.credential_json.webauthn:{};if(typeof sw.backup_eligible!=='boolean')return{ok:false,reason:'stored_passkey_backup_policy_missing'};if(sw.backup_eligible!==parsed.backupEligible)return{ok:false,reason:'passkey_backup_eligibility_changed'};const jwk=diracPasskeyA2FStoredPublicKey(row);if(!jwk)return{ok:false,reason:'stored_public_key_missing'};try{const key=crypto.createPublicKey({key:jwk,format:'jwk'}),signed=Buffer.concat([authData,diracPasskeyA2FSha256Buffer(clientRaw)]);if(!crypto.verify('sha256',signed,key,sig))return{ok:false,reason:'passkey_signature_invalid'};}catch(_){return{ok:false,reason:'passkey_signature_invalid'};}const prev=Math.max(0,Number(row&&row.sign_count||0));if(prev>0&&parsed.signCount>0&&parsed.signCount<=prev)return{...parsed,ok:false,reason:'passkey_sign_count_replay',previousSignCount:prev,newSignCount:parsed.signCount};return{ok:true,...parsed};}
async function diracPasskeyA2FReadSecurityEpoch(owner){const cid=String(owner&&owner.customerId||'');if(!customerSecurityLooksLikeUuid(cid))throw resetError('PASSKEY_SECURITY_OWNER_INVALID',503);const r=await supabaseFetch('/rest/v1/security_customer_settings?select='+encodeURIComponent('id,customer_id,security_epoch')+'&customer_id=eq.'+encodeURIComponent(cid)+'&order=created_at.desc&limit=2',{method:'GET',auth:'service'});if(!r.ok||!Array.isArray(r.data)||r.data.length!==1)throw resetError('PASSKEY_SECURITY_EPOCH_READ_FAILED',503);const e=Number(r.data[0]&&r.data[0].security_epoch||0);if(!Number.isSafeInteger(e)||e<1)throw resetError('PASSKEY_SECURITY_EPOCH_INVALID',503);return e;}

function diracPasswordArgon2V4Number(names,fallback,min,max){for(const name of names){const v=Number(String(process.env[name]||'').trim());if(Number.isFinite(v)&&String(process.env[name]||'').trim())return Math.min(Math.max(Math.floor(v),min),max);}return fallback;}
function diracPasswordArgon2V4Params(){return{memoryCost:diracPasswordArgon2V4Number(['DIRAC_PASSWORD_ARGON2_MEMORY_KIB','DIRAC_ARGON2ID_MEMORY_KIB'],65536,19456,262144),timeCost:diracPasswordArgon2V4Number(['DIRAC_PASSWORD_ARGON2_TIME_COST','DIRAC_ARGON2ID_TIME_COST'],3,3,6),parallelism:diracPasswordArgon2V4Number(['DIRAC_PASSWORD_ARGON2_PARALLELISM','DIRAC_ARGON2ID_PARALLELISM'],1,1,4),hashLength:diracPasswordArgon2V4Number(['DIRAC_PASSWORD_ARGON2_HASH_LENGTH'],32,32,64)};}
function diracPasswordArgon2V4Pepper(){return diracCentralDeriveSecretV146('password-argon2-v4-pepper').toString('base64url');}
function diracPasswordArgon2V4Hmac(value){return crypto.createHmac('sha256',diracPasswordArgon2V4Pepper()).update(String(value||'')).digest('hex');}
async function diracPasswordArgon2V4Hash(password,meta={}){let argon2;try{argon2=require('argon2');}catch(_){throw resetError('ARGON2ID_DEPENDENCY_MISSING',500);}const p=diracPasswordArgon2V4Params(),salt=crypto.randomBytes(64);try{return await argon2.hash(['dirac-customer-password-v4-argon2id',String(meta.authUserId||''),String(meta.customerId||''),normalizeAuthEmail(meta.email||''),String(password||''),diracPasswordArgon2V4Pepper()].join(':'),{type:argon2.argon2id,memoryCost:p.memoryCost,timeCost:p.timeCost,parallelism:p.parallelism,hashLength:p.hashLength,salt});}finally{salt.fill(0);}}
function diracPasswordArgon2ActiveOnlyV120SafeRowId(v){const t=String(v||'').trim();return t&&t.length<=96&&/^[a-zA-Z0-9_-]+$/.test(t)?t:'';}
function diracPasswordArgon2ActiveOnlyV120UpdateBody(row){return{auth_user_id:row.auth_user_id,customer_id:row.customer_id,email_hash:row.email_hash,password_hash:row.password_hash,hash_algorithm:'argon2id',hash_params:row.hash_params,status:'active',updated_at:row.updated_at||new Date().toISOString()};}
async function diracPasswordArgon2ActiveOnlyV120UpsertCurrent(authUserId,row,nowIso){const base='/rest/v1/security_customer_password_hashes';let r=await supabaseFetch(base+'?select='+encodeURIComponent('id,customer_id,status,updated_at')+'&auth_user_id=eq.'+encodeURIComponent(authUserId)+'&status=eq.active&order=updated_at.desc&limit=25',{method:'GET',auth:'service'});if(!r.ok||!Array.isArray(r.data))return{ok:false};const keep=r.data[0],id=diracPasswordArgon2ActiveOnlyV120SafeRowId(keep&&keep.id),body=diracPasswordArgon2ActiveOnlyV120UpdateBody(row);if(id){r=await supabaseFetch(base+'?id=eq.'+encodeURIComponent(id)+'&auth_user_id=eq.'+encodeURIComponent(authUserId),{method:'PATCH',auth:'service',prefer:'return=minimal',body});if(r.ok){await supabaseFetch(base+'?auth_user_id=eq.'+encodeURIComponent(authUserId)+'&id=neq.'+encodeURIComponent(id),{method:'DELETE',auth:'service',prefer:'return=minimal'}).catch(()=>null);return{ok:true};}}await supabaseFetch(base+'?auth_user_id=eq.'+encodeURIComponent(authUserId),{method:'DELETE',auth:'service',prefer:'return=minimal'}).catch(()=>null);r=await supabaseFetch(base,{method:'POST',auth:'service',prefer:'return=representation',body:[{...row,created_at:nowIso||new Date().toISOString(),status:'active'}]});return{ok:Boolean(r&&r.ok)};}

async function securityResetAccountAllowedV334(authUserId,email,customerId){const p=await supabaseFetch('/auth/v1/admin/users/'+encodeURIComponent(authUserId),{method:'GET',auth:'service'});const u=p&&p.ok?normalizeSupabaseAdminUser(p.data):null;if(!u||!safeEqual(String(u.id||''),authUserId)||!safeEqual(normalizeAuthEmail(u.email||''),email))throw resetError('PASSWORD_RESET_PROVIDER_OWNER_CHECK_FAILED',503);const banned=String(u.banned_until||'').trim(),bannedMs=banned?Date.parse(banned):0;if(u.deleted_at||u.disabled_at||u.disabled===true||u.is_disabled===true||u.is_anonymous===true||(Number.isFinite(bannedMs)&&bannedMs>Date.now()))throw resetError('PASSWORD_RESET_ACCOUNT_BLOCKED',403);const s=await supabaseFetch('/rest/v1/security_customer_settings?select='+encodeURIComponent('customer_id,account_locked,locked_until,security_epoch')+'&customer_id=eq.'+encodeURIComponent(customerId)+'&order=updated_at.desc&limit=2',{method:'GET',auth:'service'});if(!s.ok||!Array.isArray(s.data)||s.data.length!==1)throw resetError('PASSWORD_RESET_ACCOUNT_SETTINGS_INVALID',503);const sr=s.data[0];if(!safeEqual(String(sr.customer_id||''),customerId)||typeof sr.account_locked!=='boolean')throw resetError('PASSWORD_RESET_ACCOUNT_SETTINGS_INVALID',503);if(sr.account_locked===true){const until=String(sr.locked_until||'').trim(),ms=until?Date.parse(until):0;if(!until||(Number.isFinite(ms)&&ms>Date.now()))throw resetError('PASSWORD_RESET_ACCOUNT_BLOCKED',403);}const digestKey=diracCentralDeriveSecretV146('customer-access-block-v325-key');let digest;try{digest=crypto.createHmac('sha256',digestKey).update(['v325','account',customerId.toLowerCase()].join('\0')).digest('hex');}finally{digestKey.fill(0);}const prefix='customer-access-block-v325:account:'+digest+':';const br=await supabaseFetch('/rest/v1/'+DIRAC_PERSISTENT_BAN_TABLE+'?select='+encodeURIComponent('security_key,record_json,blocked_until_ms,expires_at')+'&security_key=like.'+encodeURIComponent(prefix+'*')+'&blocked_until_ms=gt.'+encodeURIComponent(String(Date.now()))+'&order='+encodeURIComponent('blocked_until_ms.desc,security_key.asc')+'&limit=41',{method:'GET',auth:'service'});if(!br.ok||!Array.isArray(br.data)||br.data.length>40)throw resetError('PASSWORD_RESET_BAN_STORE_UNAVAILABLE',503);if(br.data.length)throw resetError('PASSWORD_RESET_ACCOUNT_BLOCKED',403);return true;}


const DIRAC_PASSWORD_RESET_V333 = Object.freeze({
  version: 'dirac-password-reset-passkey-v333',
  protocol: 'dirac-lost-password-10-layer-v1',
  suite: 'X25519+HKDF-SHA512+4xAES-256-GCM+4xAES-256-KW',
  profile: 'dirac-lost-password-key-profile-v1',
  profilePinSha512B64u: 'y1etldCKpbWMPOa-aNEfOiQd60Y_M6R3Sc1xY9sB8rX-GtJPaIG13P5OzxgcRuYOIT98Rcuum4syOhT_Okdmlw',
  profileTtlMs: 300000,
  flowTtlSeconds: 180
});

function diracPasswordResetCanonicalV333(value) {
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) return '[' + value.map(diracPasswordResetCanonicalV333).join(',') + ']';
  if (typeof value === 'object') return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + diracPasswordResetCanonicalV333(value[key])).join(',') + '}';
  return JSON.stringify(value);
}

function diracPasswordResetErrorV333(code, statusCode, message) {
  const error = new Error(String(message || code || 'PASSWORD_RESET_FAILED'));
  error.code = String(code || 'PASSWORD_RESET_FAILED');
  error.statusCode = Math.max(400, Math.min(599, Number(statusCode || 503) || 503));
  return error;
}

function diracPasswordResetSigningKeyV333(req) {
  const raw = String(process.env.DIRAC_RECOVERY_FILE_SIGNING_PRIVATE_KEY || '').trim();
  const representation = raw.includes('-----BEGIN') ? 'pem' : (raw ? 'base64-or-der' : 'missing');
  diracResetDiagnosticV335(req, 'profile.signing_key.load', 'begin', { env_name: 'DIRAC_RECOVERY_FILE_SIGNING_PRIVATE_KEY', env_present: Boolean(raw), raw_length: raw.length, representation, expected_fingerprint: DIRAC_PASSWORD_RESET_V333.profilePinSha512B64u });
  if (!raw) { const error = diracPasswordResetErrorV333('DIRAC_D10_PROFILE_SIGNING_KEY_UNAVAILABLE', 503); diracResetDiagnosticV335(req, 'profile.signing_key.load', 'error', { env_present: false }, error); throw error; }
  let privateKey;
  let decodedLength = 0;
  let parsePath = '';
  try {
    if (raw.includes('-----BEGIN')) { parsePath = 'pem-direct'; privateKey = crypto.createPrivateKey(raw.replace(/\\n/g, '\n')); }
    else {
      const decoded = Buffer.from(raw, 'base64'); decodedLength = decoded.length;
      try { parsePath = 'pkcs8-der-base64'; privateKey = crypto.createPrivateKey({ key: decoded, format: 'der', type: 'pkcs8' }); }
      catch (_) { parsePath = 'pem-base64'; privateKey = crypto.createPrivateKey(decoded.toString('utf8').replace(/\\n/g, '\n')); }
    }
  } catch (cause) { const error = diracPasswordResetErrorV333('DIRAC_D10_PROFILE_SIGNING_KEY_INVALID', 503); diracResetDiagnosticV335(req, 'profile.signing_key.parse', 'error', { representation, raw_length: raw.length, decoded_length: decodedLength, parse_path: parsePath, cause_name: String(cause && cause.name || ''), cause_code: String(cause && cause.code || '') }, error); throw error; }
  const keyType = String(privateKey && privateKey.asymmetricKeyType || '');
  diracResetDiagnosticV335(req, 'profile.signing_key.parse', 'success', { representation, raw_length: raw.length, decoded_length: decodedLength, parse_path: parsePath, asymmetric_key_type: keyType });
  if (!privateKey || privateKey.asymmetricKeyType !== 'ed25519') { const error = diracPasswordResetErrorV333('DIRAC_D10_PROFILE_SIGNING_KEY_TYPE_INVALID', 503); diracResetDiagnosticV335(req, 'profile.signing_key.type', 'error', { asymmetric_key_type: keyType }, error); throw error; }
  const publicKey = crypto.createPublicKey(privateKey);
  const publicDer = Buffer.from(publicKey.export({ format: 'der', type: 'spki' }));
  const fingerprint = crypto.createHash('sha512').update(publicDer).digest('base64url');
  const pinMatch = safeEqual(fingerprint, DIRAC_PASSWORD_RESET_V333.profilePinSha512B64u);
  diracResetDiagnosticV335(req, 'profile.signing_key.pin', pinMatch ? 'success' : 'error', { asymmetric_key_type: keyType, public_der_length: publicDer.length, derived_fingerprint: fingerprint, expected_fingerprint: DIRAC_PASSWORD_RESET_V333.profilePinSha512B64u, pin_match: pinMatch });
  if (!pinMatch) throw diracPasswordResetErrorV333('DIRAC_D10_PROFILE_SIGNING_KEY_PIN_MISMATCH', 503);
  return { privateKey, publicDer, fingerprint };
}

function diracPasswordResetSealX25519PrivateV333(rawPrivate) {
  const privateBytes = Buffer.from(rawPrivate || Buffer.alloc(0));
  if (privateBytes.length !== 32) throw diracPasswordResetErrorV333('DIRAC_D10_X25519_PRIVATE_INVALID', 503);
  const minute = Math.floor(Date.now() / 60000) & 0xffff;
  const minuteBytes = Buffer.alloc(2);
  minuteBytes.writeUInt16BE(minute, 0);
  const nonce = crypto.randomBytes(10);
  const key = Buffer.from(diracCentralDeriveSecretV146('password-reset-d10-x25519-v333')).subarray(0, 32);
  const aad = Buffer.from(DIRAC_PASSWORD_RESET_V333.protocol + '\n' + DIRAC_PASSWORD_RESET_V333.suite + '\n' + String(minute), 'utf8');
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(privateBytes), cipher.final()]);
    const tag = cipher.getAuthTag();
    const packed = Buffer.concat([minuteBytes, nonce, ciphertext, tag]);
    if (packed.length !== 60) throw diracPasswordResetErrorV333('DIRAC_D10_KEY_ID_LENGTH_INVALID', 503);
    return packed.toString('base64url');
  } finally {
    privateBytes.fill(0); key.fill(0); aad.fill(0);
  }
}

function diracPasswordResetUnsealX25519PrivateV333(keyId) {
  let packed;
  try { packed = Buffer.from(String(keyId || ''), 'base64url'); } catch (_) { packed = Buffer.alloc(0); }
  if (packed.length !== 60 || packed.toString('base64url') !== String(keyId || '')) throw diracPasswordResetErrorV333('DIRAC_D10_KEY_ID_INVALID', 403);
  const minute = packed.readUInt16BE(0);
  const current = Math.floor(Date.now() / 60000) & 0xffff;
  const forward = (current - minute + 65536) & 0xffff;
  if (forward > 10) throw diracPasswordResetErrorV333('DIRAC_D10_PROFILE_KEY_EXPIRED', 403);
  const nonce = packed.subarray(2, 12);
  const ciphertext = packed.subarray(12, 44);
  const tag = packed.subarray(44, 60);
  const key = Buffer.from(diracCentralDeriveSecretV146('password-reset-d10-x25519-v333')).subarray(0, 32);
  const aad = Buffer.from(DIRAC_PASSWORD_RESET_V333.protocol + '\n' + DIRAC_PASSWORD_RESET_V333.suite + '\n' + String(minute), 'utf8');
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const raw = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (raw.length !== 32) throw diracPasswordResetErrorV333('DIRAC_D10_X25519_PRIVATE_INVALID', 403);
    return Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), raw]);
  } catch (error) {
    if (error && error.code) throw error;
    throw diracPasswordResetErrorV333('DIRAC_D10_KEY_ID_AUTHENTICATION_FAILED', 403);
  } finally {
    key.fill(0); aad.fill(0); packed.fill(0);
  }
}

function diracPasswordResetIssueProfileV333(req) {
  diracResetDiagnosticV335(req, 'profile.crypto', 'begin', { x25519_supported: typeof crypto.generateKeyPairSync === 'function' });
  const signing = diracPasswordResetSigningKeyV333(req);
  let pair;
  try { pair = crypto.generateKeyPairSync('x25519'); }
  catch (cause) { const error = diracPasswordResetErrorV333('DIRAC_D10_X25519_UNAVAILABLE', 503); diracResetDiagnosticV335(req, 'profile.x25519.generate', 'error', { cause_name: String(cause && cause.name || ''), cause_code: String(cause && cause.code || '') }, error); throw error; }
  diracResetDiagnosticV335(req, 'profile.x25519.generate', 'success', { private_key_type: String(pair && pair.privateKey && pair.privateKey.asymmetricKeyType || ''), public_key_type: String(pair && pair.publicKey && pair.publicKey.asymmetricKeyType || '') });
  let privateJwk;
  try { privateJwk = pair.privateKey.export({ format: 'jwk' }); }
  catch (cause) { const error = diracPasswordResetErrorV333('DIRAC_D10_X25519_EXPORT_FAILED', 503); diracResetDiagnosticV335(req, 'profile.x25519.export', 'error', { cause_name: String(cause && cause.name || ''), cause_code: String(cause && cause.code || '') }, error); throw error; }
  let rawPrivate;
  try { rawPrivate = Buffer.from(String(privateJwk && privateJwk.d || ''), 'base64url'); } catch (_) { rawPrivate = Buffer.alloc(0); }
  if (rawPrivate.length !== 32) { const error = diracPasswordResetErrorV333('DIRAC_D10_X25519_PRIVATE_INVALID', 503); diracResetDiagnosticV335(req, 'profile.x25519.export', 'error', { raw_private_length: rawPrivate.length }, error); throw error; }
  diracResetDiagnosticV335(req, 'profile.x25519.export', 'success', { raw_private_length: rawPrivate.length });
  const keyId = diracPasswordResetSealX25519PrivateV333(rawPrivate);
  diracResetDiagnosticV335(req, 'profile.x25519.seal', 'success', { key_id_length: String(keyId || '').length });
  rawPrivate.fill(0);
  const issuedAt = Date.now();
  const unsigned = {
    v: DIRAC_PASSWORD_RESET_V333.profile,
    protocol: DIRAC_PASSWORD_RESET_V333.protocol,
    suite: DIRAC_PASSWORD_RESET_V333.suite,
    key_id: keyId,
    issued_at_ms: issuedAt,
    expires_at_ms: issuedAt + DIRAC_PASSWORD_RESET_V333.profileTtlMs,
    x25519_public_key_b64url: Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' })).toString('base64url'),
    profile_signing_public_key_b64url: signing.publicDer.toString('base64url'),
    profile_signing_fingerprint_sha512_b64url: signing.fingerprint
  };
  let signature;
  try { signature = crypto.sign(null, Buffer.from(diracPasswordResetCanonicalV333(unsigned), 'utf8'), signing.privateKey).toString('base64url'); }
  catch (cause) { const error = diracPasswordResetErrorV333('DIRAC_D10_PROFILE_SIGNATURE_INVALID', 503); diracResetDiagnosticV335(req, 'profile.sign', 'error', { cause_name: String(cause && cause.name || ''), cause_code: String(cause && cause.code || '') }, error); throw error; }
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) { const error = diracPasswordResetErrorV333('DIRAC_D10_PROFILE_SIGNATURE_INVALID', 503); diracResetDiagnosticV335(req, 'profile.sign', 'error', { signature_length: String(signature || '').length }, error); throw error; }
  diracResetDiagnosticV335(req, 'profile.sign', 'success', { algorithm: 'Ed25519', signature_length: signature.length, fingerprint: signing.fingerprint });
  return { ...unsigned, signature_algorithm: 'Ed25519', signature_b64url: signature };
}

function diracPasswordResetBindingHashV333(scope, value) {
  const key = Buffer.from(diracCentralDeriveSecretV146('password-reset-binding-v333:' + String(scope || 'default')));
  try { return crypto.createHmac('sha256', key).update(String(value || ''), 'utf8').digest('hex'); }
  finally { key.fill(0); }
}

function diracPasswordResetRequestBindingV333(req) {
  const origin = normalizeDashboardMfaOrigin(requestOrigin(req) || '');
  const ua = String(requestUserAgent(req) || '').slice(0, 1000);
  const acceptLanguage = String(req && req.headers && req.headers['accept-language'] || '').slice(0, 200);
  const secChUa = String(req && req.headers && req.headers['sec-ch-ua'] || '').slice(0, 300);
  return diracPasswordResetBindingHashV333('request', [origin, ua, acceptLanguage, secChUa].join('\n'));
}

function diracPasswordResetChallengeTokenKeyV333() {
  const key = Buffer.from(diracCentralDeriveSecretV146('password-reset-challenge-token-v333'));
  if (key.length < 32) throw diracPasswordResetErrorV333('PASSWORD_RESET_CHALLENGE_KEY_INVALID', 503);
  return key;
}

function diracPasswordResetChallengeTagV333(prefix, email, context) {
  const key = diracPasswordResetChallengeTokenKeyV333();
  const source = context && typeof context === 'object' ? context : {};
  const material = Buffer.from([
    DIRAC_PASSWORD_RESET_V333.version,
    normalizeAuthEmail(email || ''),
    String(source.browserHash || ''),
    String(source.requestBinding || ''),
    String(source.keyId || ''),
    String(source.rpId || '')
  ].join('\n'), 'utf8');
  try {
    return crypto.createHmac('sha256', key).update(Buffer.from(prefix)).update(material).digest();
  } finally { key.fill(0); material.fill(0); }
}

function diracPasswordResetChallengeBytesV333(challengeId) {
  const key = Buffer.from(diracCentralDeriveSecretV146('password-reset-webauthn-challenge-v333'));
  try { return crypto.createHmac('sha256', key).update(String(challengeId || ''), 'utf8').digest(); }
  finally { key.fill(0); }
}

function diracPasswordResetIssueChallengeV333(input) {
  const source = input && typeof input === 'object' ? input : {};
  const email = normalizeAuthEmail(source.email || '');
  if (!isValidAuthEmail(email) || email.length > 120) throw diracPasswordResetErrorV333('PASSWORD_RESET_EMAIL_INVALID', 400);
  const issuedAtS = Math.floor(Date.now() / 1000);
  const prefix = Buffer.alloc(21);
  prefix[0] = 1;
  prefix.writeUInt32BE(issuedAtS >>> 0, 1);
  crypto.randomBytes(16).copy(prefix, 5);
  const tag = diracPasswordResetChallengeTagV333(prefix, email, source);
  const raw = Buffer.concat([prefix, tag]);
  try {
    if (raw.length !== 53) throw diracPasswordResetErrorV333('PASSWORD_RESET_CHALLENGE_TOKEN_LENGTH_INVALID', 503);
    const challengeId = raw.toString('base64url');
    const challengeBytes = diracPasswordResetChallengeBytesV333(challengeId);
    try {
      return Object.freeze({
        challenge_id: challengeId,
        challenge: challengeBytes.toString('base64url'),
        expires_at_ms: (issuedAtS + DIRAC_PASSWORD_RESET_V333.flowTtlSeconds) * 1000
      });
    } finally { challengeBytes.fill(0); }
  } finally { prefix.fill(0); tag.fill(0); raw.fill(0); }
}

function diracPasswordResetReadChallengeV333(challengeId, context) {
  const clean = String(challengeId || '').trim();
  let raw;
  try { raw = Buffer.from(clean, 'base64url'); } catch (_) { raw = Buffer.alloc(0); }
  if (raw.length !== 53 || raw.toString('base64url') !== clean || raw[0] !== 1) {
    if (raw.length) raw.fill(0);
    throw diracPasswordResetErrorV333('PASSWORD_RESET_CHALLENGE_TOKEN_INVALID', 403);
  }
  const issuedAtS = raw.readUInt32BE(1);
  const nowS = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(issuedAtS) || issuedAtS > nowS + 30 || nowS - issuedAtS > DIRAC_PASSWORD_RESET_V333.flowTtlSeconds) {
    raw.fill(0);
    throw diracPasswordResetErrorV333('PASSWORD_RESET_CHALLENGE_TOKEN_EXPIRED', 409);
  }
  const prefix = Buffer.from(raw.subarray(0, 21));
  const tag = Buffer.from(raw.subarray(21, 53));
  const challengeBytes = diracPasswordResetChallengeBytesV333(clean);
  raw.fill(0);
  const source = context && typeof context === 'object' ? context : {};
  const consumeBinding = diracPasswordResetBindingHashV333('consume', [
    'challenge', clean, String(source.browserHash || ''), String(source.requestBinding || ''), String(source.keyId || ''), String(source.rpId || '')
  ].join('\n'));
  return Object.freeze({
    v: 'password-reset-stateless-challenge-v333',
    kind: 'challenge',
    challenge_id: clean,
    challenge: challengeBytes.toString('base64url'),
    rp_id: String(source.rpId || ''),
    expires_at_ms: (issuedAtS + DIRAC_PASSWORD_RESET_V333.flowTtlSeconds) * 1000,
    consume_binding: consumeBinding,
    token_prefix_b64url: prefix.toString('base64url'),
    token_tag_b64url: tag.toString('base64url'),
    browser_hash: String(source.browserHash || ''),
    request_binding: String(source.requestBinding || ''),
    key_id: String(source.keyId || '')
  });
}

function diracPasswordResetChallengeOwnerValidV333(state, email) {
  if (!state || state.kind !== 'challenge') return false;
  let prefix; let tag; let expected;
  try {
    prefix = Buffer.from(String(state.token_prefix_b64url || ''), 'base64url');
    tag = Buffer.from(String(state.token_tag_b64url || ''), 'base64url');
    if (prefix.length !== 21 || tag.length !== 32) return false;
    expected = diracPasswordResetChallengeTagV333(prefix, normalizeAuthEmail(email || ''), {
      browserHash: state.browser_hash,
      requestBinding: state.request_binding,
      keyId: state.key_id,
      rpId: state.rp_id
    });
    return expected.length === tag.length && crypto.timingSafeEqual(expected, tag);
  } catch (_) { return false; }
  finally {
    if (prefix) prefix.fill(0); if (tag) tag.fill(0); if (expected) expected.fill(0);
  }
}

function diracPasswordResetUuidToBytesV333(value, code) {
  const clean = String(value || '').trim().toLowerCase();
  if (!customerSecurityLooksLikeUuid(clean)) throw diracPasswordResetErrorV333(code || 'PASSWORD_RESET_UUID_INVALID', 503);
  return Buffer.from(clean.replace(/-/g, ''), 'hex');
}

function diracPasswordResetBytesToUuidV333(bytes) {
  const hex = Buffer.from(bytes).toString('hex');
  if (hex.length !== 32) throw diracPasswordResetErrorV333('PASSWORD_RESET_UUID_DECODE_INVALID', 403);
  const value = [hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join('-');
  if (!customerSecurityLooksLikeUuid(value)) throw diracPasswordResetErrorV333('PASSWORD_RESET_UUID_DECODE_INVALID', 403);
  return value;
}

function diracPasswordResetGrantAadV333(context) {
  const source = context && typeof context === 'object' ? context : {};
  return Buffer.from([
    DIRAC_PASSWORD_RESET_V333.version,
    String(source.browserHash || ''),
    String(source.requestBinding || ''),
    String(source.keyId || '')
  ].join('\n'), 'utf8');
}

function diracPasswordResetIssueGrantV333(verified, context) {
  const source = verified && typeof verified === 'object' ? verified : {};
  const customer = diracPasswordResetUuidToBytesV333(source.customer_id, 'PASSWORD_RESET_GRANT_CUSTOMER_INVALID');
  const authUser = diracPasswordResetUuidToBytesV333(source.auth_user_id, 'PASSWORD_RESET_GRANT_AUTH_USER_INVALID');
  const passkey = diracPasswordResetUuidToBytesV333(source.passkey_id, 'PASSWORD_RESET_GRANT_PASSKEY_ID_INVALID');
  const emailHashHex = String(source.email_hash || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(emailHashHex)) throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_EMAIL_BINDING_INVALID', 503);
  const emailHash = Buffer.from(emailHashHex, 'hex');
  const securityEpoch = Number(source.security_epoch || 0);
  if (!Number.isSafeInteger(securityEpoch) || securityEpoch < 1 || securityEpoch > 0xffffffff) throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_SECURITY_EPOCH_INVALID', 503);
  const issuedAtS = Math.floor(Date.now() / 1000);
  const plaintext = Buffer.alloc(88);
  plaintext.writeUInt32BE(issuedAtS >>> 0, 0);
  customer.copy(plaintext, 4); authUser.copy(plaintext, 20); passkey.copy(plaintext, 36);
  plaintext.writeUInt32BE(securityEpoch >>> 0, 52);
  emailHash.copy(plaintext, 56);
  const nonce = crypto.randomBytes(12);
  const key = Buffer.from(diracCentralDeriveSecretV146('password-reset-grant-token-v333')).subarray(0, 32);
  const aad = diracPasswordResetGrantAadV333(context);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const raw = Buffer.concat([Buffer.from([1]), nonce, ciphertext, tag]);
    try {
      if (raw.length !== 117) throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_TOKEN_LENGTH_INVALID', 503);
      return raw.toString('base64url');
    } finally { ciphertext.fill(0); tag.fill(0); raw.fill(0); }
  } finally {
    customer.fill(0); authUser.fill(0); passkey.fill(0); emailHash.fill(0); plaintext.fill(0); nonce.fill(0); key.fill(0); aad.fill(0);
  }
}

function diracPasswordResetReadGrantV333(grantToken, context) {
  const clean = String(grantToken || '').trim();
  let raw;
  try { raw = Buffer.from(clean, 'base64url'); } catch (_) { raw = Buffer.alloc(0); }
  if (raw.length !== 117 || raw.toString('base64url') !== clean || raw[0] !== 1) {
    if (raw.length) raw.fill(0);
    throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_TOKEN_INVALID', 403);
  }
  const nonce = Buffer.from(raw.subarray(1, 13));
  const ciphertext = Buffer.from(raw.subarray(13, 101));
  const tag = Buffer.from(raw.subarray(101, 117));
  const key = Buffer.from(diracCentralDeriveSecretV146('password-reset-grant-token-v333')).subarray(0, 32);
  const aad = diracPasswordResetGrantAadV333(context);
  let plaintext;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad); decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.length !== 88) throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_TOKEN_PAYLOAD_INVALID', 403);
    const issuedAtS = plaintext.readUInt32BE(0);
    const nowS = Math.floor(Date.now() / 1000);
    if (issuedAtS > nowS + 30 || nowS - issuedAtS > 120) throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_TOKEN_EXPIRED', 409);
    const customerId = diracPasswordResetBytesToUuidV333(plaintext.subarray(4,20));
    const authUserId = diracPasswordResetBytesToUuidV333(plaintext.subarray(20,36));
    const passkeyId = diracPasswordResetBytesToUuidV333(plaintext.subarray(36,52));
    const securityEpoch = plaintext.readUInt32BE(52);
    const emailHash = plaintext.subarray(56,88).toString('hex');
    if (!Number.isSafeInteger(securityEpoch) || securityEpoch < 1 || !/^[a-f0-9]{64}$/.test(emailHash)) throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_TOKEN_PAYLOAD_INVALID', 403);
    const ctx = diracCentralCurrentContextV149();
    if (ctx) ctx.__diracPasswordResetGrantOwnerV333 = Object.freeze({ customerId, authUserId, passkeyId });
    const consumeBinding = diracPasswordResetBindingHashV333('consume', [
      'grant', clean, customerId, authUserId, passkeyId, String(securityEpoch), String(context && context.browserHash || ''), String(context && context.requestBinding || ''), String(context && context.keyId || '')
    ].join('\n'));
    return Object.freeze({
      v: 'password-reset-stateless-grant-v333', kind: 'grant', auth_user_id: authUserId,
      customer_id: customerId, email_hash: emailHash, passkey_id: passkeyId,
      security_epoch: securityEpoch, expires_at_ms: (issuedAtS + 120) * 1000, consume_binding: consumeBinding
    });
  } catch (error) {
    if (error && error.code) throw error;
    throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_TOKEN_AUTHENTICATION_FAILED', 403);
  } finally {
    raw.fill(0); nonce.fill(0); ciphertext.fill(0); tag.fill(0); key.fill(0); aad.fill(0); if (plaintext) plaintext.fill(0);
  }
}

async function diracPasswordResetConsumeStateV333(kind, id, expiresAtMs, binding) {
  const exp = Math.floor(Number(expiresAtMs || 0) / 1000);
  const result = await diracCentralAtomicConsumeV230({
    namespace: kind === 'challenge' ? 'pwd_reset_challenge' : 'pwd_reset_grant',
    jti: String(id || ''),
    expiresAt: exp,
    contextHash: String(binding || '')
  });
  if (!result || result.ok !== true) throw diracPasswordResetErrorV333('PASSWORD_RESET_STATE_REPLAY_OR_UNAVAILABLE', 409);
  return true;
}

function diracPasswordResetCredentialRowSelectV333() {
  return [
    'id','user_id','email','credential_id','credential_json','transports','sign_count','backup_eligible','backup_state','public_key_sha256',
    'rotation_id','rotation_state','rotation_purpose','credential_epoch','expected_security_epoch','authorizing_credential_id_hash',
    'current_auth_session_id','recovery_request_id','recovery_session_id','recovery_session_hash','is_active','pending_expires_at',
    'confirmed_at','activated_at','revoked_at','revoke_reason','created_at','updated_at','last_used_at'
  ].join(',');
}

async function diracPasswordResetFetchCredentialByIdV333(credentialId, customerId) {
  const id = diracPasskeyA2FSafeString(credentialId, 4096);
  if (!id) throw diracPasswordResetErrorV333('PASSWORD_RESET_CREDENTIAL_ID_INVALID', 400);
  let path = '/rest/v1/domain_passkeys?select=' + encodeURIComponent(diracPasswordResetCredentialRowSelectV333())
    + '&credential_id=eq.' + encodeURIComponent(id)
    + '&is_active=eq.true&rotation_state=eq.active';
  if (customerId) path += '&user_id=eq.' + encodeURIComponent(customerId);
  path += '&order=updated_at.desc,created_at.desc&limit=2';
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  const rows = result && result.ok === true && Array.isArray(result.data) ? result.data : [];
  if (!result || result.ok !== true) throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_READ_FAILED', 503);
  if (rows.length !== 1) throw diracPasswordResetErrorV333(rows.length ? 'PASSWORD_RESET_PASSKEY_AMBIGUOUS' : 'PASSWORD_RESET_PASSKEY_NOT_FOUND', 403);
  return rows[0];
}

async function diracPasswordResetFetchCredentialByRowIdV333(passkeyId, customerId) {
  const cleanId = String(passkeyId || '').trim().toLowerCase();
  const cleanCustomer = String(customerId || '').trim().toLowerCase();
  if (!customerSecurityLooksLikeUuid(cleanId) || !customerSecurityLooksLikeUuid(cleanCustomer)) throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_ROW_ID_INVALID', 403);
  const path = '/rest/v1/domain_passkeys?select=' + encodeURIComponent(diracPasswordResetCredentialRowSelectV333())
    + '&id=eq.' + encodeURIComponent(cleanId)
    + '&user_id=eq.' + encodeURIComponent(cleanCustomer)
    + '&is_active=eq.true&rotation_state=eq.active&order=updated_at.desc,created_at.desc&limit=2';
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  const rows = result && result.ok === true && Array.isArray(result.data) ? result.data : [];
  if (!result || result.ok !== true) throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_READ_FAILED', 503);
  if (rows.length !== 1) throw diracPasswordResetErrorV333(rows.length ? 'PASSWORD_RESET_PASSKEY_AMBIGUOUS' : 'PASSWORD_RESET_PASSKEY_NOT_FOUND', 403);
  return rows[0];
}

async function diracPasswordResetResolveOwnerV333(req, row, expectedEmailHash) {
  const ctx = diracCentralCurrentContextV149();
  const customerId = String(row && row.user_id || '').trim();
  const email = normalizeAuthEmail(row && row.email || '');
  if (!customerSecurityLooksLikeUuid(customerId) || !isValidAuthEmail(email)
      || !safeEqual(diracPasswordResetBindingHashV333('email', email), String(expectedEmailHash || ''))) {
    throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_OWNER_BINDING_INVALID', 403);
  }
  if (ctx) ctx.__diracPasswordResetBootstrapCustomerIdV333 = customerId;
  const select = 'id,auth_user_id,customer_id,email,link_status,match_confidence,disabled_at,revoked_at,updated_at';
  const linkPath = '/rest/v1/security_customer_auth_links?select=' + encodeURIComponent(select)
    + '&customer_id=eq.' + encodeURIComponent(customerId)
    + '&link_status=eq.active&disabled_at=is.null&revoked_at=is.null&order=updated_at.desc&limit=2';
  const linkResult = await supabaseFetch(linkPath, { method: 'GET', auth: 'service' });
  const links = linkResult && linkResult.ok === true && Array.isArray(linkResult.data) ? linkResult.data : [];
  const link = links.length === 1 ? links[0] : null;
  const authUserId = String(link && link.auth_user_id || '').trim();
  const linkEmail = normalizeAuthEmail(link && link.email || '');
  if (!link || !customerSecurityLooksLikeUuid(authUserId)
      || !safeEqual(String(link.customer_id || ''), customerId)
      || !safeEqual(linkEmail, email)
      || String(link.link_status || '') !== 'active' || link.disabled_at || link.revoked_at) {
    throw diracPasswordResetErrorV333('PASSWORD_RESET_AUTH_LINK_INVALID', 403);
  }
  if (ctx) ctx.__diracPasswordResetExpectedAuthUserIdV333 = authUserId;
  await securityResetAccountAllowedV334(authUserId, email, customerId);
  const owner = Object.freeze({ authUserId, customerId, email });
  if (ctx) ctx.__diracPasswordResetVerifiedOwnerV333 = owner;
  return owner;
}

async function diracPasswordResetRevokeReplayCredentialV333(row, owner) {
  const nowIso = new Date().toISOString();
  const path = '/rest/v1/domain_passkeys?id=eq.' + encodeURIComponent(row.id)
    + '&user_id=eq.' + encodeURIComponent(owner.customerId)
    + '&credential_id=eq.' + encodeURIComponent(row.credential_id)
    + '&is_active=eq.true';
  const result = await supabaseFetch(path, {
    method: 'PATCH', auth: 'service', prefer: 'return=representation',
    body: { is_active: false, revoked_at: nowIso, revoke_reason: 'password_reset_passkey_sign_count_replay', updated_at: nowIso }
  });
  const rows = result && result.ok === true && Array.isArray(result.data) ? result.data : [];
  return Boolean(result && result.ok === true && rows.length === 1 && rows[0] && rows[0].is_active === false && rows[0].revoked_at);
}

async function diracPasswordResetVerifyPasskeyV333(req, state, input) {
  diracResetDiagnosticV335(req, 'verify.passkey.server', 'begin', { state_kind: String(state && state.kind || ''), state_expires_in_ms: Number(state && state.expires_at_ms || 0) - Date.now() });
  const credential = input && input.credential && typeof input.credential === 'object' ? input.credential : null;
  const response = credential && credential.response && typeof credential.response === 'object' ? credential.response : null;
  const credentialId = diracPasskeyA2FCredentialId(credential);
  if (!credential || !response || !credentialId || !/^[A-Za-z0-9_-]{16,4096}$/.test(credentialId)) throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_RESPONSE_INVALID', 400);
  if (credential.rawId && !safeEqual(String(credential.rawId), credentialId)) throw diracPasswordResetErrorV333('PASSWORD_RESET_CREDENTIAL_ID_MISMATCH', 403);
  diracResetDiagnosticV335(req, 'verify.passkey.credential', 'validated', { credential_id_hash: crypto.createHash('sha256').update(credentialId).digest('hex').slice(0, 20), raw_id_present: Boolean(credential.rawId), response_fields: Object.keys(response).sort() });
  const row = await diracPasswordResetFetchCredentialByIdV333(credentialId, '');
  diracResetDiagnosticV335(req, 'verify.passkey.credential_read', 'success', { row_present: Boolean(row), sign_count: Number(row && row.sign_count || 0), is_active: row && row.is_active === true, rotation_state: String(row && row.rotation_state || '') });
  const owner = await diracPasswordResetResolveOwnerV333(req, row, diracPasswordResetBindingHashV333('email', normalizeAuthEmail(row && row.email || '')));
  diracResetDiagnosticV335(req, 'verify.passkey.owner', 'success', { owner_bound: Boolean(owner), auth_user_id_hash: crypto.createHash('sha256').update(String(owner && owner.authUserId || '')).digest('hex').slice(0, 20), customer_id_hash: crypto.createHash('sha256').update(String(owner && owner.customerId || '')).digest('hex').slice(0, 20) });
  if (!diracPasswordResetChallengeOwnerValidV333(state, owner.email)) throw diracPasswordResetErrorV333('PASSWORD_RESET_EMAIL_PASSKEY_MISMATCH', 403);
  if (!safeEqual(String(row.user_id || ''), owner.customerId) || !safeEqual(normalizeAuthEmail(row.email || ''), owner.email)) throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_OWNER_INVALID', 403);

  const clientData = diracPasskeyA2FDecodeClientData(response.clientDataJSON);
  if (!clientData || String(clientData.type || '') !== 'webauthn.get'
      || !safeEqual(String(clientData.challenge || ''), String(state.challenge || ''))
      || clientData.crossOrigin === true) throw diracPasswordResetErrorV333('PASSWORD_RESET_WEBAUTHN_CLIENT_DATA_INVALID', 403);
  const clientOrigin = normalizeDashboardMfaOrigin(clientData.origin || '');
  const expectedOrigin = normalizeDashboardMfaOrigin(req && req.__diracKeamananPasswordChangeGatewayV1 === PASSWORD_CHANGE_GATEWAY_TOKEN ? ('https://security.' + diracBaseDomainV250()) : diracRoleOriginV250('auth'));
  if (!clientOrigin || !expectedOrigin || !safeEqual(clientOrigin, expectedOrigin)) throw diracPasswordResetErrorV333('PASSWORD_RESET_WEBAUTHN_ORIGIN_INVALID', 403);
  if (clientData.topOrigin && !safeEqual(normalizeDashboardMfaOrigin(clientData.topOrigin), expectedOrigin)) throw diracPasswordResetErrorV333('PASSWORD_RESET_WEBAUTHN_TOP_ORIGIN_INVALID', 403);
  const rpId = diracPasskeyA2FRpId(req);
  if (!safeEqual(String(state.rp_id || ''), rpId)) throw diracPasswordResetErrorV333('PASSWORD_RESET_WEBAUTHN_RP_ID_INVALID', 403);
  const payload = { challenge: String(state.challenge || ''), rpId };
  const assertion = diracPasskeyA2FValidateAuthenticationResponse({ row, response, payload, clientData, req });
  diracResetDiagnosticV335(req, 'verify.passkey.webauthn', assertion.ok ? 'success' : 'rejected', { reason: String(assertion && assertion.reason || ''), sign_count: Number(assertion && assertion.signCount || 0), backup_eligible: assertion && assertion.backupEligible === true, backup_state: assertion && assertion.backupState === true, device_bound: assertion && assertion.deviceBound === true });
  if (!assertion.ok) {
    if (assertion.reason === 'passkey_sign_count_replay') {
      await diracPasswordResetConsumeStateV333('challenge', input.challenge_id, state.expires_at_ms, state.consume_binding);
      const revoked = await diracPasswordResetRevokeReplayCredentialV333(row, owner);
      throw diracPasswordResetErrorV333(revoked ? 'PASSKEY_CLONE_REVOKED' : 'PASSKEY_CLONE_REVOCATION_FAILED', revoked ? 403 : 503);
    }
    throw diracPasswordResetErrorV333(String(assertion.reason || 'PASSKEY_SIGNATURE_INVALID').toUpperCase(), 403);
  }
  const deviceBinding = diracPasskeyA2FValidateAuthenticationDeviceBinding({
    row,
    body: { response: String(input.device_binding || '') },
    setupToken: String(input.challenge_id || ''),
    payload,
    credentialId
  });
  diracResetDiagnosticV335(req, 'verify.passkey.device_binding', deviceBinding.ok ? 'success' : 'rejected', { reason: String(deviceBinding && deviceBinding.reason || ''), key_id_present: Boolean(deviceBinding && deviceBinding.keyId) });
  if (!deviceBinding.ok) throw diracPasswordResetErrorV333(String(deviceBinding.reason || 'DEVICE_BINDING_AUTHENTICATION_INVALID').toUpperCase(), 403);

  diracResetDiagnosticV335(req, 'verify.challenge_consume', 'begin', {});
  await diracPasswordResetConsumeStateV333('challenge', input.challenge_id, state.expires_at_ms, state.consume_binding);
  diracResetDiagnosticV335(req, 'verify.challenge_consume', 'success', {});
  const previousSignCount = Math.max(0, Number(row.sign_count || 0));
  const nextSignCount = Math.max(0, Number(assertion.signCount || diracPasskeyA2FSignCount(response) || 0));
  if (!Number.isSafeInteger(previousSignCount) || !Number.isSafeInteger(nextSignCount) || nextSignCount < previousSignCount) throw diracPasswordResetErrorV333('PASSWORD_RESET_SIGN_COUNT_INVALID', 503);
  const nowIso = new Date().toISOString();
  const currentJson = row.credential_json && typeof row.credential_json === 'object' ? row.credential_json : {};
  const transports = [];
  const addTransport = (value) => {
    const clean = String(value || '').trim().toLowerCase();
    if (clean && /^[a-z0-9_-]{1,32}$/.test(clean) && !transports.includes(clean)) transports.push(clean);
  };
  for (const values of [
    response && response.transports,
    credential && credential.transports,
    credential && credential.response && credential.response.transports,
    credential && credential.clientExtensionResults && credential.clientExtensionResults.transports
  ]) {
    if (Array.isArray(values)) values.forEach(addTransport);
  }
  const userAgent = requestUserAgent(req).slice(0, 512);
  let userAgentHash = null;
  if (userAgent) {
    const customerMfaKey = diracCentralDeriveSecretV146('customer-mfa');
    try {
      userAgentHash = crypto.createHmac('sha256', customerMfaKey.toString('base64url'))
        .update('dirac-customer-mfa-binding-v2:ua:' + userAgent).digest('hex');
    } finally { customerMfaKey.fill(0); }
  }
  const credentialIdHash = crypto.createHash('sha256').update(credentialId).digest('hex');
  const updatedJson = {
    ...currentJson,
    webauthn: {
      ...(currentJson.webauthn && typeof currentJson.webauthn === 'object' ? currentJson.webauthn : {}),
      backup_eligible: assertion.backupEligible === true,
      backup_state: assertion.backupState === true,
      device_bound: assertion.deviceBound === true,
      sync_policy: 'synced-passkey-device-binding-required-v1'
    },
    device_binding: {
      ...(currentJson.device_binding && typeof currentJson.device_binding === 'object' ? currentJson.device_binding : {}),
      version: DIRAC_PASSKEY_DEVICE_BINDING_VERSION,
      algorithm: DIRAC_PASSKEY_DEVICE_BINDING_ALGORITHM,
      required: true,
      key_id: deviceBinding.keyId,
      public_key_jwk: deviceBinding.publicKeyJwk
    },
    last_authentication: {
      schema: 'dirac-domain-passkey-v1',
      mode: 'authentication',
      rp_id: rpId,
      origin: String(clientData.origin || expectedOrigin || requestOrigin(req) || ''),
      auth_user_id: owner.authUserId,
      customer_id: owner.customerId,
      credential: {
        id_hash: credentialIdHash,
        id_hint: credentialIdHash.slice(0, 12),
        type: diracPasskeyA2FSafeString(credential && credential.type, 64) || 'public-key',
        clientExtensionResultKeys: credential && credential.clientExtensionResults && typeof credential.clientExtensionResults === 'object'
          ? Object.keys(credential.clientExtensionResults).slice(0, 20)
          : []
      },
      response: {
        clientDataJSON_sha256: crypto.createHash('sha256').update(String(response && response.clientDataJSON || '')).digest('hex'),
        attestationObject_sha256: response && response.attestationObject ? crypto.createHash('sha256').update(String(response.attestationObject)).digest('hex') : '',
        authenticatorData_sha256: response && response.authenticatorData ? crypto.createHash('sha256').update(String(response.authenticatorData)).digest('hex') : '',
        signature_sha256: response && response.signature ? crypto.createHash('sha256').update(String(response.signature)).digest('hex') : '',
        userHandle_hash: response && response.userHandle ? crypto.createHash('sha256').update(String(response.userHandle)).digest('hex') : '',
        transports: transports.slice(0, 12)
      },
      client_data: {
        type: String(clientData.type || ''),
        challenge_sha256: crypto.createHash('sha256').update(String(clientData.challenge || '')).digest('hex'),
        origin: String(clientData.origin || ''),
        crossOrigin: clientData.crossOrigin === true
      },
      saved_at: nowIso,
      user_agent_hash: userAgentHash
    }
  };
  const securityEpoch = await diracPasskeyA2FReadSecurityEpoch(owner);
  diracResetDiagnosticV335(req, 'verify.passkey.security_epoch', 'success', { security_epoch: Number(securityEpoch || 0) });
  if (!Number.isSafeInteger(securityEpoch) || securityEpoch < 1) throw diracPasswordResetErrorV333('PASSWORD_RESET_SECURITY_EPOCH_INVALID', 503);
  const storedAuthSessionId = String(row.current_auth_session_id || '').trim();
  if (!customerSecurityLooksLikeUuid(storedAuthSessionId)) throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_SESSION_BINDING_INVALID', 503);
  const signedSessionCookie = securityResetCentralCookieValueV334(req, String(process.env.DOMAIN_SIGNED_SESSION_COOKIE || 'dirac_domain_signed_session'));
  let currentAuthSessionId = '';
  if (signedSessionCookie) {
    const signedParts = String(signedSessionCookie).trim().split('.');
    if (signedParts.length === 2 && /^[A-Za-z0-9_-]+$/.test(signedParts[0]) && /^[A-Za-z0-9_-]{43}$/.test(signedParts[1])) {
      const signedKey = diracCentralDeriveSecretV146('domain-signed-session');
      let expectedSignature = '';
      try {
        expectedSignature = crypto.createHmac('sha256', signedKey.toString('base64url')).update(signedParts[0]).digest('base64url');
      } finally { signedKey.fill(0); }
      if (safeEqual(expectedSignature, signedParts[1])) {
        try {
          const rawSignedPayload = Buffer.from(signedParts[0], 'base64url');
          if (rawSignedPayload.length && rawSignedPayload.length <= 4096 && rawSignedPayload.toString('base64url') === signedParts[0]) {
            const signedPayload = JSON.parse(rawSignedPayload.toString('utf8'));
            const nowS = Math.floor(Date.now() / 1000);
            const issuedAt = Number(signedPayload && signedPayload.iat || 0);
            const expiresAt = Number(signedPayload && signedPayload.exp || 0);
            const signedUserId = String(signedPayload && (signedPayload.uid || signedPayload.id) || '').trim();
            const signedEmail = normalizeAuthEmail(signedPayload && signedPayload.email || '');
            const signedSessionId = String(signedPayload && signedPayload.sid || '').trim();
            if (signedPayload && signedPayload.typ === 'dirac-domain-signed-session-v1'
                && Number.isSafeInteger(issuedAt) && Number.isSafeInteger(expiresAt)
                && issuedAt <= nowS + 60 && expiresAt > nowS
                && expiresAt - issuedAt > 0 && expiresAt - issuedAt <= 60 * 60 * 24 * 7 + 60
                && customerSecurityLooksLikeUuid(signedUserId)
                && safeEqual(signedUserId, owner.authUserId)
                && safeEqual(signedEmail, owner.email)
                && customerSecurityLooksLikeUuid(signedSessionId)) {
              currentAuthSessionId = signedSessionId;
            }
          }
        } catch (_) {}
      }
    }
  }
  if (!customerSecurityLooksLikeUuid(currentAuthSessionId)) throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_SESSION_BINDING_INVALID', 503);
  const recorded = await supabaseFetch('/rest/v1/rpc/dirac_passkey_record_assertion_v237', {
    method: 'POST', auth: 'service', prefer: 'return=representation',
    body: {
      p_customer_id: owner.customerId,
      p_passkey_id: String(row.id || ''),
      p_expected_sign_count: previousSignCount,
      p_new_sign_count: nextSignCount,
      p_backup_state: assertion.backupState === true,
      p_credential_json: updatedJson,
      p_confirm_pending: false,
      p_auth_user_id: owner.authUserId,
      p_assertion_purpose: 'login',
      p_rotation_id: null,
      p_expected_security_epoch: securityEpoch,
      p_current_auth_session_id: currentAuthSessionId
    }
  });
  let recordedRow = null;
  if (recorded && recorded.ok === true) recordedRow = await diracPasswordResetFetchCredentialByRowIdV333(String(row.id || ''), owner.customerId);
  diracResetDiagnosticV335(req, 'verify.passkey.sign_count_cas', recorded && recorded.ok === true ? 'success' : 'error', { http_status: Number(recorded && recorded.status || 0), row_count: recordedRow ? 1 : 0, previous_sign_count: previousSignCount, next_sign_count: nextSignCount });
  if (!recorded || recorded.ok !== true || !recordedRow
      || !safeEqual(String(recordedRow.id || ''), String(row.id || ''))
      || !safeEqual(String(recordedRow.user_id || ''), owner.customerId)
      || !safeEqual(String(recordedRow.credential_id || ''), credentialId)
      || Number(recordedRow.sign_count || 0) !== nextSignCount
      || recordedRow.backup_state !== (assertion.backupState === true)
      || recordedRow.is_active !== true || String(recordedRow.rotation_state || '') !== 'active') {
    throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_USAGE_POSTCONDITION_FAILED', 503);
  }
  return Object.freeze({
    auth_user_id: owner.authUserId,
    customer_id: owner.customerId,
    email: owner.email,
    email_hash: diracPasswordResetBindingHashV333('email', owner.email),
    passkey_id: String(row.id || ''),
    credential_id: credentialId,
    security_epoch: securityEpoch,
    device_binding_key_id: deviceBinding.keyId
  });
}

function diracPasswordResetStrongPasswordV333(password, email) {
  const value = String(password || '');
  const normalizedEmail = normalizeAuthEmail(email || '');
  const local = normalizedEmail.split('@')[0] || '';
  if (value.length < 12) throw diracPasswordResetErrorV333('PASSWORD_TOO_SHORT', 400);
  if (Buffer.byteLength(value, 'utf8') > 512 || /[\0\r\n]/.test(value)) throw diracPasswordResetErrorV333('PASSWORD_FORMAT_INVALID', 400);
  if (!/[A-Z]/.test(value) || !/[0-9]/.test(value) || !/[!@#$%^&*()_+\-=\[\]{};:'",.<>?\/\\|~:]/.test(value)) throw diracPasswordResetErrorV333('PASSWORD_COMPLEXITY_REQUIRED', 400);
  if (/password|qwerty|123456|dirac|admin|welcome/i.test(value)) throw diracPasswordResetErrorV333('PASSWORD_TOO_COMMON', 400);
  if (local.length >= 3 && value.toLowerCase().includes(local.toLowerCase())) throw diracPasswordResetErrorV333('PASSWORD_CONTAINS_ACCOUNT_IDENTIFIER', 400);
  return value;
}

async function diracPasswordResetCommitPasswordV333(req, state, password, confirmation, grantId) {
  diracResetDiagnosticV335(req, 'commit.server', 'begin', { grant_hash: crypto.createHash('sha256').update(String(grantId || '')).digest('hex').slice(0, 20), security_epoch: Number(state && state.security_epoch || 0), password_present: Boolean(password), confirmation_present: Boolean(confirmation) });
  if (!safeEqual(String(password || ''), String(confirmation || ''))) throw diracPasswordResetErrorV333('PASSWORD_CONFIRMATION_MISMATCH', 400);
  const ctx = diracCentralCurrentContextV149();
  const customerId = String(state.customer_id || '');
  const authUserId = String(state.auth_user_id || '');
  const passkeyId = String(state.passkey_id || '');
  if (!customerSecurityLooksLikeUuid(customerId) || !customerSecurityLooksLikeUuid(authUserId) || !customerSecurityLooksLikeUuid(passkeyId)) throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_OWNER_INVALID', 403);
  if (ctx) {
    ctx.__diracPasswordResetBootstrapCustomerIdV333 = customerId;
    ctx.__diracPasswordResetExpectedAuthUserIdV333 = authUserId;
    ctx.__diracPasswordResetGrantOwnerV333 = Object.freeze({ customerId, authUserId, passkeyId });
  }
  const row = await diracPasswordResetFetchCredentialByRowIdV333(passkeyId, customerId);
  diracResetDiagnosticV335(req, 'commit.passkey_readback_before_update', 'success', { row_present: Boolean(row), is_active: row && row.is_active === true, rotation_state: String(row && row.rotation_state || '') });
  const credentialId = String(row && row.credential_id || '');
  if (!credentialId || !safeEqual(String(row.id || ''), passkeyId)) throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_PASSKEY_CHANGED', 409);
  const owner = await diracPasswordResetResolveOwnerV333(req, row, state.email_hash);
  diracResetDiagnosticV335(req, 'commit.owner', 'success', { auth_user_id_hash: crypto.createHash('sha256').update(String(owner && owner.authUserId || '')).digest('hex').slice(0, 20), customer_id_hash: crypto.createHash('sha256').update(String(owner && owner.customerId || '')).digest('hex').slice(0, 20) });
  if (!safeEqual(owner.authUserId, authUserId) || !safeEqual(owner.customerId, customerId)) throw diracPasswordResetErrorV333('PASSWORD_RESET_GRANT_OWNER_CHANGED', 409);
  const epoch = await diracPasskeyA2FReadSecurityEpoch(owner);
  diracResetDiagnosticV335(req, 'commit.security_epoch', 'success', { current_security_epoch: Number(epoch || 0), grant_security_epoch: Number(state.security_epoch || 0), match: Number(epoch) === Number(state.security_epoch) });
  if (!Number.isSafeInteger(epoch) || epoch !== Number(state.security_epoch)) throw diracPasswordResetErrorV333('PASSWORD_RESET_SECURITY_EPOCH_CHANGED', 409);
  const cleanPassword = diracPasswordResetStrongPasswordV333(password, owner.email);
  diracResetDiagnosticV335(req, 'commit.password_policy', 'success', { policy_passed: true });
  diracResetDiagnosticV335(req, 'commit.grant_consume', 'begin', {});
  await diracPasswordResetConsumeStateV333('grant', grantId, state.expires_at_ms, state.consume_binding);
  diracResetDiagnosticV335(req, 'commit.grant_consume', 'success', {});

  const providerUpdate = await supabaseFetch('/auth/v1/admin/users/' + encodeURIComponent(authUserId), {
    method: 'PUT', auth: 'service', body: { password: cleanPassword }
  });
  const updatedUser = providerUpdate && providerUpdate.ok === true && providerUpdate.data ? normalizeSupabaseAdminUser(providerUpdate.data) : null;
  diracResetDiagnosticV335(req, 'commit.provider_update', providerUpdate && providerUpdate.ok === true ? 'success' : 'error', { http_status: Number(providerUpdate && providerUpdate.status || 0), response_user_present: Boolean(updatedUser), id_match: Boolean(updatedUser && safeEqual(String(updatedUser.id || ''), authUserId)), email_match: Boolean(updatedUser && safeEqual(normalizeAuthEmail(updatedUser.email || ''), owner.email)) });
  if (!providerUpdate || providerUpdate.ok !== true || !updatedUser
      || !safeEqual(String(updatedUser.id || ''), authUserId)
      || !safeEqual(normalizeAuthEmail(updatedUser.email || ''), owner.email)) {
    throw diracPasswordResetErrorV333('PASSWORD_RESET_PROVIDER_UPDATE_FAILED', 503);
  }

  const verified = await supabaseFetch('/auth/v1/token?grant_type=password', {
    method: 'POST', auth: 'anon', body: { email: owner.email, password: cleanPassword }
  });
  const verifiedUser = verified && verified.ok === true && verified.data && verified.data.user ? verified.data.user : null;
  const accessToken = String(verified && verified.data && verified.data.access_token || '');
  diracResetDiagnosticV335(req, 'commit.provider_verify', verified && verified.ok === true ? 'success' : 'error', { http_status: Number(verified && verified.status || 0), verified_user_present: Boolean(verifiedUser), access_token_present: Boolean(accessToken), id_match: Boolean(verifiedUser && safeEqual(String(verifiedUser.id || ''), authUserId)), email_match: Boolean(verifiedUser && safeEqual(normalizeAuthEmail(verifiedUser.email || ''), owner.email)) });
  if (!verified || verified.ok !== true || !verifiedUser || !accessToken
      || !safeEqual(String(verifiedUser.id || ''), authUserId)
      || !safeEqual(normalizeAuthEmail(verifiedUser.email || ''), owner.email)) {
    throw diracPasswordResetErrorV333('PASSWORD_RESET_PROVIDER_VERIFY_FAILED', 503);
  }

  const nowIso = new Date().toISOString();
  const params = diracPasswordArgon2V4Params();
  let passwordHash = '';
  try { passwordHash = await diracPasswordArgon2V4Hash(cleanPassword, { authUserId, customerId, email: owner.email }); diracResetDiagnosticV335(req, 'commit.argon2', 'success', { hash_format_valid: String(passwordHash || '').startsWith('$argon2id$'), hash_length: String(passwordHash || '').length, memory_kib: params.memoryCost, time_cost: params.timeCost, parallelism: params.parallelism, configured_hash_length: params.hashLength }); }
  catch (argonError) { passwordHash = ''; diracResetDiagnosticV335(req, 'commit.argon2', 'error', { memory_kib: params.memoryCost, time_cost: params.timeCost, parallelism: params.parallelism, configured_hash_length: params.hashLength }, argonError); }
  const activeOnlyRow = {
    auth_user_id: authUserId,
    customer_id: customerId,
    email_hash: diracPasswordArgon2V4Hmac('email|' + owner.email),
    password_hash: passwordHash,
    hash_algorithm: 'argon2id',
    hash_params: {
      profile: DIRAC_PASSWORD_ARGON2ID_ACTIVE_ONLY_PATCH_V120,
      memory_kib: params.memoryCost,
      time_cost: params.timeCost,
      parallelism: params.parallelism,
      hash_length: params.hashLength,
      pepper: 'env',
      auth_user_bound: true,
      customer_bound: true,
      source_action: req && req.__diracKeamananPasswordChangeGatewayV1 === PASSWORD_CHANGE_GATEWAY_TOKEN ? 'confirm_password_change' : 'confirm_password_reset',
      active_only: true,
      old_hash_retention: 'none',
      rewritten_on_successful_auth: false
    },
    status: 'active',
    updated_at: nowIso
  };
  if (String(passwordHash || '').startsWith('$argon2id$')) {
    const shadow = await diracPasswordArgon2ActiveOnlyV120UpsertCurrent(authUserId, activeOnlyRow, nowIso).catch((shadowError) => { diracResetDiagnosticV335(req, 'commit.argon2_shadow', 'error', {}, shadowError); return null; });
    diracResetDiagnosticV335(req, 'commit.argon2_shadow', shadow && shadow.ok === true ? 'success' : 'error', { ok: Boolean(shadow && shadow.ok === true) });
  } else {
    diracResetDiagnosticV335(req, 'commit.argon2_shadow', 'skipped', { reason: 'argon2_hash_unavailable' });
  }

  const sessionPatchPath = '/rest/v1/security_customer_sessions?select=' + encodeURIComponent('id,customer_id,status,revoked_at,revoke_reason')
    + '&customer_id=eq.' + encodeURIComponent(customerId) + '&status=eq.active&revoked_at=is.null';
  const sessions = await supabaseFetch(sessionPatchPath, {
    method: 'PATCH', auth: 'service', prefer: 'return=representation',
    body: { status: 'revoked', revoked_at: nowIso, revoke_reason: req && req.__diracKeamananPasswordChangeGatewayV1 === PASSWORD_CHANGE_GATEWAY_TOKEN ? 'password_change_passkey' : 'password_reset_passkey' }
  });
  diracResetDiagnosticV335(req, 'commit.session_revoke', sessions && sessions.ok === true ? 'success' : 'error', { http_status: Number(sessions && sessions.status || 0), revoked_row_count: Array.isArray(sessions && sessions.data) ? sessions.data.length : -1 });
  if (!sessions || sessions.ok !== true || !Array.isArray(sessions.data)) throw diracPasswordResetErrorV333('PASSWORD_RESET_SESSION_REVOCATION_FAILED', 503);

  const logout = await supabaseFetch('/auth/v1/logout?scope=global', {
    method: 'POST', auth: 'anon', bearer: accessToken
  });
  diracResetDiagnosticV335(req, 'commit.provider_logout', logout && logout.ok === true ? 'success' : 'error', { http_status: Number(logout && logout.status || 0) });
  if (!logout || logout.ok !== true) throw diracPasswordResetErrorV333('PASSWORD_RESET_PROVIDER_SESSION_REVOCATION_FAILED', 503);

  const activeSessions = await supabaseFetch('/rest/v1/security_customer_sessions?select=id&customer_id=eq.' + encodeURIComponent(customerId) + '&status=eq.active&revoked_at=is.null&limit=2', {
    method: 'GET', auth: 'service'
  });
  diracResetDiagnosticV335(req, 'commit.session_postcondition', activeSessions && activeSessions.ok === true ? 'success' : 'error', { http_status: Number(activeSessions && activeSessions.status || 0), active_session_count: Array.isArray(activeSessions && activeSessions.data) ? activeSessions.data.length : -1 });
  if (!activeSessions || activeSessions.ok !== true || !Array.isArray(activeSessions.data) || activeSessions.data.length !== 0) throw diracPasswordResetErrorV333('PASSWORD_RESET_SESSION_POSTCONDITION_FAILED', 503);

  const passkeyReadback = await diracPasswordResetFetchCredentialByIdV333(credentialId, customerId);
  diracResetDiagnosticV335(req, 'commit.passkey_postcondition', passkeyReadback && passkeyReadback.is_active === true && String(passkeyReadback.rotation_state || '') === 'active' ? 'success' : 'error', { is_active: passkeyReadback && passkeyReadback.is_active === true, rotation_state: String(passkeyReadback && passkeyReadback.rotation_state || ''), row_id_match: Boolean(passkeyReadback && safeEqual(String(passkeyReadback.id || ''), String(state.passkey_id || ''))) });
  if (!passkeyReadback || passkeyReadback.is_active !== true || String(passkeyReadback.rotation_state || '') !== 'active'
      || !safeEqual(String(passkeyReadback.id || ''), String(state.passkey_id || ''))) {
    throw diracPasswordResetErrorV333('PASSWORD_RESET_PASSKEY_POSTCONDITION_FAILED', 503);
  }
  diracResetDiagnosticV335(req, 'commit.server', 'success', { password_changed: true, sessions_revoked: true, login_required: true });
  return Object.freeze({ password_changed: true, sessions_revoked: true, login_required: true });
}

function diracPasswordResetOpsV333(req) {
  return Object.freeze({
    issueProfile: () => diracPasswordResetIssueProfileV333(req),
    unsealPrivateKey: diracPasswordResetUnsealX25519PrivateV333,
    hashBinding: diracPasswordResetBindingHashV333,
    requestBinding: () => diracPasswordResetRequestBindingV333(req),
    issueChallenge: diracPasswordResetIssueChallengeV333,
    readChallenge: diracPasswordResetReadChallengeV333,
    issueGrant: diracPasswordResetIssueGrantV333,
    readGrant: diracPasswordResetReadGrantV333,
    verifyPasskey: (state, input) => diracPasswordResetVerifyPasskeyV333(req, state, input),
    commitPassword: (state, password, confirmation, grantId) => diracPasswordResetCommitPasswordV333(req, state, password, confirmation, grantId),
    rpId: () => diracPasskeyA2FRpId(req),
    authOrigin: () => req && req.__diracKeamananPasswordChangeGatewayV1 === PASSWORD_CHANGE_GATEWAY_TOKEN ? ('https://security.' + diracBaseDomainV250()) : diracRoleOriginV250('auth')
  });
}

const centralHandler = require('./health.js');

function hasCentralSecurityParity(handler) {
  return typeof handler === 'function'
    && Object.isFrozen(handler) === true
    && handler.__diracCentralSecurityGuardV146 === true
    && handler.__diracCentralArchitectureConsolidationV202 === true
    && handler.__diracCentralHardeningV221 === true
    && handler.__diracCentralSecurityScoreV221 === 100
    && typeof handler.__diracCentralPipelineHashV221 === 'string'
    && handler.__diracCentralPipelineHashV221.length > 0
    && handler.__diracCentralSelfTestV221 && handler.__diracCentralSelfTestV221.ok === true
    && handler.__diracCentralDeviceAuthBootstrapV224 === true
    && handler.__diracCentralOwaspHardeningV228 === true
    && handler.__diracCentralBackendComplianceV230 === true
    && handler.__diracCentralBackendStaticGateV230 && handler.__diracCentralBackendStaticGateV230.ok === true
    && handler.__diracCentralRuntimeLockV230 && handler.__diracCentralRuntimeLockV230.ok === true;
}
if (!hasCentralSecurityParity(centralHandler)) throw new Error('DIRAC_SECURITY_ROUTE_CENTRAL_HANDLER_INVALID');

const ACTION_METHODS = Object.freeze({
  security_report: Object.freeze(new Set(['POST', 'OPTIONS'])),
  domain_health: Object.freeze(new Set(['GET', 'HEAD', 'OPTIONS'])),
  domain_dashboard_me: Object.freeze(new Set(['GET', 'HEAD', 'OPTIONS'])),
  customer_security_status: Object.freeze(new Set(['GET', 'HEAD', 'OPTIONS'])),
  customer_security_overview: Object.freeze(new Set(['GET', 'HEAD', 'OPTIONS'])),
  customer_security_recovery_codes_status: Object.freeze(new Set(['GET', 'HEAD', 'OPTIONS'])),
  customer_security_revoke_session: Object.freeze(new Set(['POST', 'OPTIONS'])),
  customer_security_revoke_other_sessions: Object.freeze(new Set(['POST', 'OPTIONS'])),
  customer_security_account_request: Object.freeze(new Set(['POST', 'OPTIONS'])),
  customer_security_recovery_codes_generate: Object.freeze(new Set(['POST', 'OPTIONS'])),
  customer_security_trust_current_device: Object.freeze(new Set(['POST', 'OPTIONS'])),
  customer_security_untrust_device: Object.freeze(new Set(['POST', 'OPTIONS'])),
  request_password_reset: Object.freeze(new Set(['POST', 'OPTIONS'])),
  confirm_password_reset: Object.freeze(new Set(['POST', 'OPTIONS'])),
  request_password_change: Object.freeze(new Set(['POST', 'OPTIONS'])),
  confirm_password_change: Object.freeze(new Set(['POST', 'OPTIONS']))
});

function reject(res, status, code) {
  try {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
  } catch (_) {}
  return res.status(status).json({ ok: false, code, message: 'Permintaan keamanan ditolak oleh gerbang rute.' });
}

const RESET_PREFLIGHT_ALLOWED_HEADERS = Object.freeze(new Set(['accept','content-type','x-csrf-token','x-dirac-csrf-token','x-dirac-page-nonce','x-page-nonce','x-requested-with']));
function resetPreflightHeader(req, name) {
  const headers = req && req.headers && typeof req.headers === 'object' ? req.headers : {};
  const lower = String(name || '').toLowerCase();
  const value = headers[lower] !== undefined ? headers[lower] : headers[name];
  return Array.isArray(value) ? value.join(',') : String(value || '');
}
function resetPreflightBaseDomain() {
  const value = String(process.env.DIRAC_BASE_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value) ? value : '';
}
function handleResetPreflight(req, res) {
  const baseDomain = resetPreflightBaseDomain();
  if (!baseDomain) return reject(res, 503, 'SECURITY_RESET_PREFLIGHT_DOMAIN_INVALID');
  const origin = resetPreflightHeader(req, 'origin').trim().toLowerCase();
  const allowedOrigins = new Set(['https://' + baseDomain, 'https://auth.' + baseDomain]);
  if (!allowedOrigins.has(origin)) return reject(res, 403, 'SECURITY_RESET_PREFLIGHT_ORIGIN_INVALID');
  const expectedHost = 'api.' + baseDomain;
  const forwardedHost = resetPreflightHeader(req, 'x-forwarded-host').split(',')[0].trim().toLowerCase().replace(/:443$/, '');
  const directHost = resetPreflightHeader(req, 'host').split(',')[0].trim().toLowerCase().replace(/:443$/, '');
  if (directHost !== expectedHost || (forwardedHost && forwardedHost !== expectedHost)) return reject(res, 403, 'SECURITY_RESET_PREFLIGHT_HOST_INVALID');
  const forwardedProto = resetPreflightHeader(req, 'x-forwarded-proto').split(',')[0].trim().toLowerCase();
  if (process.env.NODE_ENV === 'production' ? forwardedProto !== 'https' : (forwardedProto && forwardedProto !== 'https')) return reject(res, 403, 'SECURITY_RESET_PREFLIGHT_HTTPS_REQUIRED');
  const requestedMethod = resetPreflightHeader(req, 'access-control-request-method').trim().toUpperCase();
  if (requestedMethod !== 'POST') return reject(res, 405, 'SECURITY_RESET_PREFLIGHT_METHOD_INVALID');
  const requestedHeaders = Array.from(new Set(resetPreflightHeader(req, 'access-control-request-headers').split(',').map((v) => v.trim().toLowerCase()).filter(Boolean)));
  if (requestedHeaders.length > RESET_PREFLIGHT_ALLOWED_HEADERS.size || requestedHeaders.some((name) => !/^[a-z0-9-]{1,64}$/.test(name) || !RESET_PREFLIGHT_ALLOWED_HEADERS.has(name))) return reject(res, 403, 'SECURITY_RESET_PREFLIGHT_HEADER_INVALID');
  if (resetPreflightHeader(req, 'access-control-request-private-network').trim().toLowerCase() === 'true') return reject(res, 403, 'SECURITY_RESET_PREFLIGHT_PRIVATE_NETWORK_REJECTED');
  if (resetPreflightHeader(req, 'authorization').trim() || resetPreflightHeader(req, 'cookie').trim()) return reject(res, 403, 'SECURITY_RESET_PREFLIGHT_CREDENTIALS_REJECTED');
  const contentLength = resetPreflightHeader(req, 'content-length').trim();
  if ((contentLength && contentLength !== '0') || resetPreflightHeader(req, 'transfer-encoding').trim()) return reject(res, 403, 'SECURITY_RESET_PREFLIGHT_BODY_REJECTED');
  const fetchSite = resetPreflightHeader(req, 'sec-fetch-site').trim().toLowerCase();
  const fetchMode = resetPreflightHeader(req, 'sec-fetch-mode').trim().toLowerCase();
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'same-site') return reject(res, 403, 'SECURITY_RESET_PREFLIGHT_FETCH_SITE_INVALID');
  if (fetchMode && fetchMode !== 'cors') return reject(res, 403, 'SECURITY_RESET_PREFLIGHT_FETCH_MODE_INVALID');
  try {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (requestedHeaders.length) res.setHeader('Access-Control-Allow-Headers', requestedHeaders.join(', '));
    res.setHeader('Access-Control-Max-Age', '0');
    res.setHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
  } catch (_) { return reject(res, 503, 'SECURITY_RESET_PREFLIGHT_RESPONSE_INVALID'); }
  return res.status(200).end();
}


function securityPasswordChangeValidateBrowserV1(req, method) {
  const baseDomain = diracBaseDomainV250();
  const expectedOrigin = 'https://security.' + baseDomain;
  const origin = requestOrigin(req);
  if (!safeEqual(origin, expectedOrigin)) throw resetError('SECURITY_PASSWORD_CHANGE_ORIGIN_INVALID', 403);
  const host = securityResetHeaderV334(req, 'host').split(',')[0].trim().toLowerCase().replace(/:443$/, '');
  const xhost = securityResetHeaderV334(req, 'x-forwarded-host').split(',')[0].trim().toLowerCase().replace(/:443$/, '');
  if (host !== 'api.' + baseDomain || (xhost && xhost !== 'api.' + baseDomain)) throw resetError('SECURITY_PASSWORD_CHANGE_HOST_INVALID', 403);
  const proto = securityResetHeaderV334(req, 'x-forwarded-proto').split(',')[0].trim().toLowerCase();
  if (process.env.NODE_ENV === 'production' ? proto !== 'https' : (proto && proto !== 'https')) throw resetError('SECURITY_PASSWORD_CHANGE_HTTPS_REQUIRED', 403);
  const referer = securityResetHeaderV334(req, 'referer').trim();
  if (!referer) throw resetError('SECURITY_PASSWORD_CHANGE_REFERER_REQUIRED', 403);
  let ref;
  try { ref = new URL(referer); } catch (_) { throw resetError('SECURITY_PASSWORD_CHANGE_REFERER_INVALID', 403); }
  if (!safeEqual(ref.origin.toLowerCase(), expectedOrigin) || ref.pathname !== '/keamanan.html' || ref.search || ref.hash || ref.username || ref.password) throw resetError('SECURITY_PASSWORD_CHANGE_REFERER_INVALID', 403);
  const site = securityResetHeaderV334(req, 'sec-fetch-site').trim().toLowerCase();
  const mode = securityResetHeaderV334(req, 'sec-fetch-mode').trim().toLowerCase();
  const dest = securityResetHeaderV334(req, 'sec-fetch-dest').trim().toLowerCase();
  if (site && site !== 'same-site' && site !== 'same-origin') throw resetError('SECURITY_PASSWORD_CHANGE_FETCH_SITE_INVALID', 403);
  if (method === 'POST' && mode && mode !== 'cors' && mode !== 'same-origin') throw resetError('SECURITY_PASSWORD_CHANGE_FETCH_MODE_INVALID', 403);
  if (method === 'POST' && dest && dest !== 'empty') throw resetError('SECURITY_PASSWORD_CHANGE_FETCH_DEST_INVALID', 403);
  if (securityResetHeaderV334(req, 'authorization').trim()) throw resetError('SECURITY_PASSWORD_CHANGE_AUTHORIZATION_HEADER_REJECTED', 403);
  return expectedOrigin;
}

function securityPasswordChangePreflightV1(req, res) {
  const baseDomain = diracBaseDomainV250();
  const expectedOrigin = 'https://security.' + baseDomain;
  const origin = securityResetHeaderV334(req, 'origin').trim().toLowerCase();
  if (!safeEqual(origin, expectedOrigin)) return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_ORIGIN_INVALID');
  const expectedHost = 'api.' + baseDomain;
  const forwardedHost = resetPreflightHeader(req, 'x-forwarded-host').split(',')[0].trim().toLowerCase().replace(/:443$/, '');
  const directHost = resetPreflightHeader(req, 'host').split(',')[0].trim().toLowerCase().replace(/:443$/, '');
  if (directHost !== expectedHost || (forwardedHost && forwardedHost !== expectedHost)) return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_HOST_INVALID');
  const forwardedProto = resetPreflightHeader(req, 'x-forwarded-proto').split(',')[0].trim().toLowerCase();
  if (process.env.NODE_ENV === 'production' ? forwardedProto !== 'https' : (forwardedProto && forwardedProto !== 'https')) return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_HTTPS_REQUIRED');
  if (resetPreflightHeader(req, 'access-control-request-method').trim().toUpperCase() !== 'POST') return reject(res, 405, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_METHOD_INVALID');
  const requestedHeaders = Array.from(new Set(resetPreflightHeader(req, 'access-control-request-headers').split(',').map((v) => v.trim().toLowerCase()).filter(Boolean)));
  if (requestedHeaders.length > RESET_PREFLIGHT_ALLOWED_HEADERS.size || requestedHeaders.some((name) => !/^[a-z0-9-]{1,64}$/.test(name) || !RESET_PREFLIGHT_ALLOWED_HEADERS.has(name))) return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_HEADER_INVALID');
  if (resetPreflightHeader(req, 'access-control-request-private-network').trim().toLowerCase() === 'true') return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_PRIVATE_NETWORK_REJECTED');
  if (resetPreflightHeader(req, 'authorization').trim() || resetPreflightHeader(req, 'cookie').trim()) return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_CREDENTIALS_REJECTED');
  const contentLength = resetPreflightHeader(req, 'content-length').trim();
  if ((contentLength && contentLength !== '0') || resetPreflightHeader(req, 'transfer-encoding').trim()) return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_BODY_REJECTED');
  const fetchSite = resetPreflightHeader(req, 'sec-fetch-site').trim().toLowerCase();
  const fetchMode = resetPreflightHeader(req, 'sec-fetch-mode').trim().toLowerCase();
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'same-site') return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_FETCH_SITE_INVALID');
  if (fetchMode && fetchMode !== 'cors') return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_FETCH_MODE_INVALID');
  try {
    res.setHeader('Access-Control-Allow-Origin', expectedOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (requestedHeaders.length) res.setHeader('Access-Control-Allow-Headers', requestedHeaders.join(', '));
    res.setHeader('Access-Control-Max-Age', '0');
    res.setHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
  } catch (_) { return reject(res, 503, 'SECURITY_PASSWORD_CHANGE_PREFLIGHT_RESPONSE_INVALID'); }
  return res.status(200).end();
}

function securityPasswordChangeCentralProbeResponseV1() {
  const headers = new Map();
  return {
    statusCode: 200, headersSent: false, writableEnded: false, body: null,
    locals: Object.create(null),
    setHeader(name, value) { headers.set(String(name).toLowerCase(), value); return this; },
    getHeader(name) { return headers.get(String(name).toLowerCase()); },
    removeHeader(name) { headers.delete(String(name).toLowerCase()); },
    append(name, value) {
      const key = String(name).toLowerCase(); const current = headers.get(key);
      headers.set(key, current === undefined ? value : (Array.isArray(current) ? current.concat(value) : [current].concat(value))); return this;
    },
    status(code) { this.statusCode = Number(code) || 500; return this; },
    json(value) { this.body = value; this.headersSent = true; this.writableEnded = true; return this; },
    send(value) { this.body = value; this.headersSent = true; this.writableEnded = true; return this; },
    end(value) { if (value !== undefined) this.body = value; this.headersSent = true; this.writableEnded = true; return this; },
    writeHead(code, values) { this.statusCode = Number(code) || 500; if (values && typeof values === 'object') Object.keys(values).forEach((key) => this.setHeader(key, values[key])); this.headersSent = true; return this; },
    write() { this.headersSent = true; return true; },
    cookie() { return this; },
    clearCookie() { return this; }
  };
}

async function securityPasswordChangeRequireCentralGuardV1(req) {
  const original = {
    url: req.url, method: req.method, query: req.query, headers: req.headers,
    hadOriginalUrl: Object.prototype.hasOwnProperty.call(req, 'originalUrl'), originalUrl: req.originalUrl,
    hadPath: Object.prototype.hasOwnProperty.call(req, 'path'), path: req.path
  };
  const probeRes = securityPasswordChangeCentralProbeResponseV1();
  try {
    req.url = CENTRAL_ROUTE_PATH + '?action=customer_security_guard_status';
    req.originalUrl = req.url;
    req.path = CENTRAL_ROUTE_PATH;
    req.method = 'GET';
    req.query = { action: 'customer_security_guard_status' };
    req.headers = { ...(req.headers && typeof req.headers === 'object' ? req.headers : {}) };
    delete req.headers['content-length'];
    delete req.headers['transfer-encoding'];
    delete req.headers['content-type'];
    delete req.headers['content-encoding'];
    await centralHandler(req, probeRes);
  } finally {
    try { req.url = original.url; } catch (_) {}
    try { req.method = original.method; } catch (_) {}
    try { req.query = original.query; } catch (_) {}
    try { req.headers = original.headers; } catch (_) {}
    try { if (original.hadOriginalUrl) req.originalUrl = original.originalUrl; else delete req.originalUrl; } catch (_) {}
    try { if (original.hadPath) req.path = original.path; else delete req.path; } catch (_) {}
  }
  const data = probeRes.body && typeof probeRes.body === 'object' && !Array.isArray(probeRes.body) ? probeRes.body : null;
  if (Number(probeRes.statusCode) !== 200 || !data || data.ok !== true || data.endpoint !== 'customer_security_guard_status'
      || data.linked !== true || data.mfa_required_for_page !== true || data.mfa_required_for_write !== true
      || data.mfa_active_now !== true || data.guarded_actions_ready !== true || data.write_guard !== 'mfa_required'
      || data.direct_frontend_table_access !== false || data.customer_id_source !== 'security_customer_auth_links') {
    throw resetError('SECURITY_PASSWORD_CHANGE_CENTRAL_GUARD_REQUIRED', Number(probeRes.statusCode) >= 400 && Number(probeRes.statusCode) <= 599 ? Number(probeRes.statusCode) : 403);
  }
  return true;
}

function securityPasswordChangeBootstrapTargetV1(req) {
  const raw = String(req && req.url || '');
  const q = raw.indexOf('?'); if (q < 0 || raw.slice(0, q) !== SECURITY_ROUTE_PATH) return '';
  let params; try { params = new URLSearchParams(raw.slice(q + 1)); } catch (_) { return ''; }
  if (params.getAll('action').length !== 1 || params.get('action') !== 'domain_health' || params.getAll('_dirac_page_nonce_for').length !== 1) return '';
  const target = String(params.get('_dirac_page_nonce_for') || '').trim().toLowerCase();
  if (!PASSWORD_CHANGE_ACTIONS.has(target) || params.getAll('_csrf_probe').length !== 1 || !/^\d{10,17}$/.test(String(params.get('_csrf_probe') || ''))) return '';
  return target;
}

async function handlePasswordChangeBootstrapV1(req, res, targetAction) {
  const origin = securityPasswordChangeValidateBrowserV1(req, 'GET');
  if (String(req && req.method || '').toUpperCase() !== 'GET') return reject(res, 405, 'SECURITY_PASSWORD_CHANGE_BOOTSTRAP_METHOD_INVALID');
  const params = new URLSearchParams(String(req && req.url || '').split('?').slice(1).join('?'));
  const probeMs = Number(params.get('_csrf_probe'));
  const nowMs = Date.now();
  if (!Number.isSafeInteger(probeMs) || probeMs < nowMs - 30000 || probeMs > nowMs + 5000) return reject(res, 403, 'SECURITY_PASSWORD_CHANGE_BOOTSTRAP_PROBE_INVALID');
  await securityPasswordChangeRequireCentralGuardV1(req);
  await securityResetRateLimitV334(req, 'password_change_bootstrap_' + targetAction);
  const csrf = securityResetIssueCsrfV334(req);
  const nonce = securityResetIssuePageNonceV334(req, targetAction);
  securityResetApplyHeadersV334(req, res, origin);
  res.setHeader('X-Dirac-CSRF-Token', csrf); res.setHeader('X-CSRF-Token', csrf);
  res.setHeader('X-Dirac-Page-Nonce', nonce); res.setHeader('X-Page-Nonce', nonce);
  return res.status(200).json({ ok:true, security_password_change_bootstrap:true, central_guard_verified:true });
}

async function securityPasswordChangeRunResetEngineV1(req, res, parsed, body) {
  const mappedAction = parsed.action === 'request_password_change' ? 'request_password_reset' : 'confirm_password_reset';
  const mappedBody = { ...body, action: mappedAction };
  const hadMarker = Object.prototype.hasOwnProperty.call(req, '__diracKeamananPasswordChangeGatewayV1');
  const previousMarker = req.__diracKeamananPasswordChangeGatewayV1;
  const originalQuery = req.query;
  try {
    req.__diracKeamananPasswordChangeGatewayV1 = PASSWORD_CHANGE_GATEWAY_TOKEN;
    req.query = { action: mappedAction };
    return await passwordResetEngine(req, res, diracPasswordResetOpsV333(req), mappedBody);
  } finally {
    try { req.query = originalQuery; } catch (_) {}
    try { if (hadMarker) req.__diracKeamananPasswordChangeGatewayV1 = previousMarker; else delete req.__diracKeamananPasswordChangeGatewayV1; } catch (_) {}
  }
}

async function handlePasswordChangePostV1(req, res, parsed) {
  const origin = securityPasswordChangeValidateBrowserV1(req, 'POST');
  securityResetApplyHeadersV334(req, res, origin);
  await securityPasswordChangeRequireCentralGuardV1(req);
  const contentType = securityResetHeaderV334(req, 'content-type').toLowerCase();
  if (!contentType.startsWith('application/json')) throw resetError('SECURITY_PASSWORD_CHANGE_CONTENT_TYPE_INVALID', 415);
  const primary = securityResetHeaderV334(req, 'x-dirac-csrf-token').trim();
  const compat = securityResetHeaderV334(req, 'x-csrf-token').trim();
  if (!primary || !compat || !safeEqual(primary, compat) || !securityResetVerifyCsrfV334(req, primary)) throw resetError('SECURITY_PASSWORD_CHANGE_CSRF_INVALID', 403);
  const nonceText = (securityResetHeaderV334(req, 'x-dirac-page-nonce') || securityResetHeaderV334(req, 'x-page-nonce')).trim();
  const nonce = securityResetVerifyPageNonceV334(req, nonceText, parsed.action);
  if (!nonce || nonce.__diracPageNonceSourceV334 !== 'standalone') throw resetError('SECURITY_PASSWORD_CHANGE_PAGE_NONCE_INVALID', 403);
  const body = await securityResetReadJsonV334(req);
  const bodyAction = String(body.action || '').trim().toLowerCase().replace(/-/g, '_');
  if (bodyAction !== parsed.action) throw resetError('SECURITY_PASSWORD_CHANGE_ACTION_MISMATCH', 400);
  await securityResetRateLimitV334(req, 'password_change_' + parsed.action);
  const consumed = await diracCentralAtomicConsumeV230({ namespace:'pwd_change_page_nonce', jti:String(nonce.jti), expiresAt:Number(nonce.exp), contextHash:[nonce.act,nonce.sid,nonce.oh,nonce.mth,nonce.rb].join('|') });
  if (!consumed || consumed.ok !== true) throw resetError('SECURITY_PASSWORD_CHANGE_PAGE_NONCE_REPLAY', 409);
  return securityPasswordChangeRunResetEngineV1(req, res, parsed, body);
}


function securityResetBootstrapTargetV334(req) {
  const raw = String(req && req.url || '');
  const q = raw.indexOf('?'); if (q < 0 || raw.slice(0,q) !== SECURITY_ROUTE_PATH) return '';
  let p; try { p = new URLSearchParams(raw.slice(q+1)); } catch (_) { return ''; }
  if (p.getAll('action').length !== 1 || p.get('action') !== 'domain_health' || p.getAll('_dirac_page_nonce_for').length !== 1) return '';
  const target = String(p.get('_dirac_page_nonce_for') || '').trim().toLowerCase();
  if (!RESET_ACTIONS.has(target) || p.getAll('_csrf_probe').length !== 1 || !/^\d{10,17}$/.test(String(p.get('_csrf_probe')||''))) return '';
  return target;
}
async function handleResetBootstrapV334(req,res,targetAction){
  diracResetDiagnosticV335(req, 'bootstrap', 'begin', { target_action: String(targetAction || '') });
  const origin=securityResetValidateBrowserV334(req,'GET');
  diracResetDiagnosticV335(req, 'bootstrap.browser', 'success', { target_action: String(targetAction || ''), origin });
  if (String(req&&req.method||'').toUpperCase()!=='GET') return reject(res,405,'SECURITY_RESET_BOOTSTRAP_METHOD_INVALID');
  const bootstrapParams=new URLSearchParams(String(req&&req.url||'').split('?').slice(1).join('?'));
  const bootstrapProbeMs=Number(bootstrapParams.get('_csrf_probe'));
  const bootstrapNowMs=Date.now();
  if(!Number.isSafeInteger(bootstrapProbeMs)||bootstrapProbeMs<bootstrapNowMs-30000||bootstrapProbeMs>bootstrapNowMs+5000) return reject(res,403,'SECURITY_RESET_BOOTSTRAP_PROBE_INVALID');
  diracResetDiagnosticV335(req, 'bootstrap.probe', 'success', { probe_age_ms: bootstrapNowMs - bootstrapProbeMs });
  diracResetDiagnosticV335(req, 'bootstrap.rate_limit', 'begin', { bucket: 'bootstrap_'+targetAction });
  await securityResetRateLimitV334(req,'bootstrap_'+targetAction);
  diracResetDiagnosticV335(req, 'bootstrap.rate_limit', 'success', { bucket: 'bootstrap_'+targetAction });
  const csrf=securityResetIssueCsrfV334(req),nonce=securityResetIssuePageNonceV334(req,targetAction);
  diracResetDiagnosticV335(req, 'bootstrap.tokens', 'issued', { csrf_length: csrf.length, page_nonce_length: nonce.length, target_action: String(targetAction || '') });
  securityResetApplyHeadersV334(req,res,origin);
  res.setHeader('X-Dirac-CSRF-Token',csrf); res.setHeader('X-CSRF-Token',csrf);
  res.setHeader('X-Dirac-Page-Nonce',nonce); res.setHeader('X-Page-Nonce',nonce);
  const resetNonceCookie='__Host-dirac_reset_page_nonce_v334='+encodeURIComponent(nonce)+'; Path=/; Max-Age='+SECURITY_RESET_PAGE_NONCE_TTL_S_V334+'; HttpOnly; Secure; SameSite=Strict; Priority=High';
  const existingSetCookie=typeof res.getHeader==='function'?res.getHeader('Set-Cookie'):null;
  res.setHeader('Set-Cookie',(Array.isArray(existingSetCookie)?existingSetCookie:(existingSetCookie?[existingSetCookie]:[])).concat(resetNonceCookie));
  diracResetDiagnosticV335(req, 'bootstrap', 'success', { http_status: 200, target_action: String(targetAction || ''), reset_nonce_cookie_set: true });
  return res.status(200).json({ok:true,security_reset_bootstrap:true});
}
async function handleStandaloneResetPostV334(req,res,parsed){
  diracResetDiagnosticV335(req, 'post', 'begin', { parsed_action: String(parsed && parsed.action || ''), parsed_method: String(parsed && parsed.method || '') });
  const origin=securityResetValidateBrowserV334(req,'POST'); securityResetApplyHeadersV334(req,res,origin);
  diracResetDiagnosticV335(req, 'post.browser', 'success', { origin });
  const ct=securityResetHeaderV334(req,'content-type').toLowerCase(); if(!ct.startsWith('application/json')) throw resetError('SECURITY_RESET_CONTENT_TYPE_INVALID',415);
  diracResetDiagnosticV335(req, 'post.content_type', 'success', { content_type: ct.slice(0,120) });
  const primary=securityResetHeaderV334(req,'x-dirac-csrf-token').trim(),compat=securityResetHeaderV334(req,'x-csrf-token').trim();
  if(!primary||!compat||!safeEqual(primary,compat)||!securityResetVerifyCsrfV334(req,primary)) throw resetError('SECURITY_RESET_CSRF_INVALID',403);
  const standaloneCsrfPayload=securityResetTokenDecodeV334(primary,'keamanan-reset-csrf-v1');
  diracResetDiagnosticV335(req, 'post.csrf', 'success', { source: standaloneCsrfPayload && standaloneCsrfPayload.typ==='dirac-keamanan-reset-csrf-v1' ? 'standalone' : 'central', primary_length: primary.length, compat_length: compat.length, equal: safeEqual(primary,compat) });
  const nonceText=(securityResetHeaderV334(req,'x-dirac-page-nonce')||securityResetHeaderV334(req,'x-page-nonce')).trim();
  const nonce=securityResetVerifyPageNonceV334(req,nonceText,parsed.action); if(!nonce) throw resetError('SECURITY_RESET_PAGE_NONCE_INVALID',403);
  diracResetDiagnosticV335(req, 'post.page_nonce', 'success', { source: String(nonce.__diracPageNonceSourceV334 || ''), act: String(nonce.act || ''), mth: String(nonce.mth || ''), expires_in_s: Number(nonce.exp || 0) - Math.floor(Date.now()/1000), nonce_length: nonceText.length });
  const body=await securityResetReadJsonV334(req); const bodyAction=String(body.action||'').trim().toLowerCase().replace(/-/g,'_');
  diracResetDiagnosticV335(req, 'post.body', 'success', { body_keys: Object.keys(body).sort(), body_action: bodyAction });
  if(bodyAction!==parsed.action) throw resetError('SECURITY_RESET_ACTION_MISMATCH',400);
  diracResetDiagnosticV335(req, 'post.rate_limit', 'begin', { bucket: parsed.action });
  await securityResetRateLimitV334(req,parsed.action);
  diracResetDiagnosticV335(req, 'post.rate_limit', 'success', { bucket: parsed.action });
  const centralPageNonce=nonce.__diracPageNonceSourceV334==='central';
  const consumeNamespace=centralPageNonce?'page_nonce':'pwd_reset_page_nonce';
  diracResetDiagnosticV335(req, 'post.page_nonce_consume', 'begin', { namespace: consumeNamespace, source: String(nonce.__diracPageNonceSourceV334 || '') });
  const consumed=await diracCentralAtomicConsumeV230({namespace:consumeNamespace,jti:String(nonce.jti),expiresAt:Number(nonce.exp),contextHash:centralPageNonce?[nonce.act,nonce.sid,nonce.oh,nonce.mth].join('|'):[nonce.act,nonce.sid,nonce.oh,nonce.mth,nonce.rb].join('|')});
  diracResetDiagnosticV335(req, 'post.page_nonce_consume', consumed && consumed.ok === true ? 'success' : 'rejected', { namespace: consumeNamespace, consumed: Boolean(consumed && consumed.ok === true) });
  if(!consumed.ok) throw resetError('SECURITY_RESET_PAGE_NONCE_REPLAY',409);
  diracResetDiagnosticV335(req, 'post.engine', 'begin', { action: parsed.action });
  const result=await passwordResetEngine(req,res,diracPasswordResetOpsV333(req),body);
  diracResetDiagnosticV335(req, 'post.engine', 'success', { action: parsed.action, response_status: Number(res && res.statusCode || 0) });
  return result;
}

function parseExactRequest(req) {
  const rawUrl = String(req && req.url || '');
  if (!rawUrl || rawUrl.length > 1800 || /[\u0000-\u001f\u007f]/.test(rawUrl)) return { ok: false, code: 'SECURITY_ROUTE_URL_INVALID' };
  const queryIndex = rawUrl.indexOf('?');
  const rawPath = queryIndex === -1 ? rawUrl : rawUrl.slice(0, queryIndex);
  const rawQuery = queryIndex === -1 ? '' : rawUrl.slice(queryIndex + 1);
  if (rawPath !== SECURITY_ROUTE_PATH || rawQuery.length > 1600) return { ok: false, code: 'SECURITY_ROUTE_PATH_INVALID' };
  let params;
  try { params = new URLSearchParams(rawQuery); } catch (_) { return { ok: false, code: 'SECURITY_ROUTE_QUERY_INVALID' }; }
  const actions = params.getAll('action');
  if (actions.length !== 1) return { ok: false, code: 'SECURITY_ROUTE_ACTION_COUNT_INVALID' };
  const action = String(actions[0] || '').trim();
  if (!/^[a-z][a-z0-9_]{1,79}$/.test(action) || action === 'domain_login' || action === 'domain_logout' || !Object.prototype.hasOwnProperty.call(ACTION_METHODS, action)) return { ok: false, code: 'SECURITY_ROUTE_ACTION_NOT_ALLOWED' };
  if (req && req.query && Object.prototype.hasOwnProperty.call(req.query, 'action')) {
    const queryAction = req.query.action;
    if (Array.isArray(queryAction) || String(queryAction || '').trim() !== action) return { ok: false, code: 'SECURITY_ROUTE_ACTION_MISMATCH' };
  }
  const method = String(req && req.method || 'GET').toUpperCase();
  if (!ACTION_METHODS[action].has(method)) return { ok: false, code: 'SECURITY_ROUTE_METHOD_NOT_ALLOWED', allow: Array.from(ACTION_METHODS[action]).filter((v) => v !== 'OPTIONS') };
  return { ok: true, action, method, canonicalUrl: CENTRAL_ROUTE_PATH + (rawQuery ? '?' + rawQuery : ''), reset: RESET_ACTIONS.has(action), passwordChange: PASSWORD_CHANGE_ACTIONS.has(action) };
}

async function invokeCentral(req, res, parsed) {
  const originalUrl = req.url;
  const hadOriginalUrl = Object.prototype.hasOwnProperty.call(req, 'originalUrl');
  const originalOriginalUrl = req.originalUrl;
  const hadPath = Object.prototype.hasOwnProperty.call(req, 'path');
  const originalPath = req.path;
  const hadMarker = Object.prototype.hasOwnProperty.call(req, '__diracKeamananResetGatewayV333');
  const originalMarker = req.__diracKeamananResetGatewayV333;
  try {
    req.url = parsed.canonicalUrl;
    req.originalUrl = parsed.canonicalUrl;
    req.path = CENTRAL_ROUTE_PATH;
    if (parsed.reset) req.__diracKeamananResetGatewayV333 = RESET_GATEWAY_TOKEN;
    return await centralHandler(req, res);
  } finally {
    try { req.url = originalUrl; } catch (_) {}
    try { if (hadOriginalUrl) req.originalUrl = originalOriginalUrl; else delete req.originalUrl; } catch (_) {}
    try { if (hadPath) req.path = originalPath; else delete req.path; } catch (_) {}
    try { if (hadMarker) req.__diracKeamananResetGatewayV333 = originalMarker; else delete req.__diracKeamananResetGatewayV333; } catch (_) {}
  }
}

async function keamananHandler(req, res) {
  const passwordChangeBootstrapTarget = securityPasswordChangeBootstrapTargetV1(req);
  if (passwordChangeBootstrapTarget && String(req && req.method || 'GET').toUpperCase() === 'GET') {
    try { return await handlePasswordChangeBootstrapV1(req, res, passwordChangeBootstrapTarget); }
    catch (error) { securityResetApplyHeadersV334(req, res, requestOrigin(req)); return resetResponse(res, Math.max(400, Math.min(599, Number(error && error.statusCode || 503) || 503)), { ok:false, code:String(error && error.code || 'SECURITY_PASSWORD_CHANGE_BOOTSTRAP_FAILED'), message:'Perubahan password ditolak oleh sistem keamanan.' }); }
  }
  const bootstrapTarget = securityResetBootstrapTargetV334(req);
  if (bootstrapTarget && String(req && req.method || 'GET').toUpperCase() === 'GET') {
    try { return await handleResetBootstrapV334(req, res, bootstrapTarget); }
    catch (error) { diracResetDiagnosticV335(req, 'bootstrap', 'error', { target_action: bootstrapTarget }, error); securityResetApplyHeadersV334(req, res, requestOrigin(req)); return resetResponse(res, Math.max(400, Math.min(599, Number(error && error.statusCode || 503) || 503)), { ok:false, code:String(error && error.code || 'SECURITY_RESET_BOOTSTRAP_FAILED'), message:'Permintaan keamanan ditolak.' }); }
  }
  const parsed = parseExactRequest(req);
  if (!parsed.ok) {
    if (parsed.allow && parsed.allow.length) { try { res.setHeader('Allow', parsed.allow.join(', ')); } catch (_) {} return reject(res, 405, parsed.code); }
    return reject(res, 403, parsed.code);
  }
  if (parsed.passwordChange && parsed.method === 'OPTIONS') return securityPasswordChangePreflightV1(req, res);
  if (parsed.passwordChange && parsed.method === 'POST') {
    try { return await handlePasswordChangePostV1(req, res, parsed); }
    catch (error) { securityResetApplyHeadersV334(req, res, requestOrigin(req)); return resetResponse(res, Math.max(400, Math.min(599, Number(error && error.statusCode || 503) || 503)), { ok:false, code:String(error && error.code || 'SECURITY_PASSWORD_CHANGE_FAILED'), message:'Perubahan password ditolak oleh sistem keamanan.' }); }
  }
  if (parsed.reset && parsed.method === 'OPTIONS') return handleResetPreflight(req, res);
  if (parsed.reset && parsed.method === 'POST') {
    try { return await handleStandaloneResetPostV334(req, res, parsed); }
    catch (error) { diracResetDiagnosticV335(req, 'post', 'error', { parsed_action: parsed.action, parsed_method: parsed.method }, error); securityResetApplyHeadersV334(req, res, requestOrigin(req)); return resetResponse(res, Math.max(400, Math.min(599, Number(error && error.statusCode || 503) || 503)), { ok:false, code:String(error && error.code || 'PASSWORD_RESET_ENGINE_FAILED'), message:'Pemulihan password ditolak oleh sistem keamanan.' }); }
  }
  return invokeCentral(req, res, parsed);
}

Object.defineProperty(keamananHandler, 'config', { value: centralHandler.config, enumerable: true, writable: false, configurable: false });
[
  '__diracCentralSecurityGuardV146','__diracCentralArchitectureConsolidationV202','__diracCentralHardeningV221','__diracCentralSecurityScoreV221','__diracCentralPipelineHashV221','__diracCentralSelfTestV221','__diracCentralPatchTargetCountV221','__diracCentralPatchTargetsV221','__diracCentralDeviceAuthBootstrapV224','__diracCentralOwaspHardeningV228','__diracCentralBackendComplianceV230','__diracCentralBackendStaticGateV230','__diracCentralRuntimeLockV230'
].forEach((name) => Object.defineProperty(keamananHandler, name, { value: centralHandler[name], enumerable: false }));
Object.defineProperty(keamananHandler, '__diracSecurityRouteAliasV2', { value: true, enumerable: false });
Object.freeze(keamananHandler);
module.exports = keamananHandler;


/* DIRAC APPEND-ONLY REVISION 2026-09-04: reset-password policy parity with registration. */
/* Existing reset validation is not removed; this override synchronizes the requested 12/1-uppercase/1-digit/1-symbol composition rule. */
diracPasswordResetStrongPasswordV333 = function diracPasswordResetStrongPasswordV333Parity20260904(password, email) {
  const value = String(password || '');
  const normalizedEmail = normalizeAuthEmail(email || '');
  const local = normalizedEmail.split('@')[0] || '';
  const specialCount = (value.match(/[!@#$%^&*()_+\-=\[\]{};:'",.<>?\/\\|~:]/g) || []).length;
  const uppercaseCount = (value.match(/[A-Z]/g) || []).length;
  const digitCount = (value.match(/[0-9]/g) || []).length;
  if (value.length < 12) throw diracPasswordResetErrorV333('PASSWORD_TOO_SHORT', 400);
  if (value.length > 128 || Buffer.byteLength(value, 'utf8') > 512 || /[\0\r\n]/.test(value)) throw diracPasswordResetErrorV333('PASSWORD_FORMAT_INVALID', 400);
  if (uppercaseCount < 1 || digitCount < 1 || specialCount < 1) throw diracPasswordResetErrorV333('PASSWORD_COMPLEXITY_REQUIRED', 400);
  if (/password|qwerty|123456|dirac|admin|welcome/i.test(value)) throw diracPasswordResetErrorV333('PASSWORD_TOO_COMMON', 400);
  if (local.length >= 3 && value.toLowerCase().includes(local.toLowerCase())) throw diracPasswordResetErrorV333('PASSWORD_CONTAINS_ACCOUNT_IDENTIFIER', 400);
  return value;
};

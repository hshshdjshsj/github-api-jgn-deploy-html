'use strict';

// Storage boundary only. Call encode after authorization, and decode before
// response validation. This module never performs I/O, retries, or migrations.
const crypto = require('crypto');
const MARKER = '_dirac_cipher';
const VERSION = 'aes-256-gcm:hkdf-sha512:v1';
const BOUND_VERSION = 'aes-256-gcm:hkdf-sha512:v2';
const PRIVATE_METADATA = '_dirac_private';
const BAN_IDENTITY_FIELDS = Object.freeze([
  'identity_email', 'identityEmail', 'email', 'auth_email', 'user_email', 'customer_email', 'owner_email'
]);
const BAN_NESTED_FIELDS = Object.freeze({
  metadata: BAN_IDENTITY_FIELDS, revocation: Object.freeze(['admin_email'])
});
const COMPACT_BAN_KEY = /^global-ban-active:bundle:[a-f0-9]{64}$/;
const MAX_VALUE_BYTES = 1024 * 1024;
const MAX_BATCH_BYTES = 4 * MAX_VALUE_BYTES;
const MAX_ROWS = 1000;
const MAX_NODES = 16384;
const MAX_DEPTH = 32;
const SENSITIVE_METADATA = Object.freeze([
  'partner_email', 'email', 'name', 'phone', 'message', 'admin_note',
  'address', 'full_name', 'phone_number', 'mobile', 'whatsapp',
  'billing_address', 'shipping_address', 'contact_email', 'contact_phone'
]);
const SHIPMENT_KEY = /^s2s-admin-shipment-v406:(regular|laboratorium|domain):[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const RESET_KEY = /^password-reset-mail-v338:[a-f0-9]{64}$/;
const TABLES = new Set(['payment_gateway_events', 'payment_transactions',
  'security_customer_account_requests', 'dirac_persistent_bans', 'dirac_s2s_security',
  'customers', 'orders', 'order_items', 'domain_orders', 'security_customer_auth_links',
  'security_customer_events', 'security_customer_login_logs', 'security_customer_sessions',
  'security_logs']);
const own = (value, name) => Object.prototype.hasOwnProperty.call(value, name);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

function failure() {
  return Object.assign(new Error('DATA_PROTECTION_FAILED'), {
    code: 'DATA_PROTECTION_FAILED', status: 503, statusCode: 503
  });
}

function deriveKey() {
  const root = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '').trim();
  const production = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
  if (Buffer.byteLength(root, 'utf8') < (production ? 3000 : 32)) throw failure();
  const input = Buffer.from(root, 'utf8');
  try {
    return Buffer.from(crypto.hkdfSync('sha512', input,
      Buffer.from('dirac-json-storage-v1', 'utf8'),
      Buffer.from('dirac-json-storage-aes-256-gcm-key-v1', 'utf8'), 32));
  } finally { input.fill(0); }
}

function jsonBytes(value) {
  // Check shape and size before serialization. Traversal has explicit depth,
  // node and byte limits; no recursive walk or work is scheduled afterwards.
  const stack = [{ value, depth: 0 }];
  let nodes = 0, estimate = 0;
  while (stack.length) {
    const entry = stack.pop(), item = entry.value;
    if (++nodes > MAX_NODES || entry.depth > MAX_DEPTH) throw failure();
    if (item === null || typeof item === 'boolean') estimate += 5;
    else if (typeof item === 'number' && Number.isFinite(item)) estimate += 24;
    else if (typeof item === 'string') estimate += Buffer.byteLength(item, 'utf8') + 2;
    else if (Array.isArray(item)) {
      if (item.length > MAX_NODES - nodes || stack.length + item.length > MAX_NODES) throw failure();
      estimate += item.length + 2;
      for (let i = 0; i < item.length; i += 1) stack.push({ value: item[i], depth: entry.depth + 1 });
    } else if (record(item)) {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) throw failure();
      const keys = Object.keys(item);
      if (keys.length > MAX_NODES - nodes || stack.length + keys.length > MAX_NODES) throw failure();
      estimate += 2;
      for (const name of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(item, name);
        if (!descriptor || !own(descriptor, 'value')) throw failure();
        estimate += Buffer.byteLength(name, 'utf8') + 4;
        if (estimate > MAX_VALUE_BYTES) throw failure();
        stack.push({ value: descriptor.value, depth: entry.depth + 1 });
      }
    } else throw failure();
    if (estimate > MAX_VALUE_BYTES) throw failure();
  }
  const json = JSON.stringify(value);
  if (typeof json !== 'string' || Buffer.byteLength(json, 'utf8') > MAX_VALUE_BYTES) throw failure();
  return Buffer.from(json, 'utf8');
}

function base64Bytes(value, exactLength, maxLength) {
  if (typeof value !== 'string' || value.length > Math.ceil(maxLength / 3) * 4
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw failure();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || bytes.length > maxLength
      || (exactLength !== null && bytes.length !== exactLength)) { bytes.fill(0); throw failure(); }
  return bytes;
}

function rowIdentity(row, params, name, required = true) {
  const values = params.getAll(name);
  if (values.length > 1) throw failure();
  const predicate = values.length === 1 && values[0].startsWith('eq.') ? values[0].slice(3) : null;
  const normalize = value => {
    if (typeof value !== 'string') throw failure();
    if (name === 'gateway_event_id') {
      if (!value || value.length > 220 || /[\u0000-\u001f\u007f]/.test(value)) throw failure();
      return value;
    }
    if (name === 'security_key') {
      if (!/^[A-Za-z0-9:._-]{1,500}$/.test(value)) throw failure();
      return value;
    }
    const normalized = value.toLowerCase();
    if (!UUID.test(normalized)) throw failure();
    return normalized;
  };
  const fieldValue = own(row, name) ? normalize(row[name]) : null;
  const queryValue = predicate === null ? null : normalize(predicate);
  if (fieldValue !== null && queryValue !== null && fieldValue !== queryValue) throw failure();
  const value = fieldValue === null ? queryValue : fieldValue;
  if (required && value === null) throw failure();
  return value;
}

function rowBinding(info, claimed) {
  const { table, row, params } = info;
  if (table === 'dirac_persistent_bans' && record(row.record_json)
      && row.record_json.schema === 'dirac.customer_access_block') return accessBlockBinding(info, claimed);
  let names;
  if (table === 'payment_gateway_events') names = ['customer_id', 'gateway_event_id'];
  else if (table === 'payment_transactions') names = ['id'];
  else if (table === 'dirac_persistent_bans') names = ['security_key'];
  else if (table === 'security_customer_account_requests') {
    if (claimed !== undefined) {
      if (!record(claimed) || Object.keys(claimed).length !== 1) throw failure();
      names = own(claimed, 'id') ? ['id'] : own(claimed, 'customer_id') ? ['customer_id'] : [];
    } else names = rowIdentity(row, params, 'id', false) === null ? ['customer_id'] : ['id'];
  } else throw failure();
  if (!names.length || (claimed !== undefined && (!record(claimed)
      || Object.keys(claimed).sort().join(',') !== names.slice().sort().join(',')))) throw failure();
  const binding = {};
  for (const name of names) {
    const value = rowIdentity(row, params, name);
    if (claimed !== undefined && claimed[name] !== value) throw failure();
    binding[name] = value;
  }
  return binding;
}

function accessBlockBinding(info, claimed) {
  // These existing logical records share one value across their event/IP/device
  // aliases. Bind the complete alias set so the authorized atomic IN update can
  // retain its original request shape and each returned row proves membership.
  const { row, params } = info, value = row.record_json;
  const id = value.block_id, keys = value.storage_keys;
  if (value.version !== 325 || typeof id !== 'string'
      || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(id)
      || !Array.isArray(keys) || ![3, 4].includes(keys.length)) throw failure();
  const prefix = 'customer-access-block-v325:', kinds = [];
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (typeof key !== 'string' || (index && keys[index - 1] >= key)) throw failure();
    if (key === prefix + 'event:' + id) kinds.push('event');
    else {
      const match = /^customer-access-block-v325:(account|ip|device):[a-f0-9]{64}:([a-f0-9-]{36})$/.exec(key);
      if (!match || match[2] !== id) throw failure();
      kinds.push(match[1]);
    }
  }
  if (kinds.slice().sort().join(',') !== (keys.length === 4 ? 'account,device,event,ip' : 'device,event,ip')) throw failure();
  const key = rowIdentity(row, params, 'security_key', false);
  if (key !== null && !keys.includes(key)) throw failure();
  const filter = params.get('security_key');
  let selected = null;
  if (filter && filter.startsWith('in.(') && filter.endsWith(')')) {
    selected = filter.slice(4, -1).split(',');
    if (!selected.length || selected.length > 40 || new Set(selected).size !== selected.length
        || selected.some(item => !/^[A-Za-z0-9:._-]{1,500}$/.test(item))) throw failure();
    if (key !== null && !selected.includes(key)) throw failure();
    if (!info.decode && selected.slice().sort().join(',') !== keys.join(',')) throw failure();
  }
  if (key === null && (info.decode || !selected)) throw failure();
  const binding = { block_id: id, storage_keys: keys.slice() };
  if (claimed !== undefined && (!record(claimed)
      || Object.keys(claimed).sort().join(',') !== 'block_id,storage_keys'
      || claimed.block_id !== id || !Array.isArray(claimed.storage_keys)
      || claimed.storage_keys.length !== keys.length
      || claimed.storage_keys.some((item, index) => item !== keys[index]))) throw failure();
  return binding;
}

function cryptValue(value, context, state, bindingInfo) {
  if (value === null) return null;
  const encrypted = record(value) && own(value, MARKER);
  if (state.decode && !encrypted) return value; // Legacy records remain readable.
  let plain, nonce, ciphertext, tag, aad;
  try {
    const bound = state.decode ? value[MARKER] === BOUND_VERSION : Boolean(bindingInfo);
    if (state.decode && (value[MARKER] !== VERSION && !bound)) throw failure();
    if (bound && !bindingInfo) throw failure();
    const binding = bound ? rowBinding(bindingInfo, state.decode ? value.binding : undefined) : null;
    aad = Buffer.from(JSON.stringify(bound
      ? ['dirac-json-storage-v2', context, binding] : ['dirac-json-storage-v1', context]), 'utf8');
    if (!state.key) state.key = deriveKey();
    if (!state.decode) {
      // Never trust an input envelope as already encrypted. It is plaintext
      // application input and receives a fresh outer authenticated envelope.
      plain = jsonBytes(value);
      state.bytes += plain.length;
      if (state.bytes > MAX_BATCH_BYTES) throw failure();
      nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', state.key, nonce, { authTagLength: 16 });
      cipher.setAAD(aad);
      ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
      tag = cipher.getAuthTag();
      return { [MARKER]: bound ? BOUND_VERSION : VERSION, ...(bound ? { binding } : {}),
        nonce: nonce.toString('base64'), data: ciphertext.toString('base64'), tag: tag.toString('base64') };
    }
    if (Object.keys(value).sort().join(',') !== (bound
      ? '_dirac_cipher,binding,data,nonce,tag' : '_dirac_cipher,data,nonce,tag')) throw failure();
    nonce = base64Bytes(value.nonce, 12, 12);
    ciphertext = base64Bytes(value.data, null, MAX_VALUE_BYTES);
    tag = base64Bytes(value.tag, 16, 16);
    state.bytes += ciphertext.length;
    if (state.bytes > MAX_BATCH_BYTES || ciphertext.length < 1) throw failure();
    const decipher = crypto.createDecipheriv('aes-256-gcm', state.key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const first = decipher.update(ciphertext);
    try { plain = Buffer.concat([first, decipher.final()]); }
    finally { first.fill(0); }
    const output = JSON.parse(plain.toString('utf8'));
    return output;
  } finally {
    for (const bytes of [plain, nonce, ciphertext, tag, aad]) if (bytes) bytes.fill(0);
  }
}

// DB1 optional envelope adapter. It does not silently duplicate plaintext,
// create a database record, or modify the original authorization contracts.
// Call sealDb1 only after the existing authorized owner-verified write path.
const DB1_VERSION = 'aes-256-gcm:hkdf-sha512:db1-v1';
const DB1_KID = 'root-v1';
const DB1_FIELD_ALLOWLIST = Object.freeze({
  customers: Object.freeze(['doc_id', 'name', 'phone', 'email', 'address', 'note']),
  orders: Object.freeze(['order_id', 'customer_name', 'customer_phone', 'customer_email', 'shipping_address', 'tracking_number', 'payment_proof_url', 'note']),
  order_items: Object.freeze(['product_title']),
  domain_orders: Object.freeze(['customer_name', 'customer_whatsapp', 'customer_email', 'customer_phone', 'owner_email', 'notes', 'customer_note', 'product_name']),
  payment_transactions: Object.freeze(['metadata', 'payment_url', 'gateway_reference']),
  payment_gateway_events: Object.freeze(['raw_payload', 'payload', 'metadata', 'error_message']),
  security_customer_auth_links: Object.freeze(['email', 'notes', 'metadata']),
  security_customer_events: Object.freeze(['event_title', 'event_description', 'description', 'ip_address', 'user_agent', 'device_name', 'metadata']),
  security_customer_login_logs: Object.freeze(['failure_reason', 'ip_address', 'user_agent', 'device_name', 'browser_name', 'operating_system', 'country', 'city', 'metadata']),
  security_customer_sessions: Object.freeze(['device_name', 'browser_name', 'operating_system', 'user_agent', 'ip_address', 'country', 'city', 'revoke_reason', 'metadata']),
  security_logs: Object.freeze(['detail', 'admin_email'])
});

function db1Identity(table, id) {
  if (!own(DB1_FIELD_ALLOWLIST, table) || typeof id !== 'string'
      || !UUID.test(id.toLowerCase())) throw failure();
  return id.toLowerCase();
}

function db1FieldObject(table, value) {
  if (!record(value)) throw failure();
  const keys = Object.keys(value);
  const allowed = DB1_FIELD_ALLOWLIST[table];
  if (!allowed || !keys.length || keys.length > allowed.length
      || keys.some(name => !allowed.includes(name)
        || ['__proto__', 'prototype', 'constructor'].includes(name))) throw failure();
  return value;
}

function deriveDb1Key() {
  const root = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '').trim();
  const production = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
  if (Buffer.byteLength(root, 'utf8') < (production ? 3000 : 32)) throw failure();
  const input = Buffer.from(root, 'utf8');
  try {
    return Buffer.from(crypto.hkdfSync('sha512', input,
      Buffer.from('dirac-db1-row-aes-gcm-v1', 'utf8'),
      Buffer.from('dirac-db1-hkdf-sha512-gcm-key-v1', 'utf8'), 32));
  } finally { input.fill(0); }
}

function db1AssociatedData(table, id) {
  return Buffer.from(JSON.stringify(['dirac-db1-row-v1', DB1_VERSION, DB1_KID,
    'public', table, id]), 'utf8');
}

function sealDb1(table, id, privateFields) {
  const uuid = db1Identity(table, id);
  db1FieldObject(table, privateFields);
  let key, plain, nonce, data, tag, aad;
  try {
    // Uses the same bounded JSON verifier as the existing protection module.
    plain = jsonBytes(privateFields);
    if (!plain.length) throw failure();
    key = deriveDb1Key();
    aad = db1AssociatedData(table, uuid);
    nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    const first = cipher.update(plain);
    try { data = Buffer.concat([first, cipher.final()]); }
    finally { first.fill(0); }
    tag = cipher.getAuthTag();
    return {
      version: DB1_VERSION, kid: DB1_KID,
      nonce: nonce.toString('base64'), tag: tag.toString('base64'),
      data: data.toString('base64'),
      binding: { schema: 'public', table, id: uuid }
    };
  } catch (_) { throw failure(); }
  finally {
    if (key) key.fill(0);
    if (plain) plain.fill(0);
    if (nonce) nonce.fill(0);
    if (data) data.fill(0);
    if (tag) tag.fill(0);
    if (aad) aad.fill(0);
  }
}

function openDb1(table, id, envelope) {
  const uuid = db1Identity(table, id);
  if (!record(envelope) || Object.keys(envelope).sort().join(',') !== 'binding,data,kid,nonce,tag,version'
      || envelope.version !== DB1_VERSION || envelope.kid !== DB1_KID
      || !record(envelope.binding)
      || Object.keys(envelope.binding).sort().join(',') !== 'id,schema,table'
      || envelope.binding.schema !== 'public' || envelope.binding.table !== table
      || envelope.binding.id !== uuid) throw failure();
  let key, nonce, ciphertext, tag, aad, plain;
  try {
    nonce = base64Bytes(envelope.nonce, 12, 12);
    tag = base64Bytes(envelope.tag, 16, 16);
    ciphertext = base64Bytes(envelope.data, null, MAX_VALUE_BYTES);
    if (ciphertext.length < 1) throw failure();
    key = deriveDb1Key();
    aad = db1AssociatedData(table, uuid);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const first = decipher.update(ciphertext);
    try { plain = Buffer.concat([first, decipher.final()]); }
    finally { first.fill(0); }
    if (plain.length > MAX_VALUE_BYTES) throw failure();
    const contents = db1FieldObject(table, JSON.parse(plain.toString('utf8')));
    // The authenticated JSON must also obey the legacy depth/node budget.
    const checked = jsonBytes(contents);
    checked.fill(0);
    return contents;
  } catch (_) { throw failure(); }
  finally {
    if (key) key.fill(0);
    if (nonce) nonce.fill(0);
    if (ciphertext) ciphertext.fill(0);
    if (tag) tag.fill(0);
    if (aad) aad.fill(0);
    if (plain) plain.fill(0);
  }
}

// Staged DB1 customer encryption primitives. The DB1 cutover must not begin
// until customer reads, authenticated lookup and the DB2 mirror are compatible.
// A blind index never contains the plaintext and is cryptographically distinct
// from the AEAD key. No new configuration secret is required.
function db1CustomerBlindIndex(kind, source) {
  if (kind !== 'email' && kind !== 'phone') throw failure();
  if (source === null || source === undefined || source === '') return null;
  if (typeof source !== 'string') throw failure();
  const normalized = kind === 'email'
    ? source.trim().toLowerCase()
    : source.replace(/[^0-9]/g, '');
  if (kind === 'email'
    ? (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)
      || Buffer.byteLength(normalized, 'utf8') > 320)
    : !/^[0-9]{10,20}$/.test(normalized)) throw failure();
  const root = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '').trim();
  const production = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
  if (Buffer.byteLength(root, 'utf8') < (production ? 3000 : 32)) throw failure();
  const input = Buffer.from(root, 'utf8');
  let key;
  try {
    key = Buffer.from(crypto.hkdfSync('sha512', input,
      Buffer.from('dirac-db1-blind-index-v1', 'utf8'),
      Buffer.from('dirac-db1-' + kind + '-hmac-sha256-v1', 'utf8'), 32));
    return crypto.createHmac('sha256', key).update(normalized, 'utf8').digest('hex');
  } catch (_) { throw failure(); }
  finally { input.fill(0); if (key) key.fill(0); }
}

function sealDb1CustomerProfile(id, privateFields) {
  db1Identity('customers', id);
  db1FieldObject('customers', privateFields);
  if (typeof privateFields.name !== 'string' || privateFields.name.trim().length < 3
      || (!privateFields.email && !privateFields.phone)) throw failure();
  const emailHmac = db1CustomerBlindIndex('email', privateFields.email);
  const phoneHmac = db1CustomerBlindIndex('phone', privateFields.phone);
  return {
    dirac_cipher_gcm_v1: sealDb1('customers', id, privateFields),
    dirac_email_hmac_v1: emailHmac,
    dirac_phone_hmac_v1: phoneHmac
  };
}

function decodeDb1Row(table, row) {
  if (!record(row) || row.dirac_cipher_gcm_v1 === null
      || !own(row, 'dirac_cipher_gcm_v1')) return row;
  // Fail closed: an encrypted value must be authenticated with the actual
  // primary key supplied by the database, never solely the claimed binding.
  const privateFields = openDb1(table, row.id, row.dirac_cipher_gcm_v1);
  const { dirac_cipher_gcm_v1: _ciphertext, ...safeRow } = row;
  // Do not widen the authorized PostgREST SELECT projection. A field whose
  // name was not selected by the caller must remain absent from the result.
  const projected = Object.fromEntries(Object.keys(privateFields)
    .filter(name => own(row, name)).map(name => [name, privateFields[name]]));
  return { ...safeRow, ...projected };
}

function securityKey(row, params) {
  const values = params.getAll('security_key');
  const predicate = values.length === 1 && values[0].startsWith('eq.') ? values[0].slice(3) : '';
  const key = typeof row.security_key === 'string' ? row.security_key : predicate;
  if (predicate && key && predicate !== key) throw failure();
  return key;
}

function banRecord(value, key, bindingInfo, state) {
  if (!record(value)) return value;
  const compact = value.storage_version === 501 || String(key || '').startsWith('global-ban-active:bundle:');
  if (compact && (!COMPACT_BAN_KEY.test(String(key || '')) || value.storage_version !== 501
      || value.type !== 'central_guard_global_ban_v146' || key !== 'global-ban-active:bundle:' + value.ban_id)) throw failure();
  if (own(value, PRIVATE_METADATA)) {
    const envelope = value[PRIVATE_METADATA];
    if (!state.decode || !record(envelope) || envelope[MARKER] !== BOUND_VERSION
        || BAN_IDENTITY_FIELDS.some(name => own(value, name) && value[name] !== null && value[name] !== '')
        || (compact && own(value, 'entries'))
        || Object.keys(BAN_NESTED_FIELDS).some(section => record(value[section])
          && BAN_NESTED_FIELDS[section].some(name => own(value[section], name)
            && value[section][name] !== null && value[section][name] !== ''))) throw failure();
    const privateFields = cryptValue(envelope, ['dirac_persistent_bans', 'record_json', PRIVATE_METADATA], state, bindingInfo);
    if (!record(privateFields) || !Object.keys(privateFields).length
        || Object.keys(privateFields).some(name => !BAN_IDENTITY_FIELDS.includes(name)
          && !own(BAN_NESTED_FIELDS, name) && !(compact && name === 'entries'))
        || BAN_IDENTITY_FIELDS.some(name => own(privateFields, name) && own(value, name))
        || (compact && (!Array.isArray(privateFields.entries) || privateFields.entries.length < 1 || privateFields.entries.length > 128))) throw failure();
    const restored = { ...value, ...privateFields };
    for (const section of Object.keys(BAN_NESTED_FIELDS)) {
      if (!own(privateFields, section)) continue;
      const nested = privateFields[section];
      if (!record(nested) || !Object.keys(nested).length || !record(value[section])
          || Object.keys(nested).some(name => !BAN_NESTED_FIELDS[section].includes(name) || own(value[section], name))) throw failure();
      restored[section] = { ...value[section], ...nested };
    }
    delete restored[PRIVATE_METADATA];
    return restored;
  }
  if (state.decode) {
    // v1 email envelopes belong only to the separately bound reset-mail record.
    if (BAN_IDENTITY_FIELDS.some(name => record(value[name]) && own(value[name], MARKER))
        || Object.keys(BAN_NESTED_FIELDS).some(section => record(value[section])
          && BAN_NESTED_FIELDS[section].some(name => record(value[section][name]) && own(value[section][name], MARKER)))) throw failure();
    return value;
  }
  const privateFields = {};
  for (const name of BAN_IDENTITY_FIELDS) {
    if (own(value, name) && value[name] !== null && value[name] !== '') privateFields[name] = value[name];
  }
  for (const section of Object.keys(BAN_NESTED_FIELDS)) {
    if (!record(value[section])) continue;
    const nested = {};
    for (const name of BAN_NESTED_FIELDS[section]) {
      if (own(value[section], name) && value[section][name] !== null && value[section][name] !== '') nested[name] = value[section][name];
    }
    if (Object.keys(nested).length) privateFields[section] = nested;
  }
  if (compact) {
    if (!Array.isArray(value.entries) || value.entries.length < 1 || value.entries.length > 128) throw failure();
    privateFields.entries = value.entries;
  }
  if (!Object.keys(privateFields).length) return value;
  const envelope = cryptValue(privateFields, ['dirac_persistent_bans', 'record_json', PRIVATE_METADATA], state, bindingInfo);
  const output = { ...value, [PRIVATE_METADATA]: envelope };
  for (const name of Object.keys(privateFields)) {
    if (own(BAN_NESTED_FIELDS, name)) {
      output[name] = { ...value[name] };
      for (const field of Object.keys(privateFields[name])) delete output[name][field];
    } else delete output[name];
  }
  return output;
}

// Preserve the existing text envelope for private display fields. Numeric and
// status inputs used by the financial guards are not passed to this helper.
const DB1_AUDIT_TEXT_PREFIX = 'dirac-aes256gcm-text-v1:';
function cryptDb1AuditText(value, table, name, state) {
  if (value === null) return value;
  if (typeof value !== 'string') throw failure();
  const context = ['dirac-db1-audit-text-v1', table, name];
  if (!state.decode) {
    if (!value) return value;
    return DB1_AUDIT_TEXT_PREFIX + JSON.stringify(cryptValue(value, context, state));
  }
  if (!value.startsWith(DB1_AUDIT_TEXT_PREFIX)) return value; // Existing plaintext rows.
  if (Buffer.byteLength(value, 'utf8') > Math.ceil(MAX_VALUE_BYTES / 3) * 4 + 2048) throw failure();
  let envelope;
  try { envelope = JSON.parse(value.slice(DB1_AUDIT_TEXT_PREFIX.length)); }
  catch (_) { throw failure(); }
  if (!record(envelope) || envelope[MARKER] !== VERSION) throw failure();
  const plain = cryptValue(envelope, context, state);
  if (typeof plain !== 'string') throw failure();
  return plain;
}

// Recoverable order codes use random-nonce AEAD. The separate keyed index
// supports exact lookup without revealing the code or using deterministic GCM.
const ORDER_CODE_PREFIX_V1 = 'dirac-aes256gcm-code-v1:';
const REFERENCE_STORAGE_V1 = Object.freeze({
  orders: Object.freeze({ field: 'order_id', index: 'dirac_order_hmac_v1', prefix: ORDER_CODE_PREFIX_V1, salt: 'dirac-order-code-index-v1' }),
  payment_transactions: Object.freeze({ field: 'gateway_reference', index: 'dirac_gateway_hmac_v1', prefix: 'dirac-aes256gcm-ref-v1:', salt: 'dirac-gateway-reference-index-v1' })
});
function referenceHmacV1(table, value) {
  const spec = REFERENCE_STORAGE_V1[table];
  if (!spec) throw failure();
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:@-]{3,120}$/.test(value)
      || value.startsWith(spec.prefix)) throw failure();
  const root = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '').trim();
  const production = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
  if (Buffer.byteLength(root, 'utf8') < (production ? 3000 : 32)) throw failure();
  const input = Buffer.from(root, 'utf8');
  let key;
  try {
    key = Buffer.from(crypto.hkdfSync('sha512', input,
      Buffer.from(spec.salt, 'utf8'),
      Buffer.from('public.' + table + '.' + spec.field + ':hmac-sha256:v1', 'utf8'), 32));
    return crypto.createHmac('sha256', key).update(value, 'utf8').digest('hex');
  } finally { input.fill(0); if (key) key.fill(0); }
}

function orderCodeHmacV1(value) { return referenceHmacV1('orders', value); }

function ensureStorageRowIdentityV1(row, params, state) {
  let id = rowIdentity(row, params, 'id', false);
  if (id === null) {
    if (state.method !== 'POST' || params.has('id') || params.has('order_id')
        || params.has('gateway_reference') || params.has('or') || params.has('and')) throw failure();
    id = crypto.randomUUID();
  }
  return { id, row: own(row, 'id') || state.method !== 'POST' ? row : { ...row, id } };
}

function protectStoredReferenceV1(table, row, params, state) {
  const spec = REFERENCE_STORAGE_V1[table];
  const name = spec.field;
  if (!own(row, name) || row[name] === null) return row;
  if (state.decode) {
    if (typeof row[name] !== 'string') throw failure();
    if (!row[name].startsWith(spec.prefix)) return row;
    const tail = row[name].slice(spec.prefix.length);
    const match = /^([a-f0-9]{64}):([A-Za-z0-9+/]+={0,2})$/.exec(tail);
    if (!match || tail.length > 2048) throw failure();
    const bytes = base64Bytes(match[2], null, 1400);
    let envelope;
    try { envelope = JSON.parse(bytes.toString('utf8')); }
    finally { bytes.fill(0); }
    const id = rowIdentity(row, params, 'id', false);
    const claimedId = envelope && envelope.binding && envelope.binding.id;
    if (id !== null && claimedId !== id) throw failure();
    const fields = openDb1(table, id || claimedId, envelope);
    if (Object.keys(fields).join(',') !== name) throw failure();
    const expected = referenceHmacV1(table, fields[name]);
    if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(match[1], 'hex'))) throw failure();
    return { ...row, [name]: fields[name] };
  }
  const index = referenceHmacV1(table, row[name]);
  // Give a new INSERT its ordinary UUID before AEAD binds to it. Never
  // invent an identity for an UPDATE or change an existing primary key.
  const identity = ensureStorageRowIdentityV1(row, params, state);
  const envelope = sealDb1(table, identity.id, { [name]: row[name] });
  const bytes = jsonBytes(envelope);
  try {
    state.bytes += bytes.length;
    if (state.bytes > MAX_BATCH_BYTES) throw failure();
    return { ...identity.row, [name]: spec.prefix + index + ':' + bytes.toString('base64') };
  } finally { bytes.fill(0); }
}

function referencePredicateV1(table, operator, value) {
  const spec = REFERENCE_STORAGE_V1[table];
  if (operator === 'eq') {
    return 'or(' + spec.field + '.eq.' + value + ',' + spec.index + '.eq.' + referenceHmacV1(table, value) + ')';
  }
  if (operator === 'in') {
    if (value.length > 12000 || !value.startsWith('(') || !value.endsWith(')')) throw failure();
    const codes = value.slice(1, -1).split(',');
    if (!codes.length || codes.length > 100) throw failure();
    return 'or(' + spec.field + '.in.' + value + ',' + spec.index + '.in.('
      + codes.map(code => referenceHmacV1(table, code)).join(',') + '))';
  }
  throw failure();
}

function referenceFilterV1(table, value) {
  const spec = REFERENCE_STORAGE_V1[table];
  if (typeof value !== 'string' || value.length > 24576) throw failure();
  if (new RegExp('(?:^|[,(])' + spec.index + '\\.').test(value)) throw failure();
  // The rest of each already-authorized expression is copied verbatim.
  // Only exact root order-code predicates receive an equivalent keyed lookup.
  const exact = new RegExp('(^|[,(])' + spec.field + '\\.(eq)\\.([A-Za-z0-9._:@-]{3,120})(?=[,)])', 'g');
  const output = value.replace(exact,
    (_, before, operator, code) => before + referencePredicateV1(table, operator, code));
  const withoutExact = value.replace(exact, '$1');
  if (new RegExp('(?:^|[,(])' + spec.field + '\\.').test(withoutExact)) throw failure();
  return output;
}

// Physical order rows retain the existing per-field ciphertext. This adapter
// changes storage shape only after the original authorization/egress permit.
const ITEM_BUNDLE_V1 = 'dirac_item_bundle_v1';
const ITEM_PHYSICAL_COUNTS_V1 = new WeakMap();
const ITEM_FIELDS_V1 = Object.freeze(['id', 'order_id', 'customer_id', 'product_doc_id',
  'product_title', 'quantity', 'unit_price', 'cost_price', 'line_total', 'created_at',
  'shipping_weight_grams', 'shipping_length_cm', 'shipping_width_cm', 'shipping_height_cm']);
function itemNumberV1(value, integer = true) {
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^[0-9]+(?:\.[0-9]+)?$/.test(value))) throw failure();
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0 || (integer && !Number.isSafeInteger(number))) throw failure();
  return number;
}
function itemBundleLinesV1(items, parent, customer, allowDefaults) {
  if (!Array.isArray(items) || !items.length || items.length > MAX_ROWS || !UUID.test(parent)) throw failure();
  const ids = new Set(), owners = new Set();
  const lines = items.map(source => {
    if (!record(source) || Object.keys(source).some(name => !ITEM_FIELDS_V1.includes(name) && name !== 'dirac_cipher_gcm_v1')
        || source.order_id !== parent || typeof source.product_title !== 'string'
        || !source.product_title.startsWith(DB1_AUDIT_TEXT_PREFIX)) throw failure();
    const row = { ...source };
    if (allowDefaults && !own(row, 'id')) row.id = crypto.randomUUID();
    if (typeof row.id !== 'string' || !UUID.test(row.id) || ids.has(row.id)) throw failure();
    ids.add(row.id);
    if (row.customer_id !== undefined && row.customer_id !== null) {
      if (typeof row.customer_id !== 'string' || !UUID.test(row.customer_id)) throw failure();
      owners.add(row.customer_id);
      if (customer && row.customer_id !== customer) throw failure();
    }
    const qty = itemNumberV1(row.quantity), price = itemNumberV1(row.unit_price ?? 0), cost = itemNumberV1(row.cost_price ?? 0);
    if (qty < 1 || qty > 999 || !Number.isSafeInteger(qty * price) || !Number.isSafeInteger(qty * cost)) throw failure();
    const weight = itemNumberV1(row.shipping_weight_grams);
    const dimensions = ['shipping_length_cm', 'shipping_width_cm', 'shipping_height_cm'].map(name => itemNumberV1(row[name], false));
    if (weight < 1 || weight > 50000 || dimensions.some(value => value <= 0 || value > 200)) throw failure();
    if (row.product_doc_id !== undefined && row.product_doc_id !== null && typeof row.product_doc_id !== 'string') throw failure();
    if (row.line_total !== undefined && row.line_total !== null && itemNumberV1(row.line_total) !== qty * price) throw failure();
    if (row.created_at !== undefined && row.created_at !== null
        && (typeof row.created_at !== 'string' || !Number.isFinite(Date.parse(row.created_at)))) throw failure();
    if (allowDefaults && !row.created_at) row.created_at = new Date().toISOString();
    return row;
  });
  if (owners.size > 1) throw failure();
  return lines;
}
function encodeItemBundlesV1(rows, state) {
  const groups = new Map(), itemIds = new Set();
  rows.forEach(row => {
    if (!record(row) || typeof row.order_id !== 'string' || !UUID.test(row.order_id) || own(row, ITEM_BUNDLE_V1)) throw failure();
    const group = groups.get(row.order_id) || [];
    group.push(row); groups.set(row.order_id, group);
  });
  return Array.from(groups, ([orderId, values]) => {
    const lines = itemBundleLinesV1(values, orderId, null, true), first = lines[0];
    lines.forEach(line => { if (itemIds.has(line.id)) throw failure(); itemIds.add(line.id); });
    const price = lines.reduce((sum, line) => sum + itemNumberV1(line.quantity) * itemNumberV1(line.unit_price ?? 0), 0);
    const cost = lines.reduce((sum, line) => sum + itemNumberV1(line.quantity) * itemNumberV1(line.cost_price ?? 0), 0);
    if (!Number.isSafeInteger(price) || !Number.isSafeInteger(cost)) throw failure();
    const bundle = { version: 1, order_id: orderId, items: lines };
    const bytes = jsonBytes(bundle);
    try { state.bytes += bytes.length; if (state.bytes > MAX_BATCH_BYTES) throw failure(); } finally { bytes.fill(0); }
    const physical = { ...first, id: orderId, quantity: 1, unit_price: price, cost_price: cost,
      product_doc_id: null, [ITEM_BUNDLE_V1]: bundle };
    // line_total is generated by PostgreSQL where present.
    delete physical.line_total;
    return physical;
  });
}
function decodeItemBundlesV1(rows, params, state) {
  let expanded = 0;
  const itemIds = new Set();
  const fields = params.get('select');
  const selected = !fields || fields === '*' ? null : fields.split(',');
  if (selected && selected.some(name => !ITEM_FIELDS_V1.includes(name))) throw failure();
  const output = rows.flatMap(physical => {
    if (!record(physical)) throw failure();
    let lines = [physical];
    if (physical[ITEM_BUNDLE_V1] !== undefined && physical[ITEM_BUNDLE_V1] !== null) {
      const bundle = physical[ITEM_BUNDLE_V1];
      if (!record(bundle) || Object.keys(bundle).sort().join(',') !== 'items,order_id,version'
          || bundle.version !== 1 || physical.id !== physical.order_id || bundle.order_id !== physical.order_id) throw failure();
      const bytes = jsonBytes(bundle);
      try { state.bytes += bytes.length; if (state.bytes > MAX_BATCH_BYTES) throw failure(); } finally { bytes.fill(0); }
      lines = itemBundleLinesV1(bundle.items, physical.order_id, physical.customer_id || null, false);
      const ownerFilter = params.get('customer_id');
      const allowedOwners = ownerFilter && ownerFilter.startsWith('eq.') ? [ownerFilter.slice(3)]
        : ownerFilter && /^in\.\([a-f0-9,-]+\)$/.test(ownerFilter) ? ownerFilter.slice(4, -1).split(',') : null;
      if (allowedOwners && lines.some(line => !allowedOwners.includes(line.customer_id || physical.customer_id))) throw failure();
      const total = lines.reduce((sum, line) => sum + itemNumberV1(line.quantity) * itemNumberV1(line.unit_price ?? 0), 0);
      const cost = lines.reduce((sum, line) => sum + itemNumberV1(line.quantity) * itemNumberV1(line.cost_price ?? 0), 0);
      if (!Number.isSafeInteger(total) || !Number.isSafeInteger(cost)
          || (own(physical, 'quantity') && Number(physical.quantity) !== 1)
          || (own(physical, 'unit_price') && itemNumberV1(physical.unit_price) !== total)
          || (own(physical, 'cost_price') && itemNumberV1(physical.cost_price) !== cost)) throw failure();
    }
    expanded += lines.length;
    if (expanded > 4000) throw failure();
    return lines.map(line => {
      const row = { ...line };
      if (row.id !== undefined) { if (itemIds.has(row.id)) throw failure(); itemIds.add(row.id); }
      delete row[ITEM_BUNDLE_V1];
      if (row.customer_id === undefined && own(physical, 'customer_id')) row.customer_id = physical.customer_id;
      if (row.created_at === undefined && own(physical, 'created_at')) row.created_at = physical.created_at;
      if (physical[ITEM_BUNDLE_V1]) {
        if (!own(row, 'product_doc_id') && own(physical, 'product_doc_id')) row.product_doc_id = null;
        if (!own(row, 'cost_price') && own(physical, 'cost_price')) row.cost_price = 0;
        if (!own(row, 'line_total') && own(physical, 'line_total')) row.line_total = itemNumberV1(row.quantity) * itemNumberV1(row.unit_price ?? 0);
      }
      const decoded = transformRow('order_items', row, params, state);
      if (physical[ITEM_BUNDLE_V1] && (typeof decoded.product_title !== 'string' || !decoded.product_title || decoded.product_title.length > 180)) throw failure();
      return selected ? Object.fromEntries(selected.filter(name => own(decoded, name)).map(name => [name, decoded[name]])) : decoded;
    });
  });
  ITEM_PHYSICAL_COUNTS_V1.set(output, rows.length);
  return output;
}
function itemStoragePathV1(path) {
  const match = /^\/rest\/v1\/order_items(?:\?([^#]*))?$/.exec(path);
  if (!match || !match[1]) return path;
  const params = new URLSearchParams(match[1]);
  if (params.getAll('select').length > 1) throw failure();
  const fields = params.get('select');
  if (!fields || fields === '*') return path;
  const selected = fields.split(',');
  if (selected.some(name => !ITEM_FIELDS_V1.includes(name))) throw failure();
  // Added fields are validated storage metadata and stripped before return.
  params.set('select', Array.from(new Set([...selected, 'id', 'order_id', 'quantity', 'unit_price', 'cost_price', ITEM_BUNDLE_V1])).join(','));
  return '/rest/v1/order_items?' + params.toString();
}

function storagePathV1(path) {
  if (typeof path !== 'string' || path.length > 24576) throw failure();
  if (/^\/rest\/v1\/order_items(?:\?|$)/.test(path)) return itemStoragePathV1(path);
  const match = /^\/rest\/v1\/(orders|payment_transactions)(?:\?([^#]*))?$/.exec(path);
  if (!match || !match[2]) return path;
  const table = match[1], spec = REFERENCE_STORAGE_V1[table];
  const params = new URLSearchParams(match[2]);
  if (params.has(spec.index) || params.getAll(spec.field).length > 1
      || params.getAll('and').length > 1 || params.getAll('or').length > 1) throw failure();
  let changed = false;
  ['and', 'or'].forEach(name => {
    if (!params.has(name)) return;
    const prior = params.get(name), next = referenceFilterV1(table, prior);
    if (next !== prior) { params.set(name, next); changed = true; }
  });
  if (params.has(spec.field)) {
    const predicate = params.get(spec.field);
    if (predicate !== 'is.null' && predicate !== 'not.is.null') {
      const part = /^(eq|in)\.(.+)$/.exec(predicate);
      if (!part) throw failure();
      const next = referencePredicateV1(table, part[1], part[2]);
      const prior = params.get('and');
      if (prior && (!prior.startsWith('(') || !prior.endsWith(')'))) throw failure();
      params.delete(spec.field);
      params.set('and', '(' + (prior ? prior.slice(1, -1) + ',' : '') + next + ')');
      changed = true;
    }
  }
  const output = changed ? '/rest/v1/' + table + '?' + params.toString() : path;
  if (output.length > 49152) throw failure();
  return output;
}

const PAYMENT_PRIVATE_METADATA_V1 = Object.freeze([
  'order_code', 'items', 'product_title', 'product_name', 'customer_name',
  'customer_email', 'customer_phone', 'email', 'name', 'phone', 'address',
  'shipping_address', 'message', 'note', 'gateway_invoice_id'
]);
const PAYMENT_CODE_INDEX_PREFIX_V1 = 'dirac-order-hmac-v1:';
function paymentMetadataV1(value, bindingInfo, state) {
  if (!record(value)) return value;
  const context = ['payment_transactions', 'metadata', PRIVATE_METADATA];
  let output = value;
  if (own(value, 'gateway_raw')) {
    output = { ...output, gateway_raw: cryptValue(value.gateway_raw,
      ['payment_transactions', 'metadata', 'gateway_raw'], state, bindingInfo) };
  }
  if (state.decode) {
    if (!own(value, PRIVATE_METADATA)) return output;
    const envelope = value[PRIVATE_METADATA];
    if (!record(envelope) || envelope[MARKER] !== BOUND_VERSION) throw failure();
    const fields = cryptValue(envelope, context, state, bindingInfo);
    if (!record(fields) || !Object.keys(fields).length
        || Object.keys(fields).some(name => !PAYMENT_PRIVATE_METADATA_V1.includes(name)
          || (name !== 'order_code' && own(value, name)))) throw failure();
    if (own(fields, 'order_code')) {
      const code = fields.order_code;
      if (code !== null && code !== '' && (typeof code !== 'string' || code.length > 100)) throw failure();
      const expected = code === null || code === '' ? code : PAYMENT_CODE_INDEX_PREFIX_V1 + orderCodeHmacV1(code);
      if (value.order_code !== expected) throw failure();
    }
    output = { ...output, ...fields };
    delete output[PRIVATE_METADATA];
    return output;
  }
  if (own(value, PRIVATE_METADATA)) throw failure();
  const fields = Object.fromEntries(PAYMENT_PRIVATE_METADATA_V1.filter(name => own(value, name))
    .map(name => [name, value[name]]));
  if (!Object.keys(fields).length) return output;
  const envelope = cryptValue(fields, context, state, bindingInfo);
  output = { ...output, [PRIVATE_METADATA]: envelope };
  Object.keys(fields).forEach(name => { delete output[name]; });
  if (own(fields, 'order_code')) {
    const code = fields.order_code;
    if (code !== null && code !== '' && (typeof code !== 'string' || code.length > 100)) throw failure();
    // The unchanged laboratory SQL attestation requires a nonempty <=100-char
    // code, not its display value. Keep a keyed commitment and seal the value.
    output.order_code = code === null || code === '' ? code : PAYMENT_CODE_INDEX_PREFIX_V1 + orderCodeHmacV1(code);
  }
  return output;
}

function transformRow(table, row, params, state) {
  if (!record(row)) return row;
  let output = own(REFERENCE_STORAGE_V1, table) ? protectStoredReferenceV1(table, row, params, state) : row;
  if (table === 'payment_transactions' && !state.decode && record(row.metadata)
      && PAYMENT_PRIVATE_METADATA_V1.some(name => own(row.metadata, name))) {
    output = ensureStorageRowIdentityV1(output, params, state).row;
  }
  const bindingInfo = { table, row: output, params, decode: state.decode };
  const field = (name, value, context, bind) => {
    const next = cryptValue(value, context, state, bind ? bindingInfo : undefined);
    if (next !== value) { if (output === row) output = { ...row }; output[name] = next; }
  };
  const auditText = name => {
    if (!own(row, name)) return;
    const next = cryptDb1AuditText(row[name], table, name, state);
    if (next !== row[name]) { if (output === row) output = { ...row }; output[name] = next; }
  };
  // Orders and items have the same storage protection on both databases.
  // Identity/authentication fields retain their existing authorization contract.
  if (state.decode || state.businessText || table === 'orders' || table === 'order_items') {
    if (table === 'customers') {
      auditText('name');
      auditText('phone');
      auditText('address');
      auditText('note');
    } else if (table === 'orders') {
      auditText('customer_name');
      auditText('customer_phone');
      auditText('customer_email');
      auditText('shipping_address');
      auditText('tracking_number');
      auditText('payment_proof_url');
      auditText('note');
      if (own(row, 'shipping_breakdown')) field('shipping_breakdown', row.shipping_breakdown, [table, 'shipping_breakdown']);
    } else if (table === 'order_items') {
      auditText('product_title');
    } else if (table === 'domain_orders') {
      auditText('customer_name');
      auditText('customer_whatsapp');
      auditText('customer_phone');
      auditText('notes');
      auditText('customer_note');
      auditText('product_name');
    }
  }
  if (state.decode && table === 'security_customer_auth_links' && own(row, 'customer')) {
    if (record(row.customer)) output = { ...output, customer: transformRow('customers', row.customer, params, state) };
    else if (Array.isArray(row.customer)) {
      if (row.customer.length > MAX_ROWS) throw failure();
      output = { ...output, customer: row.customer.map(item => transformRow('customers', item, params, state)) };
    }
  }
  if (table === 'security_customer_events') {
    auditText('event_title');
    auditText('description');
    auditText('event_description');
    auditText('user_agent');
    auditText('device_name');
    if (own(row, 'metadata')) field('metadata', row.metadata, [table, 'metadata']);
  } else if (table === 'security_customer_login_logs') {
    auditText('failure_reason');
    auditText('user_agent');
    auditText('device_name');
    auditText('browser_name');
    auditText('operating_system');
    auditText('country');
    auditText('city');
    if (own(row, 'metadata')) field('metadata', row.metadata, [table, 'metadata']);
  }
  if (table === 'payment_gateway_events') {
    auditText('error_message');
    for (const name of ['payload', 'raw_payload']) if (own(row, name)) field(name, row[name], [table, name], true);
  } else if (table === 'payment_transactions') {
    auditText('payment_url');
    if (record(row.metadata)) output = { ...output, metadata: paymentMetadataV1(row.metadata, bindingInfo, state) };
  } else if (table === 'security_customer_account_requests') {
    if (record(row.metadata)) {
      let metadata = row.metadata;
      if (own(metadata, PRIVATE_METADATA)) {
        const envelope = metadata[PRIVATE_METADATA];
        if (!state.decode || !record(envelope) || envelope[MARKER] !== BOUND_VERSION
            || SENSITIVE_METADATA.some(name => own(metadata, name))) throw failure();
        const restored = cryptValue(envelope, [table, 'metadata', PRIVATE_METADATA], state, bindingInfo);
        if (!record(restored) || !Object.keys(restored).length
            || Object.keys(restored).some(name => !SENSITIVE_METADATA.includes(name))) throw failure();
        metadata = { ...metadata, ...restored };
        delete metadata[PRIVATE_METADATA];
      } else if (state.decode) {
        // Read existing v1 per-field envelopes without requiring new row bindings.
        for (const name of SENSITIVE_METADATA) {
          if (!own(row.metadata, name)) continue;
          const next = cryptValue(row.metadata[name], [table, 'metadata', name], state);
          if (next !== row.metadata[name]) {
            if (metadata === row.metadata) metadata = { ...row.metadata };
            metadata[name] = next;
          }
        }
      } else {
        const privateFields = {};
        for (const name of SENSITIVE_METADATA) {
          if (!own(row.metadata, name)) continue;
          privateFields[name] = row.metadata[name];
        }
        if (Object.keys(privateFields).length) {
          const envelope = cryptValue(privateFields, [table, 'metadata', PRIVATE_METADATA], state, bindingInfo);
          metadata = { ...row.metadata, [PRIVATE_METADATA]: envelope };
          for (const name of Object.keys(privateFields)) delete metadata[name];
        }
      }
      if (metadata !== row.metadata) output = { ...row, metadata };
    }
  } else if (own(row, 'record_json')) {
    const key = securityKey(row, params), value = row.record_json;
    if (table === 'dirac_s2s_security' && SHIPMENT_KEY.test(key)) {
      if (!record(value) || (!state.decode && value.schema !== 'dirac.admin_shipment.v406')) throw failure();
      field('record_json', value, [table, 'record_json', key]);
    } else if (table === 'dirac_persistent_bans' && RESET_KEY.test(key)) {
      if (!record(value) || value.type !== 'password_reset_committed_v338') throw failure();
      if (own(value, 'email')) {
        const email = cryptValue(value.email, [table, 'record_json', 'email', key], state);
        if (email !== value.email) output = { ...row, record_json: { ...value, email } };
      }
    } else if (table === 'dirac_persistent_bans' && record(value) && !own(value, MARKER)) {
      const protectedRecord = banRecord(value, key, bindingInfo, state);
      if (protectedRecord !== value) output = { ...row, record_json: protectedRecord };
    } else if (state.decode && record(value) && (own(value, MARKER)
        || (record(value.email) && own(value.email, MARKER)))) {
      // A protected security record without its expected binding cannot be
      // safely interpreted as legacy plaintext or an unrelated record.
      throw failure();
    }
  }
  if (state.decode && own(REFERENCE_STORAGE_V1, table) && own(output, REFERENCE_STORAGE_V1[table].index)) {
    output = { ...output };
    delete output[REFERENCE_STORAGE_V1[table].index];
  }
  return state.decode && own(DB1_FIELD_ALLOWLIST, table) ? decodeDb1Row(table, output) : output;
}

function transform(path, input, decode, businessText = false, method = 'POST') {
  const state = { decode, businessText: businessText === true, method, key: null, bytes: 0 };
  try {
    const match = typeof path === 'string' && /^\/rest\/v1\/([a-z0-9_]+)(?:\?([^#]*))?$/.exec(path);
    if (!match || !TABLES.has(match[1]) || input === null || input === undefined) return input;
    const params = new URLSearchParams(match[2] || '');
    if (match[1] === 'order_items') {
      const rows = Array.isArray(input) ? input : [input];
      if (rows.length > MAX_ROWS) throw failure();
      if (decode) return Array.isArray(input) ? decodeItemBundlesV1(rows, params, state) : decodeItemBundlesV1(rows, params, state)[0];
      if (method === 'POST') {
        if (rows.some(row => !record(row) || typeof row.product_title !== 'string' || !row.product_title || row.product_title.length > 180)) throw failure();
        const stored = rows.map(row => transformRow(match[1], row, params, state));
        const bundled = encodeItemBundlesV1(stored, state);
        return Array.isArray(input) ? bundled : bundled[0];
      }
    }
    if (!Array.isArray(input)) return transformRow(match[1], input, params, state);
    if (input.length > MAX_ROWS) throw failure();
    return input.map(row => transformRow(match[1], row, params, state));
  } catch (_) { throw failure(); }
  finally { if (state.key) state.key.fill(0); }
}

module.exports = Object.freeze({
  encode: (path, body, businessText = false, method = 'POST') => transform(path, body, false, businessText, method),
  decode: (path, response) => transform(path, response, true),
  storagePathV1,
  physicalRowCountV1: rows => ITEM_PHYSICAL_COUNTS_V1.has(rows) ? ITEM_PHYSICAL_COUNTS_V1.get(rows) : Array.isArray(rows) ? rows.length : 0,
  orderCodeHmacV1,
  gatewayReferenceHmacV1: value => referenceHmacV1('payment_transactions', value),
  sealDb1, openDb1,
  sealDb1CustomerProfile,
  customerEmailHmacV1: value => db1CustomerBlindIndex('email', value),
  customerPhoneHmacV1: value => db1CustomerBlindIndex('phone', value)
});

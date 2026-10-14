'use strict';

// Storage boundary only. Call encode after authorization, and decode before
// response validation. This module never performs I/O, retries, or migrations.
const crypto = require('crypto');
const textProtection = require('./text-protection.js');
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
  'security_customer_account_requests', 'dirac_persistent_bans', 'dirac_s2s_security']);
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

function transformRow(table, row, params, state) {
  if (!record(row)) return row;
  let output = row;
  const bindingInfo = { table, row, params, decode: state.decode };
  const field = (name, value, context, bind) => {
    const next = cryptValue(value, context, state, bind ? bindingInfo : undefined);
    if (next !== value) { if (output === row) output = { ...row }; output[name] = next; }
  };
  if (table === 'payment_gateway_events') {
    for (const name of ['payload', 'raw_payload']) if (own(row, name)) field(name, row[name], [table, name], true);
  } else if (table === 'payment_transactions') {
    if (record(row.metadata) && own(row.metadata, 'gateway_raw')) {
      const next = cryptValue(row.metadata.gateway_raw, [table, 'metadata', 'gateway_raw'], state, bindingInfo);
      if (next !== row.metadata.gateway_raw) output = { ...row, metadata: { ...row.metadata, gateway_raw: next } };
    }
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
  return output;
}

function transform(path, input, decode) {
  const state = { decode, key: null, bytes: 0 };
  try {
    const match = typeof path === 'string' && /^\/rest\/v1\/([a-z0-9_]+)(?:\?([^#]*))?$/.exec(path);
    if (!match || !TABLES.has(match[1]) || input === null || input === undefined) return input;
    const params = new URLSearchParams(match[2] || '');
    if (!Array.isArray(input)) return transformRow(match[1], input, params, state);
    if (input.length > MAX_ROWS) throw failure();
    return input.map(row => transformRow(match[1], row, params, state));
  } catch (_) { throw failure(); }
  finally { if (state.key) state.key.fill(0); }
}

function cacheProtection(authUserId, customerId, email, origin) {
  let parent, key;
  try {
    if (typeof authUserId !== 'string' || !UUID.test(authUserId)
        || typeof customerId !== 'string' || !UUID.test(customerId)
        || typeof email !== 'string' || email.length > 254 || email !== email.trim().toLowerCase()
        || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
        || typeof origin !== 'string' || origin.length > 300) throw failure();
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) throw failure();
    parent = deriveKey();
    key = Buffer.from(crypto.hkdfSync('sha512', parent,
      Buffer.from('dirac-address-history-cache-v2', 'utf8'),
      Buffer.from(JSON.stringify([authUserId, customerId, email, origin]), 'utf8'), 32));
    return { v: 2, id: crypto.createHmac('sha256', key).update('dirac-address-history-cache-id-v2').digest('hex'),
      key: key.toString('hex') };
  } catch (_) { throw failure(); }
  finally { if (parent) parent.fill(0); if (key) key.fill(0); }
}

module.exports = Object.freeze({
  cacheProtection,
  path: (path, options) => textProtection.path(path, options),
  textTable: path => textProtection.tableSupported(path),
  encode: (path, body, options) => textProtection.tableSupported(path)
    ? textProtection.encode(path, body, options) : transform(path, body, false),
  decode: (path, response, options) => textProtection.tableSupported(path)
    ? textProtection.decode(path, response, options) : transform(path, response, true)
});

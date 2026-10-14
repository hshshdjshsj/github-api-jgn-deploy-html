'use strict';

// Physical storage boundary. Call only after the logical database operation has
// passed its existing authorization and one-use dispatch permit.
const crypto = require('crypto');
const FIELDS = Object.freeze({
  customers: Object.freeze(['name', 'email', 'phone']),
  orders: Object.freeze(['customer_name', 'customer_email', 'customer_phone', 'shipping_address', 'note']),
  domain_orders: Object.freeze(['customer_name', 'customer_whatsapp', 'customer_email', 'owner_email', 'customer_note']),
  security_customer_auth_links: Object.freeze(['email']),
  domain_passkeys: Object.freeze(['email'])
});
const EMAIL_FIELDS = new Set(['email', 'customer_email', 'owner_email']);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SIV_PREFIX = 'dtp2s:';
const GCM_PREFIX = 'dtp2g:';
const MAX_TEXT_BYTES = 64 * 1024;
const MAX_ROWS = 1000;
const MAX_BATCH_BYTES = 4 * 1024 * 1024;
const MAX_NODES = 16384;
const MAX_DEPTH = 8;
const own = (value, name) => Object.prototype.hasOwnProperty.call(value, name);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function failure() {
  return Object.assign(new Error('TEXT_PROTECTION_FAILED'), {
    code: 'TEXT_PROTECTION_FAILED', status: 503, statusCode: 503
  });
}

function route(path) {
  if (path === '/rest/v1/rpc/dirac_passkey_create_pending_v237') {
    return {table:'domain_passkeys',params:new URLSearchParams(),path,rpc:true};
  }
  const match = typeof path === 'string' && /^\/rest\/v1\/([a-z0-9_]+)(?:\?([^#]*))?$/.exec(path);
  return match && own(FIELDS, match[1])
    ? { table: match[1], params: new URLSearchParams(match[2] || ''), path: '/rest/v1/' + match[1] }
    : null;
}

function validatedOrigin(value) {
  if (typeof value !== 'string' || value.length > 300) throw failure();
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' || parsed.origin !== value || parsed.username || parsed.password) throw failure();
  return value;
}

function stateFor(options) {
  return { origin: validatedOrigin(options && options.origin), root: null, keys: new Map(), bytes: 0, nodes: 0 };
}

function keyFor(state, table, field, mode) {
  const context = JSON.stringify(['dirac-text-field-v2', state.origin, table, field, mode]);
  if (state.keys.has(context)) return state.keys.get(context);
  if (!state.root) {
    const root = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '').trim();
    const production = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
    if (Buffer.byteLength(root, 'utf8') < (production ? 3000 : 32)) throw failure();
    const input = Buffer.from(root, 'utf8');
    try {
      state.root = Buffer.from(crypto.hkdfSync('sha512', input,
        Buffer.from('dirac-text-storage-root-v2', 'utf8'),
        Buffer.from('dirac-pii-root-key-v2', 'utf8'), 32));
    } finally { input.fill(0); }
  }
  const key = Buffer.from(crypto.hkdfSync('sha512', state.root,
    Buffer.from('dirac-text-field-v2', 'utf8'), Buffer.from(context, 'utf8'), mode === 'siv' ? 64 : 32));
  state.keys.set(context, key);
  return key;
}

function wipeState(state) {
  if (!state) return;
  if (state.root) state.root.fill(0);
  state.keys.forEach(key => key.fill(0));
}

function blockInteger(value) { return BigInt('0x' + value.toString('hex')); }
function integerBlock(value) { return Buffer.from(value.toString(16).padStart(32, '0'), 'hex'); }
function doubled(value) {
  const number = blockInteger(value);
  return integerBlock(((number << 1n) & ((1n << 128n) - 1n)) ^ ((number >> 127n) ? 0x87n : 0n));
}
function xorBlock(left, right) { return integerBlock(blockInteger(left) ^ blockInteger(right)); }

// RFC 5297 S2V uses AES-CMAC. Native CBC processes the bounded complete message,
// avoiding a JavaScript block-processing loop or a third-party dependency.
function cmac(key, message) {
  let zero, subkey1, subkey2, padded, tail, blocks, encrypted;
  try {
    const primitive = crypto.createCipheriv('aes-' + key.length * 8 + '-ecb', key, null);
    primitive.setAutoPadding(false);
    zero = Buffer.concat([primitive.update(Buffer.alloc(16)), primitive.final()]);
    subkey1 = doubled(zero); subkey2 = doubled(subkey1);
    const complete = message.length > 0 && message.length % 16 === 0;
    const total = complete ? message.length : Math.ceil((message.length + 1) / 16) * 16;
    padded = Buffer.alloc(total);
    message.copy(padded);
    if (!complete) padded[message.length] = 0x80;
    tail = xorBlock(padded.subarray(total - 16), complete ? subkey1 : subkey2);
    tail.copy(padded, total - 16);
    const cipher = crypto.createCipheriv('aes-' + key.length * 8 + '-cbc', key, Buffer.alloc(16));
    cipher.setAutoPadding(false);
    encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);
    blocks = Buffer.from(encrypted.subarray(encrypted.length - 16));
    return blocks;
  } finally {
    [zero, subkey1, subkey2, padded, tail, encrypted].forEach(value => { if (value) value.fill(0); });
  }
}

function syntheticIv(key, plain, context) {
  let initial, twice, authenticated, combination, message;
  try {
    initial = cmac(key, Buffer.alloc(16));
    twice = doubled(initial); authenticated = cmac(key, context);
    combination = xorBlock(twice, authenticated);
    if (plain.length >= 16) {
      message = Buffer.from(plain);
      const tail = xorBlock(message.subarray(message.length - 16), combination);
      tail.copy(message, message.length - 16); tail.fill(0);
    } else {
      twice.fill(0); twice = doubled(combination);
      message = Buffer.alloc(16); plain.copy(message); message[plain.length] = 0x80;
      const padded = xorBlock(message, twice); message.fill(0); message = padded;
    }
    return cmac(key, message);
  } finally { [initial, twice, authenticated, combination, message].forEach(value => { if (value) value.fill(0); }); }
}

function sivEncrypt(key, plain, context) {
  let tag, counter, cipherText;
  try {
    if (![32, 48, 64].includes(key.length)) throw failure();
    const half = key.length / 2;
    tag = syntheticIv(key.subarray(0, half), plain, context);
    counter = Buffer.from(tag); counter[8] &= 0x7f; counter[12] &= 0x7f;
    const cipher = crypto.createCipheriv('aes-' + half * 8 + '-ctr', key.subarray(half), counter);
    cipherText = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([tag, cipherText]);
  } finally { [tag, counter, cipherText].forEach(value => { if (value) value.fill(0); }); }
}

function sivDecrypt(key, sealed, context) {
  let counter, plain, expected;
  try {
    if (![32, 48, 64].includes(key.length) || sealed.length < 16) throw failure();
    const half = key.length / 2, tag = sealed.subarray(0, 16);
    counter = Buffer.from(tag); counter[8] &= 0x7f; counter[12] &= 0x7f;
    const cipher = crypto.createDecipheriv('aes-' + half * 8 + '-ctr', key.subarray(half), counter);
    plain = Buffer.concat([cipher.update(sealed.subarray(16)), cipher.final()]);
    expected = syntheticIv(key.subarray(0, half), plain, context);
    if (!crypto.timingSafeEqual(tag, expected)) throw failure();
    const result = Buffer.from(plain);
    return result;
  } finally { [counter, plain, expected].forEach(value => { if (value) value.fill(0); }); }
}

function canonicalEmail(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value, 'utf8') > 254
      || value.startsWith(SIV_PREFIX) || value.startsWith(GCM_PREFIX)
      || value !== value.trim().toLowerCase() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) throw failure();
  return value;
}

function fieldContext(state, table, field) {
  return Buffer.from(JSON.stringify(['dirac-text-storage-v2', state.origin, table, field]), 'utf8');
}

function identity(row, params, name) {
  const values = params.getAll(name);
  if (values.length > 1) throw failure();
  const normalize = value => {
    if (typeof value !== 'string' || !UUID.test(value.toLowerCase())) throw failure();
    return value.toLowerCase();
  };
  const fromRow = own(row, name) ? normalize(row[name]) : null;
  const fromQuery = values.length === 1 && values[0].startsWith('eq.') ? normalize(values[0].slice(3)) : null;
  if (fromRow !== null && fromQuery !== null && fromRow !== fromQuery) throw failure();
  const value = fromRow === null ? fromQuery : fromRow;
  if (value === null) throw failure();
  return value;
}

function bindingContext(state, table, field, row, params) {
  const binding = { id: identity(row, params, 'id') };
  if (table === 'orders' || table === 'domain_orders') binding.customer_id = identity(row, params, 'customer_id');
  return Buffer.from(JSON.stringify(['dirac-text-storage-v2', state.origin, table, field, binding]), 'utf8');
}

function strictBase64(value, maximum) {
  if (typeof value !== 'string' || value.length > Math.ceil(maximum * 4 / 3)
      || !/^[A-Za-z0-9_-]+$/.test(value)) throw failure();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maximum || bytes.toString('base64url') !== value) { bytes.fill(0); throw failure(); }
  return bytes;
}

function encryptEmail(value, state, table, field) {
  let plain, context, sealed;
  try {
    plain = Buffer.from(canonicalEmail(value), 'utf8');
    state.bytes += plain.length;
    if (state.bytes > MAX_BATCH_BYTES) throw failure();
    context = fieldContext(state, table, field);
    sealed = sivEncrypt(keyFor(state, table, field, 'siv'), plain, context);
    return SIV_PREFIX + sealed.toString('base64url');
  } finally { [plain, context, sealed].forEach(bytes => { if (bytes) bytes.fill(0); }); }
}

function transformField(value, state, table, field, row, params, decode) {
  if (value === null || value === '') return value;
  if (typeof value !== 'string') throw failure();
  const email = EMAIL_FIELDS.has(field);
  const expectedPrefix = email ? SIV_PREFIX : GCM_PREFIX;
  const protectedValue = value.startsWith(SIV_PREFIX) || value.startsWith(GCM_PREFIX);
  if (decode && !protectedValue) return value; // Explicit transitional legacy compatibility.
  if (!decode && protectedValue) throw failure(); // Never accept caller-supplied storage envelopes.
  let plain, context, sealed, nonce, tag, ciphertext;
  try {
    if (decode) {
      if (!value.startsWith(expectedPrefix)) throw failure();
      sealed = strictBase64(value.slice(expectedPrefix.length), MAX_TEXT_BYTES + 28);
      state.bytes += sealed.length;
      if (state.bytes > MAX_BATCH_BYTES) throw failure();
      if (email) {
        context = fieldContext(state, table, field);
        plain = sivDecrypt(keyFor(state, table, field, 'siv'), sealed, context);
      } else {
        if (sealed.length < 29) throw failure();
        context = bindingContext(state, table, field, row, params);
        nonce = sealed.subarray(0, 12); tag = sealed.subarray(12, 28);
        const cipher = crypto.createDecipheriv('aes-256-gcm', keyFor(state, table, field, 'gcm'), nonce, {authTagLength:16});
        cipher.setAAD(context); cipher.setAuthTag(tag);
        const first = cipher.update(sealed.subarray(28));
        try { plain = Buffer.concat([first, cipher.final()]); }
        finally { first.fill(0); }
      }
      if (plain.length > MAX_TEXT_BYTES) throw failure();
      const text = new TextDecoder('utf-8', {fatal:true}).decode(plain);
      if (email) canonicalEmail(text);
      return text;
    }
    if (email) return encryptEmail(value, state, table, field);
    plain = Buffer.from(value, 'utf8');
    state.bytes += plain.length;
    if (plain.length > MAX_TEXT_BYTES || state.bytes > MAX_BATCH_BYTES) throw failure();
    context = bindingContext(state, table, field, row, params);
    nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyFor(state, table, field, 'gcm'), nonce, {authTagLength:16});
    cipher.setAAD(context);
    ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]); tag = cipher.getAuthTag();
    return GCM_PREFIX + Buffer.concat([nonce, tag, ciphertext]).toString('base64url');
  } finally { [plain, context, sealed, nonce, tag, ciphertext].forEach(bytes => { if (bytes) bytes.fill(0); }); }
}

function selectParts(value) {
  if (typeof value !== 'string' || value.length > 12000) throw failure();
  const state = Array.from(value).reduce((state, character) => {
    if (character === '(') state.depth += 1;
    if (character === ')') state.depth -= 1;
    if (state.depth < 0 || state.depth > 6) throw failure();
    if (character === ',' && state.depth === 0) { state.parts.push(state.current); state.current = ''; }
    else state.current += character;
    return state;
  }, {depth:0,parts:[],current:''});
  if (state.depth !== 0) throw failure();
  state.parts.push(state.current);
  if (state.parts.length > 100 || state.parts.some(part => !part.trim())) throw failure();
  return state.parts;
}

function relation(part) {
  const match = /^([a-z][a-z0-9_]*):(?:([a-z][a-z0-9_]*))(?:![a-z0-9_]+)*\(([\s\S]*)\)$/.exec(part.trim());
  return match && ((match[1] === 'customer' && match[2] === 'customers')
    || (match[1] === 'passkeys' && match[2] === 'domain_passkeys'))
    ? {alias:match[1],table:match[2],select:match[3],prefix:part.slice(0,part.indexOf('(')+1)} : null;
}

function selectedField(part, table) {
  const clean = part.trim();
  if (FIELDS[table].includes(clean)) return {name:clean,field:clean};
  const alias = /^([a-z][a-z0-9_]*):([a-z][a-z0-9_]*)$/.exec(clean);
  return alias && FIELDS[table].includes(alias[2]) ? {name:alias[1],field:alias[2]} : null;
}

function selectPlan(table, select) {
  if (!select || select.trim() === '*') return {physical:select,inject:[],fields:null,relations:[]};
  const parts = selectParts(select);
  const wildcard = parts.some(part => part.trim() === '*');
  const selected = parts.map(part => selectedField(part, table)).filter(Boolean);
  const nested = parts.map(part => relation(part)).filter(Boolean);
  const randomFields = selected.some(item => !EMAIL_FIELDS.has(item.field));
  const inject = randomFields && !wildcard
    ? ['id', ...((table === 'orders' || table === 'domain_orders') ? ['customer_id'] : [])].filter(name => !parts.some(part => part.trim() === name)) : [];
  const physical = parts.map(part => {
    const nestedRelation = relation(part);
    return nestedRelation ? nestedRelation.prefix + selectPlan(nestedRelation.table, nestedRelation.select).physical + ')' : part;
  }).concat(inject).join(',');
  return {physical,inject,fields:wildcard ? null : selected,relations:nested};
}

function transformRow(info, row, state, options, decode, plan, depth = 0) {
  if (!record(row) || ++state.nodes > MAX_NODES || depth > MAX_DEPTH) throw failure();
  const prototype = Object.getPrototypeOf(row);
  if (prototype !== Object.prototype && prototype !== null) throw failure();
  let output = row;
  const mappings = plan && plan.fields !== null ? plan.fields : FIELDS[info.table].map(field => ({name:field,field}));
  if (!decode && String(options.method || 'POST').toUpperCase() === 'POST' && !own(row, 'id')
      && mappings.some(item => !EMAIL_FIELDS.has(item.field) && own(row,item.name) && row[item.name] !== null && row[item.name] !== '')) {
    output = {...row,id:crypto.randomUUID()};
  }
  mappings.forEach(({name,field}) => {
    if (!own(output,name)) return;
    const value = transformField(output[name], state, info.table, field, output, info.params, decode);
    if (value !== output[name]) { if (output === row) output = {...row}; output[name] = value; }
  });
  if (decode) {
    const known = [
      {alias:'customer',table:'customers',select:null}, {alias:'passkeys',table:'domain_passkeys',select:null}
    ];
    const nested = plan ? plan.relations.concat(plan.fields === null
      ? known.filter(item => !plan.relations.some(existing => existing.alias === item.alias)) : []) : known;
    nested.forEach(item => {
      if (!own(output,item.alias) || output[item.alias] === null) return;
      const nestedInfo = {table:item.table,params:new URLSearchParams()}, nestedPlan = selectPlan(item.table,item.select);
      const value = output[item.alias];
      if (Array.isArray(value) && value.length > MAX_ROWS) throw failure();
      const restored = Array.isArray(value)
        ? value.map(child => transformRow(nestedInfo,child,state,options,true,nestedPlan,depth + 1))
        : transformRow(nestedInfo,value,state,options,true,nestedPlan,depth + 1);
      if (output === row) output = {...row}; output[item.alias] = restored;
    });
    if (plan && plan.inject.length) {
      if (output === row) output = {...row};
      plan.inject.forEach(name => { delete output[name]; });
    }
  }
  return output;
}

function transform(path, input, options, decode) {
  const info = route(path);
  if (!info || input === null || input === undefined) return input;
  let state;
  try {
    state = stateFor(options);
    if (info.rpc) {
      if (!decode && String(options && options.method || 'POST').toUpperCase() !== 'POST') throw failure();
      const transformRpc = value => {
        if (!record(value)) throw failure();
        if (!decode && (!own(value,'p_email') || value.p_email === null || value.p_email === '')) throw failure();
        const names = decode ? ['email','p_email'] : ['p_email'];
        let output = value;
        names.forEach(name => {
          if (!own(value,name)) return;
          const restored = transformField(value[name],state,'domain_passkeys','email',value,info.params,decode);
          if (restored !== value[name]) { if (output === value) output = {...value}; output[name] = restored; }
        });
        return output;
      };
      if (Array.isArray(input)) {
        if (!decode || input.length > MAX_ROWS) throw failure();
        return input.map(transformRpc);
      }
      return transformRpc(input);
    }
    const select = info.params.getAll('select');
    if (select.length > 1) throw failure();
    const plan = decode ? selectPlan(info.table,select[0] || null) : null;
    if (Array.isArray(input)) {
      if (input.length > MAX_ROWS) throw failure();
      return input.map(row => transformRow(info,row,state,options || {},decode,plan));
    }
    return transformRow(info,input,state,options || {},decode,plan);
  } catch (_) { throw failure(); }
  finally { wipeState(state); }
}

function literalIlike(value) {
  if (/(?:^|[^\\])(?:\\\\)*[%_]/.test(value) || /\\(?:[^%_\\]|$)/.test(value)) throw failure();
  return value.replace(/\\([%_\\])/g,'$1');
}
function quoted(value) { return '"' + value.replace(/\\/g,'\\\\').replace(/"/g,'\\"') + '"'; }

function physicalPath(path, options = {}) {
  const info = route(path);
  if (!info) return path;
  let state;
  try {
    state = stateFor(options);
    if (info.rpc) return path;
    let changed = false;
    const params = info.params;
    FIELDS[info.table].filter(name => EMAIL_FIELDS.has(name)).forEach(name => {
      const values = params.getAll(name);
      if (!values.length) return;
      if (values.length !== 1) throw failure();
      const predicate = values[0];
      if (predicate === 'is.null' || predicate === 'not.is.null' || predicate === 'eq.') return;
      const exact = predicate.startsWith('eq.'), insensitive = predicate.startsWith('ilike.');
      if (!exact && !insensitive) throw failure();
      const value = canonicalEmail(insensitive ? literalIlike(predicate.slice(6)) : predicate.slice(3));
      const cipher = encryptEmail(value,state,info.table,name);
      const method = String(options.method || 'GET').toUpperCase();
      params.set(name, method === 'GET' && options.legacy !== false
        ? 'in.(' + quoted(value) + ',' + quoted(cipher) + ')' : 'eq.' + cipher);
      changed = true;
    });
    const selects = params.getAll('select');
    if (selects.length > 1) throw failure();
    if (selects.length) {
      const plan = selectPlan(info.table,selects[0]);
      if (plan.physical !== selects[0]) { params.set('select',plan.physical); changed = true; }
    }
    return changed ? info.path + (params.toString() ? '?' + params.toString() : '') : path;
  } catch (_) { throw failure(); }
  finally { wipeState(state); }
}

module.exports = Object.freeze({
  fieldsForTable:FIELDS,
  tableSupported:path => Boolean(route(path)),
  path:physicalPath,
  encode:(path,input,options = {}) => transform(path,input,options,false),
  decode:(path,input,options = {}) => transform(path,input,options,true)
});

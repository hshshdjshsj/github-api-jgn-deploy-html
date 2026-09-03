'use strict';

const { Worker } = require('worker_threads');
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
    && handler.__diracCentralSelfTestV221
    && handler.__diracCentralSelfTestV221.ok === true
    && handler.__diracCentralDeviceAuthBootstrapV224 === true
    && handler.__diracCentralOwaspHardeningV228 === true
    && handler.__diracCentralBackendComplianceV230 === true
    && handler.__diracCentralBackendStaticGateV230
    && handler.__diracCentralBackendStaticGateV230.ok === true
    && handler.__diracCentralRuntimeLockV230
    && handler.__diracCentralRuntimeLockV230.ok === true;
}

if (!hasCentralSecurityParity(centralHandler)) {
  throw new Error('DIRAC_SECURITY_ROUTE_CENTRAL_HANDLER_INVALID');
}

const SECURITY_ROUTE_PATH = '/api/keamanan';
const CENTRAL_ROUTE_PATH = '/api/health';
const RESET_ROUTE_PATH = '/api/chat.js';
const RESET_ACTIONS = Object.freeze(new Set(['request_password_reset', 'confirm_password_reset']));
let resetWorkerState = null;
let resetWorkerSequence = 0;

function resetWorkerMain() {
  'use strict';
  const { parentPort, workerData } = require('worker_threads');
  const { EventEmitter } = require('events');
  const { Readable } = require('stream');

  function secureHandler(handler) {
    const exportParity = typeof handler === 'function'
      && Object.isFrozen(handler) === true
      && handler.__diracCentralSecurityGuardV146 === true
      && handler.__diracCentralArchitectureConsolidationV202 === true
      && handler.__diracCentralHardeningV221 === true
      && handler.__diracCentralSecurityScoreV221 === 100
      && typeof handler.__diracCentralPipelineHashV221 === 'string'
      && handler.__diracCentralPipelineHashV221.length > 0
      && handler.__diracCentralSelfTestV221
      && handler.__diracCentralSelfTestV221.ok === true
      && handler.__diracCentralDeviceAuthBootstrapV224 === true
      && handler.__diracCentralOwaspHardeningV228 === true
      && handler.__diracCentralBackendComplianceV230 === true
      && handler.__diracCentralBackendStaticGateV230
      && handler.__diracCentralBackendStaticGateV230.ok === true
      && handler.__diracCentralRuntimeLockV230
      && handler.__diracCentralRuntimeLockV230.ok === true;
    if (exportParity) return true;
    if (typeof handler !== 'function') return false;
    const egressFlag = Object.getOwnPropertyDescriptor(globalThis, '__DIRAC_V202_SECURE_EGRESS_GATEWAY__');
    const runtimeFlag = Object.getOwnPropertyDescriptor(globalThis, '__DIRAC_V230_RUNTIME_READY__');
    const fetchLock = Object.getOwnPropertyDescriptor(globalThis, 'fetch');
    return Boolean(
      egressFlag && egressFlag.value === true && egressFlag.writable === false && egressFlag.configurable === false
      && runtimeFlag && runtimeFlag.value === true && runtimeFlag.writable === false && runtimeFlag.configurable === false
      && fetchLock && typeof fetchLock.value === 'function' && fetchLock.writable === false && fetchLock.configurable === false
      && String(fetchLock.value.name || '') === 'fetchV202Gateway'
    );
  }

  function normalizeHeaders(headers) {
    const out = Object.create(null);
    if (!headers || typeof headers !== 'object') return out;
    Object.keys(headers).forEach((name) => {
      const value = headers[name];
      if (value === undefined) return;
      out[String(name).toLowerCase()] = Array.isArray(value) ? value.map(String) : String(value);
    });
    return out;
  }

  function parseQuery(rawUrl) {
    const out = Object.create(null);
    const index = String(rawUrl || '').indexOf('?');
    if (index < 0) return out;
    const params = new URLSearchParams(String(rawUrl).slice(index + 1));
    for (const key of new Set(params.keys())) {
      const values = params.getAll(key);
      out[key] = values.length > 1 ? values : String(values[0] || '');
    }
    return out;
  }

  function bodyBuffer(payload) {
    if (payload && typeof payload.rawBodyBase64 === 'string' && payload.rawBodyBase64) {
      return Buffer.from(payload.rawBodyBase64, 'base64');
    }
    return Buffer.alloc(0);
  }

  function makeRequest(payload) {
    const raw = bodyBuffer(payload);
    let pushed = false;
    const req = new Readable({
      read() {
        if (pushed) return;
        pushed = true;
        if (raw.length) this.push(raw);
        this.push(null);
      }
    });
    req.method = String(payload.method || 'GET').toUpperCase();
    req.url = String(payload.url || '');
    req.originalUrl = req.url;
    req.path = req.url.split('?')[0];
    req.headers = normalizeHeaders(payload.headers);
    req.rawHeaders = Array.isArray(payload.rawHeaders) ? payload.rawHeaders.map(String) : [];
    req.query = parseQuery(req.url);
    req.cookies = payload.cookies && typeof payload.cookies === 'object' ? payload.cookies : Object.create(null);
    if (Object.prototype.hasOwnProperty.call(payload, 'body')) req.body = payload.body;
    if (raw.length) req.rawBody = raw;
    req.ip = String(payload.ip || payload.remoteAddress || '');
    req.ips = Array.isArray(payload.ips) ? payload.ips.map(String) : [];
    req.socket = {
      remoteAddress: String(payload.remoteAddress || payload.ip || ''),
      remotePort: Number(payload.remotePort || 0),
      localAddress: String(payload.localAddress || ''),
      localPort: Number(payload.localPort || 0),
      encrypted: Boolean(payload.encrypted)
    };
    req.connection = req.socket;
    req.protocol = String(payload.protocol || String(req.headers['x-forwarded-proto'] || '').split(',')[0] || 'https').trim().toLowerCase();
    req.secure = req.protocol === 'https';
    req.hostname = String(payload.hostname || req.headers.host || '').split(':')[0];
    req.httpVersion = String(payload.httpVersion || '1.1');
    req.httpVersionMajor = Number(payload.httpVersionMajor || 1);
    req.httpVersionMinor = Number(payload.httpVersionMinor || 1);
    req.get = req.header = function getHeader(name) {
      const value = req.headers[String(name || '').toLowerCase()];
      return Array.isArray(value) ? value.join(', ') : value;
    };
    return req;
  }

  class WorkerResponse extends EventEmitter {
    constructor(done) {
      super();
      this.statusCode = 200;
      this.statusMessage = '';
      this.headersSent = false;
      this.finished = false;
      this.writableEnded = false;
      this._headers = new Map();
      this._chunks = [];
      this._done = done;
      this._completed = false;
    }
    setHeader(name, value) {
      const clean = String(name || '');
      if (!clean) throw new TypeError('HEADER_NAME_REQUIRED');
      this._headers.set(clean.toLowerCase(), { name: clean, value: Array.isArray(value) ? value.map(String) : String(value) });
      return this;
    }
    appendHeader(name, value) {
      const key = String(name || '').toLowerCase();
      const current = this._headers.get(key);
      const incoming = Array.isArray(value) ? value.map(String) : [String(value)];
      if (!current) return this.setHeader(name, incoming);
      const prior = Array.isArray(current.value) ? current.value : [String(current.value)];
      current.value = prior.concat(incoming);
      this._headers.set(key, current);
      return this;
    }
    getHeader(name) {
      const item = this._headers.get(String(name || '').toLowerCase());
      return item ? item.value : undefined;
    }
    getHeaders() {
      const out = Object.create(null);
      for (const [key, item] of this._headers.entries()) out[key] = item.value;
      return out;
    }
    getHeaderNames() { return Array.from(this._headers.keys()); }
    hasHeader(name) { return this._headers.has(String(name || '').toLowerCase()); }
    removeHeader(name) { this._headers.delete(String(name || '').toLowerCase()); }
    status(code) { this.statusCode = Number(code); return this; }
    type(value) { this.setHeader('Content-Type', String(value)); return this; }
    writeHead(code, statusMessage, headers) {
      this.statusCode = Number(code);
      if (statusMessage && typeof statusMessage === 'object') headers = statusMessage;
      else if (typeof statusMessage === 'string') this.statusMessage = statusMessage;
      if (headers && typeof headers === 'object') Object.keys(headers).forEach((name) => this.setHeader(name, headers[name]));
      this.headersSent = true;
      return this;
    }
    flushHeaders() { this.headersSent = true; return this; }
    write(chunk, encoding) {
      if (chunk !== undefined && chunk !== null) this._chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), encoding || 'utf8'));
      this.headersSent = true;
      return true;
    }
    json(value) {
      if (!this.hasHeader('content-type')) this.setHeader('Content-Type', 'application/json; charset=utf-8');
      return this.end(JSON.stringify(value));
    }
    send(value) {
      if (value !== null && typeof value === 'object' && !Buffer.isBuffer(value) && !(value instanceof Uint8Array)) return this.json(value);
      return this.end(value);
    }
    sendStatus(code) { this.status(code); return this.end(String(code)); }
    redirect(statusOrUrl, maybeUrl) {
      const status = maybeUrl === undefined ? 307 : Number(statusOrUrl);
      const url = maybeUrl === undefined ? statusOrUrl : maybeUrl;
      this.statusCode = Number(status) || 307;
      this.setHeader('Location', String(url || ''));
      return this.end();
    }
    end(chunk, encoding) {
      if (this.writableEnded) return this;
      if (chunk !== undefined && chunk !== null) this.write(chunk, encoding);
      this.headersSent = true;
      this.finished = true;
      this.writableEnded = true;
      this.emit('finish');
      if (!this._completed) {
        this._completed = true;
        const headers = [];
        for (const item of this._headers.values()) headers.push([item.name, item.value]);
        this._done({
          statusCode: Number(this.statusCode) || 200,
          statusMessage: String(this.statusMessage || ''),
          headers,
          bodyBase64: Buffer.concat(this._chunks).toString('base64')
        });
      }
      return this;
    }
  }

  async function finishReturnedResponse(value, res) {
    if (res.writableEnded || !value || typeof value !== 'object') return;
    if (typeof value.status !== 'number' || !value.headers || typeof value.arrayBuffer !== 'function') return;
    res.statusCode = Number(value.status) || 200;
    try { value.headers.forEach((v, k) => res.appendHeader(k, v)); } catch (_) {}
    const bytes = Buffer.from(await value.arrayBuffer());
    res.end(bytes);
  }

  let handler;
  try { handler = require(String(workerData && workerData.modulePath || '')); }
  catch (_) {
    parentPort.postMessage({ type: 'ready', ok: false, code: 'SECURITY_RESET_HANDLER_UNAVAILABLE' });
    return;
  }
  if (!secureHandler(handler)) {
    parentPort.postMessage({ type: 'ready', ok: false, code: 'SECURITY_RESET_HANDLER_CENTRAL_PARITY_INVALID' });
    return;
  }

  parentPort.on('message', async (message) => {
    if (!message || message.type !== 'request' || !message.id) return;
    let complete = false;
    const finish = (response) => {
      if (complete) return;
      complete = true;
      parentPort.postMessage({ type: 'response', id: String(message.id), ok: true, response });
    };
    try {
      const req = makeRequest(message.request || {});
      const res = new WorkerResponse(finish);
      req.res = res;
      res.req = req;
      const returned = await handler(req, res);
      await finishReturnedResponse(returned, res);
      if (!res.writableEnded && !complete) {
        parentPort.postMessage({ type: 'response', id: String(message.id), ok: false, code: 'SECURITY_RESET_RESPONSE_NOT_ENDED' });
      }
    } catch (_) {
      if (!complete) parentPort.postMessage({ type: 'response', id: String(message.id), ok: false, code: 'SECURITY_RESET_WORKER_EXECUTION_FAILED' });
    }
  });
  parentPort.postMessage({ type: 'ready', ok: true });
}

const RESET_WORKER_SOURCE = '(' + resetWorkerMain.toString() + ')();';

function rawHeaders(req) {
  if (req && Array.isArray(req.rawHeaders) && req.rawHeaders.length % 2 === 0) return req.rawHeaders.map(String);
  const out = [];
  const headers = req && req.headers && typeof req.headers === 'object' ? req.headers : {};
  Object.keys(headers).forEach((name) => {
    const value = headers[name];
    if (Array.isArray(value)) value.forEach((item) => out.push(name, String(item)));
    else if (value !== undefined) out.push(name, String(value));
  });
  return out;
}

function existingRawBodyBase64(req) {
  const values = [req && req.rawBody, req && req.bodyRaw, req && req.raw];
  for (const value of values) {
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value).toString('base64');
    if (typeof value === 'string') return Buffer.from(value, 'utf8').toString('base64');
  }
  return '';
}

async function resetRawBodyBase64(req) {
  const existing = existingRawBodyBase64(req);
  if (existing) return existing;
  if (!req || typeof req[Symbol.asyncIterator] !== 'function') return '';
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > 524288) throw new Error('SECURITY_RESET_BODY_TOO_LARGE');
    chunks.push(bytes);
  }
  return chunks.length ? Buffer.concat(chunks, total).toString('base64') : '';
}

function failResetWorker(state, code) {
  if (!state || state.failed) return;
  state.failed = true;
  if (resetWorkerState === state) resetWorkerState = null;
  const error = new Error(code || 'SECURITY_RESET_WORKER_FAILED');
  for (const pending of state.pending.values()) {
    pending.reject(error);
  }
  state.pending.clear();
  if (!state.readySettled) {
    state.readySettled = true;
    state.rejectReady(error);
  }
  try { state.worker.terminate(); } catch (_) {}
}

function ensureResetWorker() {
  if (resetWorkerState && !resetWorkerState.failed) return resetWorkerState.ready;
  let modulePath;
  try { modulePath = require.resolve('./chat.js'); }
  catch (_) { return Promise.reject(new Error('SECURITY_RESET_HANDLER_UNAVAILABLE')); }
  let worker;
  try {
    worker = new Worker(RESET_WORKER_SOURCE, {
      eval: true,
      workerData: { modulePath }
    });
  } catch (_) {
    return Promise.reject(new Error('SECURITY_RESET_WORKER_START_FAILED'));
  }
  try { worker.unref(); } catch (_) {}
  const state = {
    worker,
    pending: new Map(),
    failed: false,
    readySettled: false,
    ready: null,
    resolveReady: null,
    rejectReady: null
  };
  state.ready = new Promise((resolve, rejectReady) => {
    state.resolveReady = resolve;
    state.rejectReady = rejectReady;
  });
  resetWorkerState = state;
  worker.on('message', (message) => {
    if (!message || typeof message !== 'object') return;
    if (message.type === 'ready') {
      if (state.readySettled || state.failed) return;
      if (message.ok === true) {
        state.readySettled = true;
        state.resolveReady(state);
      } else {
        failResetWorker(state, String(message.code || 'SECURITY_RESET_WORKER_START_FAILED'));
      }
      return;
    }
    if (message.type !== 'response' || !message.id || state.failed) return;
    const id = String(message.id);
    const pending = state.pending.get(id);
    if (!pending) return;
    state.pending.delete(id);
    if (message.ok === true && message.response) pending.resolve(message.response);
    else pending.reject(new Error(String(message.code || 'SECURITY_RESET_WORKER_EXECUTION_FAILED')));
  });
  worker.on('error', () => failResetWorker(state, 'SECURITY_RESET_WORKER_ERROR'));
  worker.on('exit', (code) => {
    if (!state.failed) failResetWorker(state, code === 0 ? 'SECURITY_RESET_WORKER_EXITED' : 'SECURITY_RESET_WORKER_CRASHED');
  });
  return state.ready;
}

async function requestPayload(req, parsed) {
  return {
    method: parsed.method,
    url: parsed.canonicalUrl,
    headers: req && req.headers && typeof req.headers === 'object' ? req.headers : {},
    rawHeaders: rawHeaders(req),
    body: req ? req.body : undefined,
    rawBodyBase64: await resetRawBodyBase64(req),
    cookies: req && req.cookies && typeof req.cookies === 'object' ? req.cookies : {},
    ip: String(req && req.ip || ''),
    ips: Array.isArray(req && req.ips) ? req.ips.map(String) : [],
    remoteAddress: String(req && req.socket && req.socket.remoteAddress || ''),
    remotePort: Number(req && req.socket && req.socket.remotePort || 0),
    localAddress: String(req && req.socket && req.socket.localAddress || ''),
    localPort: Number(req && req.socket && req.socket.localPort || 0),
    encrypted: Boolean(req && req.socket && req.socket.encrypted),
    protocol: String(req && req.protocol || ''),
    hostname: String(req && req.hostname || ''),
    httpVersion: String(req && req.httpVersion || '1.1'),
    httpVersionMajor: Number(req && req.httpVersionMajor || 1),
    httpVersionMinor: Number(req && req.httpVersionMinor || 1)
  };
}

function applyResetResponse(res, response) {
  if (!response || !Number.isInteger(Number(response.statusCode))) throw new Error('SECURITY_RESET_RESPONSE_INVALID');
  if (Array.isArray(response.headers)) {
    response.headers.forEach((entry) => {
      if (!Array.isArray(entry) || entry.length !== 2) return;
      res.setHeader(String(entry[0]), entry[1]);
    });
  }
  res.statusCode = Number(response.statusCode);
  if (response.statusMessage) {
    try { res.statusMessage = String(response.statusMessage); } catch (_) {}
  }
  return res.end(Buffer.from(String(response.bodyBase64 || ''), 'base64'));
}

async function invokeResetHandler(req, res, parsed) {
  let state;
  try { state = await ensureResetWorker(); }
  catch (_) { return reject(res, 503, 'SECURITY_RESET_HANDLER_INVALID'); }
  const id = String(++resetWorkerSequence);
  let payload;
  try { payload = await requestPayload(req, parsed); }
  catch (_) { return reject(res, 503, 'SECURITY_RESET_HANDLER_INVALID'); }
  let response;
  try {
    response = await new Promise((resolve, rejectPending) => {
      state.pending.set(id, { resolve, reject: rejectPending });
      try { state.worker.postMessage({ type: 'request', id, request: payload }); }
      catch (error) {
        state.pending.delete(id);
        rejectPending(error);
      }
    });
  } catch (_) {
    return reject(res, 503, 'SECURITY_RESET_HANDLER_INVALID');
  }
  try { return applyResetResponse(res, response); }
  catch (_) { return reject(res, 503, 'SECURITY_RESET_RESPONSE_INVALID'); }
}

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
  confirm_password_reset: Object.freeze(new Set(['POST', 'OPTIONS']))
});

function reject(res, status, code) {
  try {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
  } catch (_) {}
  return res.status(status).json({
    ok: false,
    code,
    message: 'Permintaan keamanan ditolak oleh gerbang rute.'
  });
}

function parseExactRequest(req) {
  const rawUrl = String(req && req.url || '');
  if (!rawUrl || rawUrl.length > 1800 || /[\u0000-\u001f\u007f]/.test(rawUrl)) {
    return { ok: false, code: 'SECURITY_ROUTE_URL_INVALID' };
  }
  const queryIndex = rawUrl.indexOf('?');
  const rawPath = queryIndex === -1 ? rawUrl : rawUrl.slice(0, queryIndex);
  const rawQuery = queryIndex === -1 ? '' : rawUrl.slice(queryIndex + 1);
  if (rawPath !== SECURITY_ROUTE_PATH || rawQuery.length > 1600) {
    return { ok: false, code: 'SECURITY_ROUTE_PATH_INVALID' };
  }

  let params;
  try { params = new URLSearchParams(rawQuery); }
  catch (_) { return { ok: false, code: 'SECURITY_ROUTE_QUERY_INVALID' }; }
  const actions = params.getAll('action');
  if (actions.length !== 1) return { ok: false, code: 'SECURITY_ROUTE_ACTION_COUNT_INVALID' };
  const action = String(actions[0] || '').trim();
  if (!/^[a-z][a-z0-9_]{1,79}$/.test(action)
      || action === 'domain_login'
      || action === 'domain_logout'
      || !Object.prototype.hasOwnProperty.call(ACTION_METHODS, action)) {
    return { ok: false, code: 'SECURITY_ROUTE_ACTION_NOT_ALLOWED' };
  }

  if (req && req.query && Object.prototype.hasOwnProperty.call(req.query, 'action')) {
    const queryAction = req.query.action;
    if (Array.isArray(queryAction) || String(queryAction || '').trim() !== action) {
      return { ok: false, code: 'SECURITY_ROUTE_ACTION_MISMATCH' };
    }
  }

  const method = String(req && req.method || 'GET').toUpperCase();
  if (!ACTION_METHODS[action].has(method)) {
    return { ok: false, code: 'SECURITY_ROUTE_METHOD_NOT_ALLOWED', allow: Array.from(ACTION_METHODS[action]).filter((v) => v !== 'OPTIONS') };
  }
  return {
    ok: true,
    action,
    method,
    canonicalUrl: (RESET_ACTIONS.has(action) ? RESET_ROUTE_PATH : CENTRAL_ROUTE_PATH) + (rawQuery ? '?' + rawQuery : ''),
    reset: RESET_ACTIONS.has(action)
  };
}

function resetBootstrapCanonicalUrl(req, parsed) {
  if (!parsed || parsed.action !== 'domain_health' || parsed.method !== 'GET') return '';
  const rawUrl = String(req && req.url || '');
  const queryIndex = rawUrl.indexOf('?');
  if (queryIndex < 0) return '';
  const rawQuery = rawUrl.slice(queryIndex + 1);
  let params;
  try { params = new URLSearchParams(rawQuery); }
  catch (_) { return ''; }
  const nonceTargets = params.getAll('_dirac_page_nonce_for');
  const csrfProbes = params.getAll('_csrf_probe');
  const probeHeader = String(req && req.headers && (req.headers['x-dirac-csrf-probe'] || req.headers['X-Dirac-CSRF-Probe']) || '');
  if (nonceTargets.length !== 1
      || !RESET_ACTIONS.has(String(nonceTargets[0] || '').trim())
      || csrfProbes.length !== 1
      || !/^\d{10,16}$/.test(String(csrfProbes[0] || ''))
      || probeHeader !== 'security-reset-v143'
      || !/(?:^|&)action=domain_health(?:&|$)/.test(rawQuery)) return '';
  return RESET_ROUTE_PATH + '?' + rawQuery.replace(/(^|&)action=domain_health(?=&|$)/, '$1action=chat_health');
}

async function keamananHandler(req, res) {
  const parsed = parseExactRequest(req);
  if (!parsed.ok) {
    if (parsed.allow && parsed.allow.length) {
      try { res.setHeader('Allow', parsed.allow.join(', ')); } catch (_) {}
      return reject(res, 405, parsed.code);
    }
    return reject(res, 403, parsed.code);
  }

  const resetBootstrapUrl = resetBootstrapCanonicalUrl(req, parsed);
  if (resetBootstrapUrl) {
    return invokeResetHandler(req, res, Object.assign({}, parsed, { canonicalUrl: resetBootstrapUrl, reset: true }));
  }
  if (parsed.reset) return invokeResetHandler(req, res, parsed);

  const originalUrl = req.url;
  try {
    req.url = parsed.canonicalUrl;
    return await centralHandler(req, res);
  } finally {
    try { req.url = originalUrl; } catch (_) {}
  }
}

Object.defineProperty(keamananHandler, 'config', {
  value: centralHandler.config,
  enumerable: true,
  writable: false,
  configurable: false
});
[
  '__diracCentralSecurityGuardV146',
  '__diracCentralArchitectureConsolidationV202',
  '__diracCentralHardeningV221',
  '__diracCentralSecurityScoreV221',
  '__diracCentralPipelineHashV221',
  '__diracCentralSelfTestV221',
  '__diracCentralPatchTargetCountV221',
  '__diracCentralPatchTargetsV221',
  '__diracCentralDeviceAuthBootstrapV224',
  '__diracCentralOwaspHardeningV228',
  '__diracCentralBackendComplianceV230',
  '__diracCentralBackendStaticGateV230',
  '__diracCentralRuntimeLockV230'
].forEach((name) => {
  Object.defineProperty(keamananHandler, name, { value: centralHandler[name], enumerable: false });
});
Object.defineProperty(keamananHandler, '__diracSecurityRouteAliasV2', { value: true, enumerable: false });
Object.freeze(keamananHandler);

module.exports = keamananHandler;

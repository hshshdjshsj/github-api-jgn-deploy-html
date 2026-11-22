'use strict';

// One executor for every API policy. Policy functions retain their route's
// authentication protocol; no caller-supplied flag can create a receipt.
const STAGES = Object.freeze(['identity', 'memory ban', 'persistent ban', 'action format',
  'alias', 'whitelist', 'server role', 'ENV partition', 'classification', 'rate limit',
  'server authentication', 'browser authenticity', 'CSRF', 'page nonce', 'browser signal',
  'device binding', 'admin authentication', 'public-read policy', 'body validation',
  'light guard', 'contract validation', 'A2F signature', 'security report', 'request sample',
  'threat detection', 'zero-day protection', 'IDOR/BOLA', 'circuit breaker', 'MFA', 'integrity']);
const PASSED = Symbol('central-stage-passed');
const receipts = new WeakMap();
const ROUTES = new Set(['health', 'worker', 'admin', 'security', 'support']);
function failure() {
  return Object.assign(new Error('CENTRAL_PIPELINE_REQUIRED'), { code: 'CENTRAL_PIPELINE_REQUIRED', status: 503, statusCode: 503 });
}
// Copy header values once. Node uses strings and occasionally string arrays.
// Keep JSON semantics for unusual header values supplied by adapters.
function captureBinding(req) {
  const headers = req.headers || {};
  const keys = Object.keys(headers);
  const values = keys.map(key => headers[key]);
  const ordinary = values.every(value => typeof value === 'string'
    || Array.isArray(value) && value.every(item => typeof item === 'string'));
  const raw = req.rawHeaders;
  if (raw != null && (!Array.isArray(raw) || raw.some(value => typeof value !== 'string'))) throw failure();
  return {
    method: String(req.method || '').toUpperCase(), url: String(req.url || ''),
    host: String(headers.host || ''), origin: String(headers.origin || ''),
    referer: String(headers.referer || headers.referrer || ''),
    raw: raw == null ? raw : raw.slice(),
    keys: ordinary ? keys : null,
    values: ordinary ? values.map(value => Array.isArray(value) ? value.slice() : value) : JSON.stringify(headers)
  };
}
function sameList(expected, current) {
  if (!Array.isArray(current) || current.length !== expected.length) return false;
  for (let i = 0; i < expected.length; i++) if (current[i] !== expected[i]) return false;
  return true;
}
function bindingMatches(req, binding) {
  const headers = req.headers || {};
  if (binding.method !== String(req.method || '').toUpperCase() || binding.url !== String(req.url || '')
      || binding.host !== String(headers.host || '') || binding.origin !== String(headers.origin || '')
      || binding.referer !== String(headers.referer || headers.referrer || '')) return false;
  if (binding.raw == null ? req.rawHeaders !== binding.raw : !sameList(binding.raw, req.rawHeaders)) return false;
  if (binding.keys === null) return binding.values === JSON.stringify(headers);
  const keys = Object.keys(headers);
  if (keys.length !== binding.keys.length) return false;
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i], expected = binding.values[i], actual = headers[key];
    if (key !== binding.keys[i] || (Array.isArray(expected) ? !sameList(expected, actual) : expected !== actual)) return false;
  }
  return true;
}
function transportCancelled(req, res) {
  return req.aborted === true || (req.signal && req.signal.aborted === true)
    || (res.destroyed === true && res.writableFinished !== true);
}
// A disconnected client cannot receive a response. A still-writable adapter
// can expose an AbortSignal for a server-side cancellation; finish it once.
function stopTransport(res) {
  if (!res.destroyed && !res.writableEnded && typeof res.end === 'function') {
    if (res.headersSent) res.end();
    else {
      res.statusCode = 503;
      if (typeof res.setHeader === 'function') {
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
      }
      res.end('{"ok":false,"code":"REQUEST_CANCELLED"}');
    }
  }
  return { passed: false, value: undefined };
}
function shape(stages) {
  return Array.isArray(stages) && Object.isFrozen(stages) && stages.length === STAGES.length
    && STAGES.every((name, i) => Object.hasOwn(stages, i) && stages[i] && Object.isFrozen(stages[i])
      && stages[i].name === name && typeof stages[i].guard === 'function');
}
function policy(guards) {
  if (!guards || !Object.isFrozen(guards) || Object.keys(guards).length !== STAGES.length) throw failure();
  const stages = Object.freeze(STAGES.map(name => {
    if (!Object.prototype.hasOwnProperty.call(guards, name) || typeof guards[name] !== 'function') throw failure();
    return Object.freeze({ name, guard: guards[name] });
  }));
  if (!shape(stages)) throw failure();
  return stages;
}
async function run(req, res, route, stages, invoke) {
  if (!req || typeof req !== 'object' || !res || !ROUTES.has(route) || !shape(stages)
      || typeof invoke !== 'function' || receipts.has(req)) throw failure();
  if (transportCancelled(req, res) || res.writableEnded === true) return stopTransport(res);
  const receipt = { req, res, route, stages, binding: captureBinding(req), phase: 'guard', index: -1, count: 0, context: null };
  receipts.set(req, receipt);
  let cancellation;
  function active(policyDenied = false) {
    if (receipts.get(req) !== receipt || receipt.phase !== 'guard' || !bindingMatches(req, receipt.binding)) return false;
    if (!policyDenied && transportCancelled(req, res)) {
      cancellation = failure();
      throw cancellation;
    }
    return true;
  }
  try {
    // Keep the first policy callback asynchronous, as in the original executor.
    await Promise.resolve();
    for (let index = 0; index < stages.length; index++) {
      if (receipt.count !== index || !active()) throw failure();
      receipt.index = index;
      let calls = 0, guardResult, guardFinished = false;
      const stage = stages[index];
      const guarded = Object.freeze({ ...stage, guard: async ctx => {
        if (++calls !== 1 || receipt.index !== index || receipt.count !== index || !active()
            || !ctx || ctx.req !== req || ctx.res !== res
            || (receipt.context && receipt.context !== ctx)) throw failure();
        receipt.context = ctx;
        guardResult = await stage.guard(ctx);
        const policyDenied = guardResult === false || (guardResult && guardResult.ok === false);
        if (receipt.index !== index || receipt.count !== index || !active(policyDenied) || ctx.req !== req || ctx.res !== res) throw failure();
        guardFinished = true;
        return guardResult;
      } });
      const result = await invoke(guarded, index);
      if (result !== PASSED) { receipt.phase = 'blocked'; return { passed: false, value: result }; }
      if (calls !== 1 || !guardFinished || guardResult === false || guardResult && guardResult.ok === false) throw failure();
      receipt.count += 1;
    }
    if (receipt.count !== STAGES.length || receipt.index !== STAGES.length - 1 || !active()
        || receipt.context.req !== req || receipt.context.res !== res) throw failure();
    if (res.writableEnded === true) { receipt.phase = 'blocked'; return stopTransport(res); }
    receipt.phase = 'handler';
    return Object.freeze({ passed: true });
  } catch (error) {
    receipt.phase = 'blocked';
    // Preserve independent policy errors, including those raised by a guard
    // when the socket closes concurrently. Only our own cancellation is benign.
    if (cancellation && error === cancellation) return stopTransport(res);
    throw error;
  }
}
function assertPassed(req, res, route) {
  const receipt = receipts.get(req);
  if (!receipt || receipt.phase !== 'handler' || receipt.count !== STAGES.length
      || receipt.index !== STAGES.length - 1 || !bindingMatches(req, receipt.binding)
      || res && receipt.res !== res || route && receipt.route !== route) throw failure();
  return true;
}
function at(req, route, index) {
  const receipt = receipts.get(req);
  return !!(receipt && receipt.phase === 'guard' && receipt.route === route && receipt.index === index
    && receipt.count === index && bindingMatches(req, receipt.binding));
}
function restoreWorkerUrl(req, res, restore) {
  assertPassed(req, res, 'worker');
  if (typeof restore !== 'function') throw failure();
  const receipt = receipts.get(req), previousUrl = req.url;
  try {
    restore(req);
    const restoredUrl = req.url;
    req.url = previousUrl;
    assertPassed(req, res, 'worker');
    req.url = restoredUrl;
    receipt.binding.url = String(restoredUrl || '');
  } catch (error) {
    receipt.phase = 'blocked';
    throw error;
  }
}
function close(req, res) {
  const receipt = receipts.get(req);
  if (receipt && receipt.res === res) { receipt.phase = 'closed'; receipts.delete(req); }
}
function audit(req) {
  const receipt = receipts.get(req);
  return receipt ? Object.freeze({ route: receipt.route, phase: receipt.phase, completed: receipt.count,
    current: receipt.index, stage: STAGES[receipt.index] || '' }) : null;
}
module.exports = Object.freeze({ version: 'dirac-central-executor-v545', stages: STAGES, PASSED, policy, run, assertPassed, at, restoreWorkerUrl, close, audit });

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
function fingerprint(req) {
  const h = req && req.headers || {};
  return JSON.stringify([String(req && req.method || '').toUpperCase(), String(req && req.url || ''),
    String(h.host || ''), String(h.origin || ''), String(h.referer || h.referrer || '')]);
}
function shape(stages) {
  return Array.isArray(stages) && Object.isFrozen(stages) && stages.length === STAGES.length
    && stages.every((stage, i) => stage && Object.isFrozen(stage) && stage.name === STAGES[i] && typeof stage.guard === 'function');
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
  const receipt = { req, res, route, stages, binding: fingerprint(req), phase: 'guard', index: -1, count: 0, context: null };
  receipts.set(req, receipt);
  try {
    const outcome = await stages.reduce((previous, stage, index) => previous.then(async stopped => {
      if (stopped) return stopped;
      if (receipts.get(req) !== receipt || receipt.phase !== 'guard' || receipt.count !== index || receipt.binding !== fingerprint(req)) throw failure();
      receipt.index = index;
      let calls = 0, guardResult, guardFinished = false;
      // A stage closure is valid only while this exact receipt is active.
      // Recheck after await so cancellation cannot revive a closed pipeline.
      const guarded = Object.freeze({ ...stage, guard: async ctx => {
        if (++calls !== 1 || receipts.get(req) !== receipt || receipt.phase !== 'guard'
            || receipt.index !== index || receipt.count !== index || receipt.binding !== fingerprint(req)
            || !ctx || ctx.req !== req || ctx.res !== res
            || (receipt.context && receipt.context !== ctx)) throw failure();
        receipt.context = ctx;
        guardResult = await stage.guard(ctx);
        if (receipts.get(req) !== receipt || receipt.phase !== 'guard' || receipt.index !== index
            || receipt.count !== index || receipt.binding !== fingerprint(req)) throw failure();
        guardFinished = true;
        return guardResult;
      } });
      const result = await invoke(guarded, index);
      if (result !== PASSED) { receipt.phase = 'blocked'; return { passed: false, value: result }; }
      if (calls !== 1 || !guardFinished || guardResult === false || guardResult && guardResult.ok === false) throw failure();
      receipt.count += 1;
      return null;
    }), Promise.resolve(null));
    if (outcome) return outcome;
    if (receipts.get(req) !== receipt || receipt.phase !== 'guard' || receipt.count !== STAGES.length
        || receipt.index !== STAGES.length - 1 || receipt.binding !== fingerprint(req)) throw failure();
    receipt.phase = 'handler';
    return Object.freeze({ passed: true });
  } catch (error) { receipt.phase = 'blocked'; throw error; }
}
function assertPassed(req, res, route) {
  const receipt = receipts.get(req);
  if (!receipt || receipt.phase !== 'handler' || receipt.count !== STAGES.length
      || receipt.index !== STAGES.length - 1 || receipt.binding !== fingerprint(req)
      || res && receipt.res !== res || route && receipt.route !== route) throw failure();
  return true;
}
function at(req, route, index) {
  const receipt = receipts.get(req);
  return !!(receipt && receipt.phase === 'guard' && receipt.route === route && receipt.index === index
    && receipt.count === index && receipt.binding === fingerprint(req));
}
function restoreWorkerUrl(req, res, restore) {
  assertPassed(req, res, 'worker');
  if (typeof restore !== 'function') throw failure();
  const receipt = receipts.get(req), previousUrl = req.url;
  restore(req);
  const restoredUrl = req.url;
  req.url = previousUrl;
  try { assertPassed(req, res, 'worker'); }
  catch (error) { receipt.phase = 'blocked'; throw error; }
  req.url = restoredUrl;
  receipt.binding = fingerprint(req);
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

'use strict';

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
let resetHandlerCache = null;

function resetHandler() {
  if (resetHandlerCache) return resetHandlerCache;
  let handler;
  try { handler = require('./chat.js'); }
  catch (_) { throw new Error('DIRAC_SECURITY_RESET_HANDLER_UNAVAILABLE'); }
  if (!hasCentralSecurityParity(handler)
      || handler.__diracCentralPipelineHashV221 !== centralHandler.__diracCentralPipelineHashV221) {
    throw new Error('DIRAC_SECURITY_RESET_HANDLER_CENTRAL_PARITY_INVALID');
  }
  resetHandlerCache = handler;
  return resetHandlerCache;
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

async function keamananHandler(req, res) {
  const parsed = parseExactRequest(req);
  if (!parsed.ok) {
    if (parsed.allow && parsed.allow.length) {
      try { res.setHeader('Allow', parsed.allow.join(', ')); } catch (_) {}
      return reject(res, 405, parsed.code);
    }
    return reject(res, 403, parsed.code);
  }

  let targetHandler = centralHandler;
  if (parsed.reset) {
    try { targetHandler = resetHandler(); }
    catch (_) { return reject(res, 503, 'SECURITY_RESET_HANDLER_INVALID'); }
  }

  const originalUrl = req.url;
  try {
    req.url = parsed.canonicalUrl;
    return await targetHandler(req, res);
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

'use strict';

const centralHandler = require('./health.js');

if (typeof centralHandler !== 'function'
    || Object.isFrozen(centralHandler) !== true
    || centralHandler.__diracCentralSecurityGuardV146 !== true
    || centralHandler.__diracCentralArchitectureConsolidationV202 !== true
    || centralHandler.__diracCentralBackendComplianceV230 !== true) {
  throw new Error('DIRAC_SECURITY_ROUTE_CENTRAL_HANDLER_INVALID');
}

const SECURITY_ROUTE_PATH = '/api/keamanan';
const CENTRAL_ROUTE_PATH = '/api/health';

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
  customer_security_untrust_device: Object.freeze(new Set(['POST', 'OPTIONS']))
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
    canonicalUrl: CENTRAL_ROUTE_PATH + (rawQuery ? '?' + rawQuery : '')
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
Object.defineProperty(keamananHandler, '__diracCentralSecurityGuardV146', { value: true, enumerable: false });
Object.defineProperty(keamananHandler, '__diracCentralArchitectureConsolidationV202', { value: true, enumerable: false });
Object.defineProperty(keamananHandler, '__diracCentralBackendComplianceV230', { value: true, enumerable: false });
Object.defineProperty(keamananHandler, '__diracSecurityRouteAliasV1', { value: true, enumerable: false });
Object.freeze(keamananHandler);

module.exports = keamananHandler;

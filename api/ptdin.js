'use strict';

// Deploy beside the authoritative health.js in the same API application.
// No session is issued, copied or trusted by this adapter: every accepted
// request enters the existing, frozen central handler with its original proofs.
const centralHandler = require('./health.js');
const PTDIN_ROUTE = '/api/ptdin';
const CENTRAL_ROUTE = '/api/health';
const PTDIN_PAGES = Object.freeze(new Set(['/website.html', '/topup.html', '/domain.html']));
const PTDIN_ACTIONS = Object.freeze({
  domain_health: Object.freeze(new Set(['GET', 'HEAD', 'OPTIONS'])),
  domain_dashboard_me: Object.freeze(new Set(['GET', 'HEAD', 'OPTIONS'])),
  domain_logout: Object.freeze(new Set(['POST', 'OPTIONS'])),
  security_report: Object.freeze(new Set(['POST', 'OPTIONS'])),
  customer_session_handoff_issue: Object.freeze(new Set(['POST', 'OPTIONS']))
});

function centralSecurityReady(handler) {
  return typeof handler === 'function' && Object.isFrozen(handler)
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
if (!centralSecurityReady(centralHandler)) throw new Error('PTDIN_CENTRAL_HANDLER_INVALID');

function rejectPtdin(res, status, code) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  return res.status(status).json({ ok: false, code, message: 'Permintaan layanan belum dapat diproses.' });
}

function parsePtdinRequest(req) {
  const raw = String(req && req.url || '');
  if (!raw || raw.length > 1800 || /[\u0000-\u0020\u007f#]/.test(raw)) return { code: 'PTDIN_URL_INVALID' };
  const split = raw.indexOf('?');
  if (split < 0 || raw.slice(0, split) !== PTDIN_ROUTE) return { code: 'PTDIN_ROUTE_INVALID' };
  const params = new URLSearchParams(raw.slice(split + 1));
  const actions = params.getAll('action');
  const action = actions.length === 1 ? actions[0] : '';
  if (!/^[a-z][a-z0-9_]{1,79}$/.test(action) || !Object.prototype.hasOwnProperty.call(PTDIN_ACTIONS, action)) return { code: 'PTDIN_ACTION_INVALID' };
  if (req.query && Object.prototype.hasOwnProperty.call(req.query, 'action')
      && (typeof req.query.action !== 'string' || req.query.action !== action)) return { code: 'PTDIN_ACTION_MISMATCH' };
  const method = String(req.method || '').toUpperCase();
  if (!PTDIN_ACTIONS[action].has(method)) return { code: 'PTDIN_METHOD_INVALID', status: 405 };
  const base = String(process.env.DIRAC_BASE_DOMAIN || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^\./, '');
  if (base.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(base)
      || /^\d+$/.test(base.split('.').pop()) || /(?:^|\.)(?:localhost|local|internal)$/.test(base)) return { code: 'PTDIN_DOMAIN_INVALID', status: 503 };
  const origin = 'https://' + base;
  const headers = req.headers || {};
  if (typeof headers.origin !== 'string' || headers.origin !== origin) return { code: 'PTDIN_ORIGIN_INVALID' };
  if (method !== 'OPTIONS') {
    let referrer;
    try { referrer = new URL(String(headers.referer || headers.referrer || '')); }
    catch (_) { return { code: 'PTDIN_PAGE_INVALID' }; }
    if (referrer.origin !== origin || referrer.protocol !== 'https:' || referrer.port
        || referrer.username || referrer.password || referrer.search || referrer.hash
        || !PTDIN_PAGES.has(referrer.pathname)) return { code: 'PTDIN_PAGE_INVALID' };
  }
  return { ok: true, canonicalUrl: CENTRAL_ROUTE + raw.slice(split) };
}

async function ptdinHandler(req, res) {
  const parsed = parsePtdinRequest(req);
  if (!parsed.ok) return rejectPtdin(res, parsed.status || 403, parsed.code);
  const originalUrl = req.url;
  const hadOriginalUrl = Object.prototype.hasOwnProperty.call(req, 'originalUrl');
  const originalOriginalUrl = req.originalUrl;
  try {
    req.url = parsed.canonicalUrl;
    req.originalUrl = parsed.canonicalUrl;
    return await centralHandler(req, res);
  } finally {
    req.url = originalUrl;
    if (hadOriginalUrl) req.originalUrl = originalOriginalUrl; else delete req.originalUrl;
  }
}

Object.defineProperty(ptdinHandler, 'config', { value: centralHandler.config, enumerable: true });
Object.defineProperty(ptdinHandler, '__diracPtdinCentralDelegateV336', { value: true });
Object.freeze(ptdinHandler);
module.exports = ptdinHandler;

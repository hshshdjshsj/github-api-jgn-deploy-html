'use strict';

// PTDIN is intentionally a transport-only adapter.
// It never decides, writes, clears, mirrors, or owns security bans.
// Every request is handed to the authoritative health.js handler unchanged
// except for canonicalizing the API pathname to /api/health.
const centralHandler = require('./health.js');
const CENTRAL_ROUTE = '/api/health';

function centralSecurityReady(handler) {
  return typeof handler === 'function' && Object.isFrozen(handler)
    && handler.__diracCentralSecurityGuardV146 === true
    && handler.__diracCentralArchitectureConsolidationV202 === true
    && handler.__diracCentralHardeningV221 === true
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

function canonicalCentralUrl(req) {
  const raw = String(req && req.url || '');
  const split = raw.indexOf('?');
  const path = split < 0 ? raw : raw.slice(0, split);
  if (path !== '/api/ptdin' || raw.length > 8192 || /[\u0000-\u0020\u007f]/.test(raw)) {
    throw new Error('PTDIN_REQUEST_PATH_INVALID');
  }
  return CENTRAL_ROUTE + (split >= 0 ? raw.slice(split) : '');
}

async function ptdinHandler(req, res) {
  const originalUrl = req.url;
  const hadOriginalUrl = Object.prototype.hasOwnProperty.call(req, 'originalUrl');
  const originalOriginalUrl = req.originalUrl;
  try {
    const canonicalUrl = canonicalCentralUrl(req);
    req.url = canonicalUrl;
    req.originalUrl = canonicalUrl;
    return await centralHandler(req, res);
  } catch (error) {
    if (!error || error.message !== 'PTDIN_REQUEST_PATH_INVALID') throw error;
    res.statusCode = 400;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.end(JSON.stringify({ ok: false, code: 'PTDIN_REQUEST_INVALID' }));
  } finally {
    req.url = originalUrl;
    if (hadOriginalUrl) req.originalUrl = originalOriginalUrl; else delete req.originalUrl;
  }
}

Object.defineProperty(ptdinHandler, 'config', { value: centralHandler.config, enumerable: true });
Object.defineProperty(ptdinHandler, '__diracPtdinCentralDelegateV336', { value: true });
Object.defineProperty(ptdinHandler, '__diracPtdinPureCentralDelegateV353', { value: true });
Object.freeze(ptdinHandler);
module.exports = ptdinHandler;

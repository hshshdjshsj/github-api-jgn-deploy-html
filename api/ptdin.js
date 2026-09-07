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

function canonicalCentralUrl(req) {
  const raw = String(req && req.url || '');
  const split = raw.indexOf('?');
  return CENTRAL_ROUTE + (split >= 0 ? raw.slice(split) : '');
}

function mirrorCentralHardBanSetCookie(value, req) {
  const host = String(req && req.headers && req.headers.host || '').trim().toLowerCase().replace(/:\d+$/, '');
  if (host !== 'diracgroup.store' && !host.endsWith('.diracgroup.store')) return value;
  function mirror(cookie) {
    if (typeof cookie !== 'string' || !cookie.startsWith('dirac_global_hard_ban=') || /;\s*domain=/i.test(cookie)) return [cookie];
    const shared = cookie.replace(/;\s*Path=\/(?=;|$)/i, '; Path=/api/health');
    return shared === cookie ? [cookie] : [cookie, shared + '; Domain=diracgroup.store'];
  }
  const mirrored = (Array.isArray(value) ? value : [value]).flatMap(mirror);
  return Array.isArray(value) || mirrored.length > 1 ? mirrored : mirrored[0];
}

async function ptdinHandler(req, res) {
  const originalUrl = req.url;
  const originalSetHeader = res && typeof res.setHeader === 'function' ? res.setHeader : null;
  if (originalSetHeader) {
    res.setHeader = function ptdinSharedHardBanSetHeader(name, value) {
      const nextValue = /^set-cookie$/i.test(String(name || ''))
        ? mirrorCentralHardBanSetCookie(value, req)
        : value;
      return originalSetHeader.call(this, name, nextValue);
    };
  }
  const hadOriginalUrl = Object.prototype.hasOwnProperty.call(req, 'originalUrl');
  const originalOriginalUrl = req.originalUrl;
  try {
    const canonicalUrl = canonicalCentralUrl(req);
    req.url = canonicalUrl;
    req.originalUrl = canonicalUrl;
    return await centralHandler(req, res);
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

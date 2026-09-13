'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');
const { execFileSync } = require('child_process');

const MODE = String(process.argv[2] || 'main').trim().toLowerCase();
if (!['main', 'recovery'].includes(MODE)) throw new Error('DIRAC_CLOUDFLARE_MODE_INVALID');

process.env.NODE_ENV = 'production';
process.env.DIRAC_TRUSTED_PROXY_MODE = 'standard';
process.env.DIRAC_TRUSTED_PROXY_IPS = '127.0.0.1,::1';
delete process.env.VERCEL;
for (const name of Object.keys(process.env)) {
  if (/^VERCEL_/.test(name)) delete process.env[name];
}

const TLS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'dirac-cf-tls-'));
fs.chmodSync(TLS_DIR, 0o700);
const TLS_KEY = path.join(TLS_DIR, 'key.pem');
const TLS_CERT = path.join(TLS_DIR, 'cert.pem');
execFileSync('openssl', [
  'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '36500',
  '-keyout', TLS_KEY,
  '-out', TLS_CERT,
  '-subj', '/CN=localhost',
  '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'
], { stdio: 'ignore' });
fs.chmodSync(TLS_KEY, 0o600);
fs.chmodSync(TLS_CERT, 0o600);
const key = fs.readFileSync(TLS_KEY);
const cert = fs.readFileSync(TLS_CERT);
fs.rmSync(TLS_DIR, { recursive: true, force: true });

function queryObject(rawUrl) {
  const out = Object.create(null);
  const source = String(rawUrl || '/');
  const queryIndex = source.indexOf('?');
  if (queryIndex < 0) return out;
  const fragmentIndex = source.indexOf('#', queryIndex + 1);
  const query = source.slice(queryIndex + 1, fragmentIndex < 0 ? undefined : fragmentIndex);
  for (const [name, value] of new URLSearchParams(query)) {
    if (!Object.prototype.hasOwnProperty.call(out, name)) out[name] = value;
    else if (Array.isArray(out[name])) out[name].push(value);
    else out[name] = [out[name], value];
  }
  return out;
}

function cookieObject(raw) {
  const out = Object.create(null);
  if (typeof raw !== 'string' || !raw || raw.length > 32768) return out;
  for (const part of raw.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    if (!name || Object.prototype.hasOwnProperty.call(out, name)) continue;
    const value = part.slice(index + 1).trim();
    try { out[name] = decodeURIComponent(value); } catch (_) { out[name] = value; }
  }
  return out;
}

function decorateRequest(req) {
  req.query = queryObject(req.url);
  req.path = String(req.url || '/').split('?', 1)[0];
  req.originalUrl = req.url;
  req.cookies = cookieObject(req.headers && req.headers.cookie);
  return req;
}

function decorateResponse(res) {
  res.status = function status(code) {
    const numeric = Number(code);
    if (!Number.isInteger(numeric) || numeric < 100 || numeric > 599) throw new Error('DIRAC_HTTP_STATUS_INVALID');
    res.statusCode = numeric;
    return res;
  };
  res.json = function json(payload) {
    if (!res.headersSent) res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(payload));
    return res;
  };
  res.send = function send(payload) {
    if (Buffer.isBuffer(payload) || payload instanceof Uint8Array) res.end(payload);
    else if (payload && typeof payload === 'object') res.json(payload);
    else res.end(payload === undefined || payload === null ? '' : String(payload));
    return res;
  };
  res.redirect = function redirect(statusOrUrl, maybeUrl) {
    const status = maybeUrl === undefined ? 307 : Number(statusOrUrl);
    const location = maybeUrl === undefined ? String(statusOrUrl || '') : String(maybeUrl || '');
    if (!Number.isInteger(status) || status < 300 || status > 399 || !location || /[\r\n]/.test(location)) {
      throw new Error('DIRAC_REDIRECT_INVALID');
    }
    res.statusCode = status;
    res.setHeader('Location', location);
    res.end();
    return res;
  };
  res.header = res.set = function setHeader(name, value) {
    res.setHeader(name, value);
    return res;
  };
  return res;
}

let healthHandler;
let ptdinHandler;
let keamananHandler;
let supportHandlerPromise;
let recoveryHandler;

function loadHealth() {
  if (!healthHandler) healthHandler = require('./health.js');
  return healthHandler;
}
function loadPtdin() {
  if (!ptdinHandler) ptdinHandler = require('./ptdin.js');
  return ptdinHandler;
}
function loadKeamanan() {
  if (!keamananHandler) keamananHandler = require('./keamanan.js');
  return keamananHandler;
}
async function loadSupport() {
  if (!supportHandlerPromise) supportHandlerPromise = import('./support.mjs').then((module) => module && module.default);
  const handler = await supportHandlerPromise;
  if (typeof handler !== 'function') throw new Error('DIRAC_SUPPORT_HANDLER_INVALID');
  return handler;
}
function loadRecovery() {
  if (!recoveryHandler) recoveryHandler = require('./health server reco.js');
  return recoveryHandler;
}

async function handlerFor(req) {
  const pathname = String(req.url || '/').split('?', 1)[0];
  if (MODE === 'recovery') {
    if (pathname !== '/api/health') return null;
    return loadRecovery();
  }
  if (pathname === '/api/health') return loadHealth();
  if (pathname === '/api/ptdin') return loadPtdin();
  if (pathname === '/api/keamanan') return loadKeamanan();
  if (pathname === '/api/support') return loadSupport();
  return null;
}

function safeError(res, status, code) {
  if (res.writableEnded) return;
  try {
    if (!res.headersSent) {
      res.statusCode = status;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
    }
    res.end(JSON.stringify({ ok: false, code }));
  } catch (_) {
    try { res.destroy(); } catch (_) {}
  }
}

const tlsServer = https.createServer({ key, cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, async (req, res) => {
  decorateRequest(req);
  decorateResponse(res);
  try {
    const handler = await handlerFor(req);
    if (!handler) return safeError(res, 404, MODE === 'recovery' ? 'DIRAC_RECOVERY_ROUTE_NOT_FOUND' : 'DIRAC_API_ROUTE_NOT_FOUND');
    await handler(req, res);
    if (!res.writableEnded) {
      if (res.headersSent) res.end();
      else safeError(res, 500, 'DIRAC_HANDLER_NO_RESPONSE');
    }
  } catch (error) {
    try {
      console.error('[dirac-cloudflare-adapter]', JSON.stringify({
        mode: MODE,
        code: String(error && (error.code || error.name) || 'ERROR').slice(0, 80)
      }));
    } catch (_) {}
    safeError(res, 500, 'DIRAC_HANDLER_EXECUTION_FAILED');
  }
});

tlsServer.on('clientError', (error, socket) => {
  try { socket.destroy(); } catch (_) {}
});

tlsServer.listen(8443, '127.0.0.1');

function exactForwardHost(req) {
  const raw = String(req.headers && req.headers['x-forwarded-host'] || '').trim().toLowerCase();
  if (!raw || raw.length > 257 || raw.includes(',') || /[\s\x00-\x1f\x7f\\/@]/.test(raw)) return '';
  const host = raw.endsWith(':443') ? raw.slice(0, -4) : raw;
  if (host !== raw && raw !== host + ':443') return '';
  if (host === raw && host.includes(':')) return '';
  if (host === 'localhost') return host;
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host)) return '';
  return host;
}

function proxyHeaders(req) {
  const headers = { ...req.headers };
  const host = exactForwardHost(req);
  if (!host) return null;
  headers.host = host;
  headers['x-forwarded-host'] = host;
  headers['x-forwarded-proto'] = 'https';
  delete headers.connection;
  delete headers['proxy-connection'];
  delete headers['keep-alive'];
  delete headers.upgrade;
  delete headers.te;
  delete headers.trailer;
  return headers;
}

const proxy = http.createServer((req, res) => {
  if (req.url === '/__dirac_cf_ready' && req.method === 'GET') {
    res.statusCode = 204;
    res.setHeader('Cache-Control', 'no-store');
    return res.end();
  }

  const headers = proxyHeaders(req);
  if (!headers) return safeError(res, 400, 'DIRAC_EDGE_HOST_INVALID');

  const upstream = https.request({
    host: '127.0.0.1',
    port: 8443,
    method: req.method,
    path: req.url,
    headers,
    ca: cert,
    rejectUnauthorized: true,
    servername: 'localhost',
    checkServerIdentity: (hostname, peerCert) => {
      if (hostname !== 'localhost') return new Error('DIRAC_INTERNAL_TLS_HOST_INVALID');
      return tls.checkServerIdentity(hostname, peerCert);
    }
  }, (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode || 502, upstreamRes.statusMessage, upstreamRes.headers);
    upstreamRes.pipe(res);
  });

  upstream.on('error', () => safeError(res, 502, 'DIRAC_INTERNAL_TLS_UNAVAILABLE'));
  req.on('aborted', () => upstream.destroy());
  req.pipe(upstream);
});

proxy.on('clientError', (error, socket) => {
  try { socket.destroy(); } catch (_) {}
});
proxy.listen(8080, '0.0.0.0');

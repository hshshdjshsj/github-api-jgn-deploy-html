'use strict';

// Request-driven retirement only. No scheduler, timer, retry, or background loop.
const RPC = '/rest/v1/rpc/dirac_cleanup_completed_passkey_sync_v1';
const TABLE = '/rest/v1/dirac_persistent_bans';
const MAINTENANCE_RPC = '/rest/v1/rpc/dirac_request_cleanup_v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const BATCH = 16;
const SELECT = 'security_key,record_json,blocked_until_ms,expires_at,updated_at,revision';
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;

function createOperationCleanupV1(deps) {
  const permits = new WeakMap();
  const maintenancePermits = new WeakMap();
  let nextSweepAt = 0;
  const ready = ctx => Boolean(ctx && ctx.req && ctx.req.__diracCentralSecurityGuardPassedV146 === true
    && deps.context() === ctx && deps.fullyPassed(ctx, ctx.req) === true);
  const recordKind = row => {
    if (!row || typeof row !== 'object' || Array.isArray(row)
        || !Number.isSafeInteger(Number(row.revision)) || Number(row.revision) < 1
        || !ISO.test(row.expires_at) || !ISO.test(row.updated_at)
        || !Number.isSafeInteger(Date.parse(row.expires_at)) || !Number.isSafeInteger(Date.parse(row.updated_at))
        || Number(row.blocked_until_ms) !== 0) return '';
    const r = row.record_json;
    if (!r || typeof r !== 'object' || Array.isArray(r) || !HASH.test(String(r.token_hash || ''))
        || r.blocked_until_ms !== undefined && Number(r.blocked_until_ms) !== 0) return '';
    const keys = Object.keys(r);
    if (/^passkey-a2f-jti:[A-Za-z0-9_-]{43}$/.test(row.security_key)
        && keys.every(k => ['token_hash','expiresAtMs','used','usedAtMs','blocked_until_ms'].includes(k))
        && typeof r.used === 'boolean' && Number.isSafeInteger(r.expiresAtMs) && r.expiresAtMs > 0
        && (r.usedAtMs === undefined || Number.isSafeInteger(r.usedAtMs) && r.usedAtMs > 0)) return 'challenge';
    if (/^passkey-a2f-used:[A-Za-z0-9_-]{43}$/.test(row.security_key)
        && keys.every(k => ['type','token_hash','usedAtMs','blocked_until_ms'].includes(k))
        && r.type === 'passkey_a2f_one_time_claim_v194'
        && Number.isSafeInteger(r.usedAtMs) && r.usedAtMs > 0) return 'claim';
    return '';
  };
  const expired = (row, cutoff) => {
    const kind = recordKind(row), r = row && row.record_json;
    return Boolean(kind && Date.parse(row.expires_at) <= cutoff
      && (kind === 'claim' ? r.usedAtMs <= cutoff - 120000 : r.expiresAtMs <= cutoff)
      && (r.usedAtMs === undefined || r.usedAtMs <= cutoff));
  };

  async function sweepExpiredChallenges() {
    const ctx = deps.context();
    if (!ready(ctx)) return false;
    const now = Date.now();
    if (now < nextSweepAt) return false;
    nextSweepAt = now + 60000;
    const maintenanceOptions = Object.freeze({method:'POST',auth:'service',db:'security',body:Object.freeze({p_limit:512})});
    const legacyOptions = Object.freeze({...maintenanceOptions,db:'legacy'});
    maintenancePermits.set(ctx, new Set([maintenanceOptions,legacyOptions]));
    try { await Promise.allSettled([deps.request(MAINTENANCE_RPC, maintenanceOptions),deps.request(MAINTENANCE_RPC, legacyOptions)]); }
    finally { maintenancePermits.delete(ctx); }
    const cutoff = now - 30000;
    const response = await deps.request(TABLE + '?select=' + encodeURIComponent(SELECT)
      + '&security_key=like.passkey-a2f-*&blocked_until_ms=eq.0&expires_at=lte.'
      + encodeURIComponent(new Date(cutoff).toISOString()) + '&order=expires_at.asc,security_key.asc&limit=' + BATCH,
      {method:'GET',auth:'service'}).catch(() => null);
    if (!response || response.ok !== true || !Array.isArray(response.data) || response.data.length > BATCH) return false;
    const candidates = response.data.filter(row => expired(row, cutoff));
    if (!candidates.length) return true;
    if (new Set(candidates.map(r => r.security_key)).size !== candidates.length) return false;
    const claims = candidates.filter(row => recordKind(row) === 'claim');
    let counterparts = [];
    if (claims.length) {
      const keys = claims.map(r => 'passkey-a2f-jti:' + r.security_key.slice('passkey-a2f-used:'.length));
      const paired = await deps.request(TABLE + '?select=' + encodeURIComponent(SELECT)
        + '&security_key=in.(' + keys.map(encodeURIComponent).join(',') + ')&limit=' + keys.length,
        {method:'GET',auth:'service'}).catch(() => null);
      if (!paired || paired.ok !== true || !Array.isArray(paired.data) || paired.data.length > keys.length
          || paired.data.some(r => !keys.includes(r.security_key))
          || new Set(paired.data.map(r => r.security_key)).size !== paired.data.length) return false;
      counterparts = paired.data;
    }
    const safe = candidates.filter(row => {
      if (recordKind(row) !== 'claim') return true;
      const key = 'passkey-a2f-jti:' + row.security_key.slice('passkey-a2f-used:'.length);
      const challenge = counterparts.find(r => r.security_key === key);
      return !challenge || expired(challenge, cutoff)
        && challenge.record_json.token_hash === row.record_json.token_hash;
    });
    if (!safe.length || !ready(ctx)) return true;
    const clauses = safe.map(row => 'and(security_key.eq.' + row.security_key
      + ',revision.eq.' + Number(row.revision) + ',blocked_until_ms.eq.0,expires_at.eq.' + row.expires_at
      + ',updated_at.eq.' + row.updated_at + ')');
    const removed = await deps.request(TABLE + '?security_key=like.passkey-a2f-*&or=' + encodeURIComponent('(' + clauses.join(',') + ')')
      + '&expires_at=lte.' + encodeURIComponent(new Date(cutoff).toISOString()) + '&select=security_key',
      {method:'DELETE',auth:'service',prefer:'return=representation'}).catch(() => null);
    return Boolean(removed && removed.ok === true && Array.isArray(removed.data)
      && removed.data.length <= safe.length
      && removed.data.every(row => safe.some(r => r.security_key === row.security_key)));
  }

  async function retireConsumedChallenge(proof) {
    const ctx = deps.context();
    if (!ready(ctx) || ctx.action !== 'dirac_mfa_passkey_verify' || ctx.method !== 'POST'
        || !proof || proof.claimed !== true || !/^[A-Za-z0-9_-]{43}$/.test(proof.jti)
        || !HASH.test(proof.tokenHash)) return false;
    const key = 'passkey-a2f-jti:' + proof.jti;
    // The independently committed passkey-a2f-used receipt is deliberately NOT deleted.
    // A stale/unconsumed replacement cannot match these atomic DELETE predicates.
    const condition = '(record_json->>used.eq.true,record_json->>token_hash.eq.' + proof.tokenHash + ')';
    const result = await deps.request(TABLE + '?security_key=eq.' + encodeURIComponent(key)
      + '&blocked_until_ms=eq.0&and=' + encodeURIComponent(condition) + '&select=security_key',
      {method:'DELETE',auth:'service',prefer:'return=representation'}).catch(() => null);
    return Boolean(result && result.ok === true && Array.isArray(result.data)
      && result.data.length <= 1 && result.data.every(row => row && row.security_key === key));
  }

  function allowsRpc(action, url, method, authMode) {
    const ctx = deps.context(), permit = ctx && permits.get(ctx);
    return Boolean(permit && ready(ctx) && action === 'passkey_sync_push'
      && ctx.action === action && ctx.method === 'POST' && ctx.classification === 'server'
      && method === 'POST' && authMode === 'service' && url.pathname === RPC && url.search === '');
  }

  function allowsRequest(path, options) {
    const ctx = deps.context(), maintenance = ctx && maintenancePermits.get(ctx);
    if (maintenance && ready(ctx) && path === MAINTENANCE_RPC && maintenance.has(options)
        && options.method === 'POST' && options.auth === 'service' && ['security','legacy'].includes(options.db)
        && options.body.p_limit === 512 && Object.keys(options.body).join(',') === 'p_limit') return true;
    const permit = ctx && permits.get(ctx);
    if (!permit || !ready(ctx) || path !== RPC || options.method !== 'POST' || options.auth !== 'service'
        || !['legacy','security'].includes(options.db) || options.bearer || options.prefer) return false;
    return JSON.stringify(options.body) === permit.body;
  }

  async function afterSyncAck(proof) {
    const ctx = deps.context();
    if (!ready(ctx) || ctx.action !== 'passkey_sync_push' || ctx.method !== 'POST'
        || ctx.classification !== 'server' || permits.has(ctx)) return false;
    const signed = deps.syncEvidence(ctx.req);
    if (!signed || signed.eventId !== proof.eventId || !UUID.test(proof.eventId)
        || !UUID.test(proof.passkeyId) || !Number.isSafeInteger(proof.eventVersion) || proof.eventVersion < 1
        || !/^[a-f0-9]{128}$/.test(proof.rowSha512)) return false;
    const body = Object.freeze({p_event_id:proof.eventId,p_passkey_id:proof.passkeyId,
      p_event_version:proof.eventVersion,p_row_sha512:proof.rowSha512,p_limit:BATCH});
    permits.set(ctx, Object.freeze({body:JSON.stringify(body)}));
    try {
      const results = await Promise.allSettled([
        deps.request(RPC,{method:'POST',auth:'service',db:'legacy',body}),
        deps.request(RPC,{method:'POST',auth:'service',db:'security',body})
      ]);
      return results.every(r => r.status === 'fulfilled' && r.value && r.value.ok === true
        && r.value.data && r.value.data.ok === true);
    } finally { permits.delete(ctx); }
  }

  return Object.freeze({sweepExpiredChallenges,afterSyncAck,allowsRpc,allowsRequest,retireConsumedChallenge});
}

module.exports = {createOperationCleanupV1};

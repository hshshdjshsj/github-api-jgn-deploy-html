'use strict';

// The PT endpoint enters the unchanged central security pipeline first. Its
// page-specific business projections run only through the full-pass dispatcher.
const centralHandler = require('./health.js');
const CAPABILITIES = Object.freeze({ profile_edit: false, dns_edit: false,
  live_tracking: false, wallet: false, ticket_reply: false, account_review: true });
const ORDER_VIEWS = Object.freeze(['invoice', 'parfum', 'projects', 'topup', 'shipment']);
const DIGITAL_SERVICES = Object.freeze(['topup_game', 'isi_pulsa', 'paket_data', 'isi_saldo', 'isi_saldo_etoll', 'transfer_luar_negeri']);
const PTDIN_CENTRAL_CONTRACTS_V403 = Object.freeze({
  customer_security_account_request: Object.freeze({
    allowed: Object.freeze(['request_type']), required: Object.freeze(['request_type']), enumField: 'request_type',
    enumValues: Object.freeze(['security_review', 'export_data', 'deactivate_account', 'reactivate_account'])
  })
});

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
    && handler.__diracCentralRuntimeLockV230 && handler.__diracCentralRuntimeLockV230.ok === true
    && typeof handler.__diracCentralPtdinEntryV402 === 'function';
}
if (!centralSecurityReady(centralHandler)) throw new Error('PTDIN_CENTRAL_HANDLER_INVALID');

function cleanText(value, maximum) {
  return String(value == null ? '' : value).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, maximum);
}
function invoiceLegalIdentifier(value, minimumDigits, maximumDigits) {
  if (typeof value !== 'string' || value.length > 40 || /[^0-9 .-]/.test(value)) return '';
  const text = value.trim();
  if (!/^[0-9]+(?:[ .-][0-9]+)*$/.test(text)) return '';
  const digits = text.replace(/[ .-]/g, '').length;
  return digits >= minimumDigits && digits <= maximumDigits ? text : '';
}
function ownRows(value, maximum) {
  return Array.isArray(value) ? value.filter((row) => row && typeof row === 'object' && !Array.isArray(row)).slice(0, maximum) : [];
}
function orderMatchesView(order, view) {
  const service = cleanText(order.service_type, 80).toLowerCase();
  if (view === 'parfum' || view === 'shipment') return service === 'parfum';
  if (view === 'projects') return service === 'jasa_website' || service === 'pengembangan_website';
  if (view === 'topup') return DIGITAL_SERVICES.includes(service);
  return true;
}
function orderSummary(rows) {
  const summary = rows.reduce((out, row) => {
    if (row.payment_status === 'unpaid') {
      out.unpaid += 1;
      const amount = Number(row.total);
      if (Number.isSafeInteger(amount) && amount >= 0 && Number.isSafeInteger(out.unpaid_total + amount)) out.unpaid_total += amount;
    } else if (row.payment_status === 'paid') out.paid += 1;
    if (row.order_status === 'pending' || row.order_status === 'pending_payment') out.pending += 1;
    else if (row.order_status === 'processing') out.processing += 1;
    else if (row.order_status === 'completed') out.completed += 1;
    else if (row.order_status === 'failed' || row.order_status === 'cancelled') out.failed += 1;
    return out;
  }, { total_orders: rows.length, unpaid: 0, paid: 0, pending: 0, processing: 0, completed: 0, failed: 0, unpaid_total: 0 });
  return summary;
}

function moneyValue(value) {
  const amount = Number(value);
  return Number.isSafeInteger(amount) && amount >= 0 ? amount : 0;
}
function safeIsoEdge(rows, newest) {
  let picked = null;
  for (const row of rows) {
    const time = Date.parse(String(row && row.created_at || ''));
    if (!Number.isFinite(time)) continue;
    if (!picked || (newest ? time > picked.time : time < picked.time)) picked = { time, value: String(row.created_at) };
  }
  return picked ? picked.value : null;
}
function orderAnalytics(rows) {
  const services = new Map();
  const stats = rows.reduce((out, row) => {
    const key = cleanText(row.service_type || row.service_label || 'order', 80).toLowerCase() || 'order';
    services.set(key, (services.get(key) || 0) + 1);
    const amount = moneyValue(row.total ?? row.total_price);
    if (Number.isSafeInteger(out.total_value + amount)) out.total_value += amount;
    if (row.payment_status === 'paid') {
      out.paid_count += 1;
      if (Number.isSafeInteger(out.paid_total + amount)) out.paid_total += amount;
    } else if (row.payment_status === 'unpaid') {
      out.unpaid_count += 1;
      if (Number.isSafeInteger(out.unpaid_total + amount)) out.unpaid_total += amount;
    }
    if (row.order_status === 'processing') out.processing_count += 1;
    else if (row.order_status === 'completed') out.completed_count += 1;
    else if (row.order_status === 'pending' || row.order_status === 'pending_payment') out.pending_count += 1;
    const time = Date.parse(String(row && row.created_at || ''));
    if (Number.isFinite(time)) {
      if (!out.latest || time > out.latest.time) out.latest = { time, value: String(row.created_at) };
      if (!out.first || time < out.first.time) out.first = { time, value: String(row.created_at) };
    }
    return out;
  }, { total_value: 0, paid_total: 0, unpaid_total: 0, paid_count: 0, unpaid_count: 0, processing_count: 0, completed_count: 0, pending_count: 0, latest: null, first: null });
  let topService = '', topCount = 0;
  services.forEach((count, key) => { if (count > topCount) { topService = key; topCount = count; } });
  return {
    record_count: rows.length,
    total_value: stats.total_value,
    paid_total: stats.paid_total,
    unpaid_total: stats.unpaid_total,
    paid_count: stats.paid_count,
    unpaid_count: stats.unpaid_count,
    processing_count: stats.processing_count,
    completed_count: stats.completed_count,
    pending_count: stats.pending_count,
    latest_order_at: stats.latest ? stats.latest.value : null,
    first_order_at: stats.first ? stats.first.value : null,
    top_service: topService || null,
    top_service_count: topCount,
    scope: 'latest_120_records_max'
  };
}
function domainAnalytics(rows) {
  const stats = rows.reduce((out, row) => {
    const items = ownRows(row.domain_order_items, 100);
    out.domain_count += items.length || (row.domain_name ? 1 : 0);
    items.forEach((item) => {
      const renewal = moneyValue(item.renewal_price);
      if (Number.isSafeInteger(out.renewal_reference_total + renewal)) out.renewal_reference_total += renewal;
    });
    if (row.payment_status === 'paid') out.paid_count += 1;
    else if (row.payment_status === 'unpaid') out.unpaid_count += 1;
    const amount = moneyValue(row.total_price);
    if (Number.isSafeInteger(out.total_value + amount)) out.total_value += amount;
    const time = Date.parse(String(row && row.created_at || ''));
    if (Number.isFinite(time) && (!out.latest || time > out.latest.time)) out.latest = { time, value: String(row.created_at) };
    return out;
  }, { domain_count: 0, paid_count: 0, unpaid_count: 0, total_value: 0, renewal_reference_total: 0, latest: null });
  return {
    order_count: rows.length,
    domain_count: stats.domain_count,
    paid_count: stats.paid_count,
    unpaid_count: stats.unpaid_count,
    total_value: stats.total_value,
    renewal_reference_total: stats.renewal_reference_total,
    latest_order_at: stats.latest ? stats.latest.value : null
  };
}
function securityAnalytics(overview, events = ownRows(overview.events, 120), tickets = ownRows(overview.account_requests, 120)) {
  const counts = overview.counts && typeof overview.counts === 'object' ? overview.counts : {};
  const eventStats = events.reduce((out, row) => {
    if (cleanText(row.risk_level, 20).toLowerCase() === 'high') out.high_risk_count += 1;
    if (cleanText(row.status, 20).toLowerCase() === 'info') out.info_count += 1;
    const time = Date.parse(String(row && row.created_at || ''));
    if (Number.isFinite(time) && (!out.latest || time > out.latest.time)) out.latest = { time, value: String(row.created_at) };
    return out;
  }, { high_risk_count: 0, info_count: 0, latest: null });
  const ticketStats = tickets.reduce((out, row) => {
    const status = cleanText(row.status, 30).toLowerCase();
    if (status === 'pending') out.ticket_pending += 1;
    else if (status === 'processing') out.ticket_processing += 1;
    else if (status === 'completed') out.ticket_completed += 1;
    return out;
  }, { ticket_pending: 0, ticket_processing: 0, ticket_completed: 0 });
  return {
    event_count: events.length,
    high_risk_count: eventStats.high_risk_count,
    info_count: eventStats.info_count,
    latest_event_at: eventStats.latest ? eventStats.latest.value : null,
    ticket_count: tickets.length,
    ticket_pending: ticketStats.ticket_pending,
    ticket_processing: ticketStats.ticket_processing,
    ticket_completed: ticketStats.ticket_completed,
    active_session_count: Number.isSafeInteger(Number(counts.sessions)) ? Number(counts.sessions) : 0
  };
}
function projectResponse(action, view, payload, profile) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || payload.ok !== true) return payload;
  if (action === 'domain_health' || action === 'domain_logout') return payload;
  const out = { ...payload, service: 'dirac-ptdin', capabilities: CAPABILITIES };
  if (action === 'domain_dashboard_me') {
    const verifiedEmail = cleanText(payload.user && payload.user.email, 254).toLowerCase();
    const matchingProfile = profile && profile.email && profile.email.toLowerCase() === verifiedEmail;
    out.profile_available = Boolean(matchingProfile);
    out.profile = matchingProfile ? { name: cleanText(profile.name, 120), email: cleanText(profile.email, 254), phone: cleanText(profile.phone, 80) } : null;
  } else if (action === 'my_orders') {
    out.view = view || 'invoice';
    const allOrders = ownRows(payload.orders, 120);
    out.orders = out.view === 'invoice' ? allOrders : allOrders.filter((order) => orderMatchesView(order, out.view));
    out.summary = orderSummary(out.orders);
    out.analytics = orderAnalytics(out.orders);
    out.account_analytics = out.orders.length === allOrders.length ? { ...out.analytics } : orderAnalytics(allOrders);
    const latestOrder = allOrders[0] || null;
    out.profile_supplement = {
      phone: cleanText(latestOrder && latestOrder.customer_phone, 80),
      address: cleanText(latestOrder && (latestOrder.shipping_address || latestOrder.customer_address || latestOrder.address || latestOrder.alamat || latestOrder.delivery_address || latestOrder.recipient_address), 520),
      registered_at: cleanText(payload.user && payload.user.created_at, 64) || null,
      customer_since: out.account_analytics.first_order_at
    };
    out.partial = Boolean(payload.diagnostics && (payload.diagnostics.generic_orders_ready === false || payload.diagnostics.domain_orders_ready === false));
    if (out.view === 'invoice') out.invoice_issuer = {
      legal_name: 'PT Dirac Inovasi Nusantara',
      nib: invoiceLegalIdentifier(process.env.DIRAC_INVOICE_NIB, 13, 13),
      npwp: invoiceLegalIdentifier(process.env.DIRAC_INVOICE_NPWP, 15, 16)
    };
    if (out.view === 'shipment') {
      out.shipment_data_ready = out.orders.every(order => order.shipment_data_ready !== false);
      out.tracking_available = out.orders.some(order => order.shipment_data_ready === true
        && order.shipment && typeof order.shipment === 'object' && !Array.isArray(order.shipment)
        && /^[A-Za-z0-9][A-Za-z0-9 ._-]{2,99}$/.test(String(order.shipment.tracking_number || ''))
        && Number.isSafeInteger(order.shipment.revision) && order.shipment.revision > 0);
      out.partial = out.partial || !out.shipment_data_ready;
    }
    if (out.view === 'projects') out.project_progress_available = false;
    if (out.view === 'topup') out.balance_available = false;
  } else if (action === 'domain_orders') {
    const domains = ownRows(payload.data, 120);
    out.domains = JSON.parse(JSON.stringify(domains));
    out.data = domains;
    out.domain_summary = domainAnalytics(out.domains);
  } else if (action === 'customer_security_overview') {
    const overview = payload.overview && typeof payload.overview === 'object' ? payload.overview : {};
    out.view = view || 'notifications';
    const tickets = ownRows(overview.account_requests, 120);
    const events = ownRows(overview.events, 120);
    out.tickets = JSON.parse(JSON.stringify(tickets));
    out.notifications = JSON.parse(JSON.stringify(events));
    out.partial = overview.partial === true || payload.security_data_ready === false;
    out.warnings = Array.isArray(overview.warnings) ? JSON.parse(JSON.stringify(overview.warnings.slice(0, 20))) : [];
    out.security_summary = securityAnalytics(overview, events, tickets);
    out.security_settings = overview.settings && typeof overview.settings === 'object' ? {
      email_active: overview.settings.email_active === true,
      two_factor_enabled: overview.settings.two_factor_enabled === true,
      two_factor_method: cleanText(overview.settings.two_factor_method, 40),
      notify_new_login: overview.settings.notify_new_login === true,
      notify_password_change: overview.settings.notify_password_change === true,
      notify_new_device: overview.settings.notify_new_device === true,
      password_changed_at: overview.settings.password_changed_at || null,
      last_security_check_at: overview.settings.last_security_check_at || null
    } : null;
    out.ticket_kind = 'account_security_request';
  }
  return out;
}

// V430: the caller supplies only a frozen capability issued after the complete central guard.
const INVOICE_FORMAT_V430 = 'DIRAC-INVOICE-1';
const INVOICE_VERSION_V430 = 'dirac-invoice-v430';
const INVOICE_ACTIONS_V430 = Object.freeze(['invoice_email_status', 'invoice_email_send', 'invoice_email_unlock']);
const invoiceCryptoV430 = require('crypto');
const invoiceZlibV430 = require('zlib');
function invoiceErrorV430(code, status = 503) { return Object.assign(new Error(code), { code, status }); }
function invoiceIsoV430(value) { return Number.isSafeInteger(value) ? new Date(value).toISOString() : null; }
function invoiceHashV430(value) { return invoiceCryptoV430.createHash('sha256').update(value).digest('hex'); }
function invoicePdfValidateV430(value) {
  if (typeof value !== 'string' || value.length > 1398104 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw invoiceErrorV430('INVOICE_PDF_INVALID', 400);
  const pdf = Buffer.from(value, 'base64');
  if (!pdf.length || pdf.length > 1048576 || pdf.toString('base64') !== value) throw invoiceErrorV430('INVOICE_PDF_INVALID', 400);
  let offset = 0; const offsets = [0];
  function exact(text) { const bytes = Buffer.from(text, 'ascii'); if (!pdf.subarray(offset, offset + bytes.length).equals(bytes)) throw invoiceErrorV430('INVOICE_PDF_INVALID', 400); offset += bytes.length; }
  function integer() { const match = /^[1-9][0-9]{0,6}/.exec(pdf.toString('ascii', offset, Math.min(offset + 8, pdf.length))); if (!match) throw invoiceErrorV430('INVOICE_PDF_INVALID', 400); offset += match[0].length; return Number(match[0]); }
  function object(id, text) { offsets[id] = offset; exact(id + ' 0 obj\n' + text + '\nendobj\n'); }
  exact('%PDF-1.4\n'); object(1, '<< /Type /Catalog /Pages 2 0 R >>');
  offsets[2] = offset; exact('2 0 obj\n<< /Type /Pages /Count '); const count = integer();
  if (count < 1 || count > 20) throw invoiceErrorV430('INVOICE_PDF_PAGE_LIMIT', 400);
  exact(' /Kids [' + Array.from({ length: count }, (_, index) => (3 + index * 3) + ' 0 R').join(' ') + '] >>\nendobj\n');
  for (let index = 0; index < count; index += 1) {
    const page = 3 + index * 3, content = page + 1, image = page + 2;
    object(page, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] /Resources << /XObject << /Im0 ' + image + ' 0 R >> >> /Contents ' + content + ' 0 R >>');
    const commands = 'q\n595.28 0 0 841.89 0 0 cm\n/Im0 Do\nQ\n';
    object(content, '<< /Length ' + commands.length + ' >>\nstream\n' + commands + 'endstream');
    offsets[image] = offset; exact(image + ' 0 obj\n<< /Type /XObject /Subtype /Image /Width 1240 /Height 1754 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length ');
    const size = integer(); exact(' >>\nstream\n');
    if (size > pdf.length - offset) throw invoiceErrorV430('INVOICE_PDF_INVALID', 400);
    const compressed = pdf.subarray(offset, offset + size); let inflated;
    try { inflated = invoiceZlibV430.inflateSync(compressed, { maxOutputLength: 1240 * 1754 * 3, info: true }); }
    catch (_) { throw invoiceErrorV430('INVOICE_PDF_IMAGE_INVALID', 400); }
    if (!inflated || inflated.buffer.length !== 1240 * 1754 * 3 || inflated.engine.bytesWritten !== size) throw invoiceErrorV430('INVOICE_PDF_IMAGE_INVALID', 400);
    inflated.buffer.fill(0); offset += size; exact('\nendstream\nendobj\n');
  }
  const xref = offset, size = 3 + count * 3;
  exact('xref\n0 ' + size + '\n0000000000 65535 f \n');
  for (let id = 1; id < size; id += 1) exact(String(offsets[id]).padStart(10, '0') + ' 00000 n \n');
  exact('trailer\n<< /Size ' + size + ' /Root 1 0 R >>\nstartxref\n' + xref + '\n%%EOF\n');
  if (offset !== pdf.length) throw invoiceErrorV430('INVOICE_PDF_INVALID', 400);
  return pdf;
}
function invoiceRandomCodeV430() {
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const code = String(invoiceCryptoV430.randomInt(100000000)).padStart(8, '0');
    if (/^(\d)\1{7}$/.test(code) || /^(\d{2})\1{3}$/.test(code) || /^(\d{4})\1$/.test(code)) continue;
    const step = Number(code[1]) - Number(code[0]);
    if (Math.abs(step) === 1 && Array.from(code).every((digit, index) => index === 0 || Number(digit) - Number(code[index - 1]) === step)) continue;
    return code;
  }
  throw invoiceErrorV430('INVOICE_RANDOM_UNAVAILABLE');
}
function invoicePackSecretV430(secret, storageKey, aad) {
  const iv = invoiceCryptoV430.randomBytes(12), cipher = invoiceCryptoV430.createCipheriv('aes-256-gcm', storageKey, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const data = Buffer.concat([cipher.update(JSON.stringify(secret), 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { iv: iv.toString('base64url'), data: data.toString('base64url') };
}
function invoiceUnpackSecretV430(record, storageKey, aad) {
  if (!record || !record.secret || !/^[A-Za-z0-9_-]{16}$/.test(String(record.secret.iv || '')) || !/^[A-Za-z0-9_-]{100,400}$/.test(String(record.secret.data || ''))) throw invoiceErrorV430('INVOICE_KEY_UNAVAILABLE');
  try {
    const data = Buffer.from(record.secret.data, 'base64url'), decipher = invoiceCryptoV430.createDecipheriv('aes-256-gcm', storageKey, Buffer.from(record.secret.iv, 'base64url'));
    decipher.setAAD(Buffer.from(aad, 'utf8')); decipher.setAuthTag(data.subarray(-16));
    const plain = Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]);
    const secret = JSON.parse(plain.toString('utf8')); plain.fill(0);
    if (Object.keys(secret).sort().join(',') !== 'code,dek' || !/^\d{8}$/.test(secret.code) || !/^[A-Za-z0-9_-]{43}$/.test(secret.dek)) throw new Error('invalid');
    return secret;
  } catch (_) { throw invoiceErrorV430('INVOICE_KEY_UNAVAILABLE'); }
}
async function invoiceBusinessV430(req, res, ops) {
  if (!ops || !Object.isFrozen(ops) || ops.version !== INVOICE_VERSION_V430 || typeof ops.assertFullGuard !== 'function' || !INVOICE_ACTIONS_V430.includes(ops.action)) throw invoiceErrorV430('INVOICE_FULL_GUARD_REQUIRED', 403);
  const identity = ops.identity, input = ops.body || {};
  ops.assertFullGuard();
  if (!identity || !Object.isFrozen(identity) || !/^[0-9a-f-]{36}$/.test(identity.customerId) || !/^[0-9a-f-]{36}$/.test(identity.userId) || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(identity.email)) throw invoiceErrorV430('INVOICE_OWNER_REQUIRED', 403);
  const order = String(input.order_id || ''), kind = String(input.kind || '');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(order) || !['regular', 'domain'].includes(kind)) return res.status(400).json({ ok: false, code: 'INVOICE_SCOPE_INVALID' });
  const scope = invoiceHashV430(JSON.stringify([identity.userId, identity.customerId, kind, order]));
  const prefix = 's2s-invoice-v430:', rateKey = prefix + 'send:' + scope, headKey = prefix + 'latest:' + scope;
  const fileKey = id => prefix + 'file:' + invoiceHashV430(scope + ':' + id);
  const recordAad = (id, issuerOrigin = identity.origin) => [INVOICE_VERSION_V430, identity.userId, identity.customerId, issuerOrigin, kind, order, id].join(':');
  let storageKey = null;
  function secretOf(record) { if (!storageKey) storageKey = ops.storageKey(); return invoiceUnpackSecretV430(record, storageKey, recordAad(record.file_id, record.issuer_origin)); }
  function validRecord(record, id) { return !!(record && record.version === INVOICE_VERSION_V430 && record.scope === scope && record.kind === kind && record.order_id === order && record.file_id === id && /^[A-Za-z0-9_-]{43}$/.test(id) && /^[a-f0-9]{64}$/.test(record.file_sha256) && ['pending', 'accepted', 'failed', 'unknown'].includes(record.status) && Number.isSafeInteger(record.created_at) && Number.isSafeInteger(record.expires_at) && record.expires_at > Date.now()); }
  async function read(key) { const result = await ops.read(key); if (!result || result.ok !== true) throw invoiceErrorV430('INVOICE_STORAGE_UNAVAILABLE'); return result.found ? result.record : null; }
  async function publish(status, body) { ops.assertFullGuard(); await ops.verifyOwner(); ops.assertFullGuard(); return res.status(status).json(body); }
  async function statusResponse() {
    const [claimed, latest] = await Promise.all([read(rateKey), read(headKey)]);
    const pointer = claimed || latest, next = claimed && Number.isSafeInteger(claimed.next_allowed_at) ? claimed.next_allowed_at : null;
    if (!pointer) return publish(200, { ok: true, available: false, status: 'idle', accepted: false, unlock_key: null, file_id: null, next_allowed_at: null, expires_at: null });
    if (pointer.version !== INVOICE_VERSION_V430 || pointer.scope !== scope || !/^[A-Za-z0-9_-]{43}$/.test(String(pointer.file_id || ''))) throw invoiceErrorV430('INVOICE_RECORD_INVALID');
    const record = await read(fileKey(pointer.file_id));
    if (!record) return publish(200, { ok: true, available: false, status: 'unknown', accepted: false, unlock_key: null, file_id: pointer.file_id, next_allowed_at: invoiceIsoV430(next), expires_at: null });
    if (!validRecord(record, pointer.file_id)) throw invoiceErrorV430('INVOICE_RECORD_INVALID');
    const status = record.status === 'pending' && Date.now() - record.created_at > 120000 ? 'unknown' : record.status;
    const key = status === 'failed' ? null : secretOf(record).code;
    return publish(200, { ok: true, available: key !== null, status, accepted: status === 'accepted', unlock_key: key, file_id: record.file_id, next_allowed_at: invoiceIsoV430(next), expires_at: invoiceIsoV430(record.expires_at) });
  }
  try {
    await ops.verifyOwner();
    if (ops.action === 'invoice_email_status') return await statusResponse();
    if (ops.action === 'invoice_email_unlock') {
      const id = String(input.file_id || ''), code = String(input.code || ''), hash = String(input.file_sha256 || '');
      if (!/^[A-Za-z0-9_-]{43}$/.test(id) || !/^\d{8}$/.test(code) || !/^[a-f0-9]{64}$/.test(hash)) return publish(400, { ok: false, code: 'INVOICE_UNLOCK_INVALID' });
      if (await ops.takeRate(prefix + 'unlock:' + scope) !== true) return publish(429, { ok: false, code: 'INVOICE_UNLOCK_RATE_LIMITED' });
      const record = await read(fileKey(id));
      if (!validRecord(record, id) || record.status === 'failed' || record.file_sha256 !== hash) return publish(403, { ok: false, code: 'INVOICE_UNLOCK_INVALID' });
      const secret = secretOf(record);
      if (!invoiceCryptoV430.timingSafeEqual(Buffer.from(secret.code), Buffer.from(code))) return publish(403, { ok: false, code: 'INVOICE_UNLOCK_INVALID' });
      return publish(200, { ok: true, decrypt_key: secret.dek, file_id: id, expires_at: invoiceIsoV430(record.expires_at) });
    }
    const pdf = invoicePdfValidateV430(input.pdf_base64), now = Date.now(), next = now + 86400000, expiry = now + 30 * 86400000;
    const id = invoiceCryptoV430.randomBytes(32).toString('base64url');
    const pointer = { version: INVOICE_VERSION_V430, scope, file_id: id, next_allowed_at: next, created_at: now, revision: invoiceCryptoV430.randomBytes(16).toString('hex') };
    if (await ops.claim(rateKey, pointer, 86400) !== true) { pdf.fill(0); const existing = await read(rateKey); if (!existing || existing.version !== INVOICE_VERSION_V430 || existing.scope !== scope) throw invoiceErrorV430('INVOICE_STORAGE_UNAVAILABLE'); return publish(429, { ok: false, code: 'INVOICE_SEND_DAILY_LIMIT', next_allowed_at: invoiceIsoV430(existing.next_allowed_at) }); }
    const dek = invoiceCryptoV430.randomBytes(32), iv = invoiceCryptoV430.randomBytes(12), code = invoiceRandomCodeV430();
    let record, accepted = false, attempted = false;
    try {
      const cipher = invoiceCryptoV430.createCipheriv('aes-256-gcm', dek, iv);
      cipher.setAAD(Buffer.from(INVOICE_FORMAT_V430 + ':' + id + ':' + kind + ':' + order, 'utf8'));
      const ciphertext = Buffer.concat([cipher.update(pdf), cipher.final(), cipher.getAuthTag()]); pdf.fill(0);
      const attachment = Buffer.from(JSON.stringify({ format: INVOICE_FORMAT_V430, file_id: id, order_id: order, kind, iv: iv.toString('base64url'), ciphertext: ciphertext.toString('base64url') }), 'utf8');
      if (attachment.length > 1420000) throw invoiceErrorV430('INVOICE_ATTACHMENT_LIMIT', 400);
      if (!storageKey) storageKey = ops.storageKey();
      record = { version: INVOICE_VERSION_V430, scope, file_id: id, kind, order_id: order, issuer_origin: identity.origin, file_sha256: invoiceHashV430(attachment), status: 'pending', created_at: now, expires_at: expiry, revision: invoiceCryptoV430.randomBytes(16).toString('hex'), secret: invoicePackSecretV430({ dek: dek.toString('base64url'), code }, storageKey, recordAad(id)) };
      if (await ops.claim(fileKey(id), record, 30 * 86400) !== true) throw invoiceErrorV430('INVOICE_STORAGE_UNAVAILABLE');
      const previousHead = await read(headKey);
      const headStored = previousHead ? await ops.replace(headKey, previousHead.revision, pointer, 30 * 86400) : await ops.claim(headKey, pointer, 30 * 86400);
      if (headStored !== true) throw invoiceErrorV430('INVOICE_STORAGE_UNAVAILABLE');
      await ops.verifyOwner(); ops.assertFullGuard(); attempted = true;
      const sent = await ops.mail({ fileId: id, content: attachment });
      accepted = !!(sent && sent.accepted === true && sent.ok === true);
      const state = accepted ? 'accepted' : sent && sent.ambiguous === false ? 'failed' : 'unknown';
      const replacement = { ...record, status: state, revision: invoiceCryptoV430.randomBytes(16).toString('hex') };
      if (await ops.replace(fileKey(id), record.revision, replacement, 30 * 86400) !== true) return publish(503, { ok: false, code: 'INVOICE_SEND_STATUS_UNCONFIRMED', status: 'unknown', next_allowed_at: invoiceIsoV430(next) });
      record = replacement;
      if (!accepted) return publish(503, { ok: false, code: state === 'failed' ? 'INVOICE_SEND_FAILED' : 'INVOICE_SEND_STATUS_UNCONFIRMED', status: state, next_allowed_at: invoiceIsoV430(next) });
      return publish(200, { ok: true, accepted: true, status: 'accepted', unlock_key: code, file_id: id, next_allowed_at: invoiceIsoV430(next), expires_at: invoiceIsoV430(expiry) });
    } catch (error) {
      if (record && record.status === 'pending') {
        const failed = { ...record, status: attempted ? 'unknown' : 'failed', revision: invoiceCryptoV430.randomBytes(16).toString('hex') };
        try { await ops.replace(fileKey(id), record.revision, failed, 30 * 86400); } catch (_) {}
      }
      if (attempted) return publish(503, { ok: false, code: 'INVOICE_SEND_STATUS_UNCONFIRMED', status: 'unknown', next_allowed_at: invoiceIsoV430(next) });
      throw error;
    } finally { pdf.fill(0); dek.fill(0); }
  } catch (error) {
    ops.assertFullGuard();
    const allowed = ['INVOICE_PDF_INVALID', 'INVOICE_PDF_PAGE_LIMIT', 'INVOICE_PDF_IMAGE_INVALID', 'INVOICE_ATTACHMENT_LIMIT', 'INVOICE_STORAGE_UNAVAILABLE', 'INVOICE_KEY_UNAVAILABLE', 'INVOICE_RECORD_INVALID', 'INVOICE_RANDOM_UNAVAILABLE', 'INVOICE_OWNER_UNAVAILABLE'];
    return res.status(allowed.includes(error && error.code) && error.status === 400 ? 400 : 503).json({ ok: false, code: allowed.includes(error && error.code) ? error.code : 'INVOICE_TEMPORARILY_UNAVAILABLE' });
  } finally { if (storageKey) storageKey.fill(0); }
}

async function ptdinBusiness(req, res, operations) {
  if (!operations || !Object.isFrozen(operations) || typeof operations.run !== 'function'
      || typeof operations.readProfile !== 'function') throw new Error('PTDIN_FULL_GUARD_OPERATIONS_REQUIRED');
  const action = String(operations.action || '');
  const view = cleanText(req.query && req.query.type, 40);
  if ((action === 'my_orders' && view && !ORDER_VIEWS.includes(view))
      || (action === 'customer_security_overview' && view && !['tickets', 'notifications'].includes(view))) {
    return res.status(400).json({ ok: false, code: 'PTDIN_VIEW_INVALID', message: 'Pilihan halaman tidak valid.' });
  }
  const profile = action === 'domain_dashboard_me' && req.method === 'GET'
    && new URL(String(req.headers && (req.headers.referer || req.headers.referrer) || '')).pathname === '/profil.html'
    ? await operations.readProfile()
    : null;
  // run is single-use and request-bound. It retains the existing account
  // request rate limit, MFA, ownership, payment and response middleware.
  return operations.run((payload) => projectResponse(action, view, payload, profile));
}

async function ptdinHandler(req, res) {
  return centralHandler.__diracCentralPtdinEntryV402(req, res);
}
Object.defineProperty(ptdinHandler, 'config', { value: centralHandler.config, enumerable: true });
Object.defineProperty(ptdinHandler, '__diracPtdinBusinessV402', { value: ptdinBusiness });
Object.defineProperty(ptdinHandler, '__diracInvoiceBusinessV430', { value: invoiceBusinessV430 });
Object.defineProperty(ptdinHandler, '__diracPtdinCentralContractsV403', { value: PTDIN_CENTRAL_CONTRACTS_V403 });
Object.defineProperty(ptdinHandler, '__diracPtdinCentralGuardedBusinessV402', { value: true });
Object.freeze(ptdinHandler);
module.exports = ptdinHandler;

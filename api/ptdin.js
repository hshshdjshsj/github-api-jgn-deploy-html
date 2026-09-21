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
    if (out.view === 'shipment') out.tracking_available = false;
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
Object.defineProperty(ptdinHandler, '__diracPtdinCentralContractsV403', { value: PTDIN_CENTRAL_CONTRACTS_V403 });
Object.defineProperty(ptdinHandler, '__diracPtdinCentralGuardedBusinessV402', { value: true });
Object.freeze(ptdinHandler);
module.exports = ptdinHandler;

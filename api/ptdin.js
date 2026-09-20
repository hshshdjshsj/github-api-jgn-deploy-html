'use strict';

// The PT endpoint enters the unchanged central security pipeline first. Its
// page-specific business projections run only through the full-pass dispatcher.
const centralHandler = require('./health.js');
const CAPABILITIES = Object.freeze({ profile_edit: false, dns_edit: false,
  live_tracking: false, wallet: false, ticket_reply: false, account_review: true });
const ORDER_VIEWS = Object.freeze(['invoice', 'parfum', 'projects', 'topup', 'shipment']);
const DIGITAL_SERVICES = Object.freeze(['topup_game', 'isi_pulsa', 'paket_data', 'isi_saldo', 'isi_saldo_etoll', 'transfer_luar_negeri']);

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
  return {
    total_orders: rows.length,
    unpaid: rows.filter((row) => row.payment_status === 'unpaid').length,
    paid: rows.filter((row) => row.payment_status === 'paid').length,
    pending: rows.filter((row) => row.order_status === 'pending' || row.order_status === 'pending_payment').length,
    processing: rows.filter((row) => row.order_status === 'processing').length,
    completed: rows.filter((row) => row.order_status === 'completed').length,
    failed: rows.filter((row) => row.order_status === 'failed' || row.order_status === 'cancelled').length,
    unpaid_total: rows.filter((row) => row.payment_status === 'unpaid').reduce((sum, row) => {
      const amount = Number(row.total);
      return Number.isSafeInteger(amount) && amount >= 0 && Number.isSafeInteger(sum + amount) ? sum + amount : sum;
    }, 0)
  };
}

function moneyValue(value) {
  const amount = Number(value);
  return Number.isSafeInteger(amount) && amount >= 0 ? amount : 0;
}
function safeMoneySum(rows, predicate) {
  return rows.reduce((sum, row) => {
    if (predicate && !predicate(row)) return sum;
    const amount = moneyValue(row.total ?? row.total_price);
    return Number.isSafeInteger(sum + amount) ? sum + amount : sum;
  }, 0);
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
  rows.forEach((row) => {
    const key = cleanText(row.service_type || row.service_label || 'order', 80).toLowerCase() || 'order';
    services.set(key, (services.get(key) || 0) + 1);
  });
  let topService = '', topCount = 0;
  services.forEach((count, key) => { if (count > topCount) { topService = key; topCount = count; } });
  return {
    record_count: rows.length,
    total_value: safeMoneySum(rows),
    paid_total: safeMoneySum(rows, (row) => row.payment_status === 'paid'),
    unpaid_total: safeMoneySum(rows, (row) => row.payment_status === 'unpaid'),
    paid_count: rows.filter((row) => row.payment_status === 'paid').length,
    unpaid_count: rows.filter((row) => row.payment_status === 'unpaid').length,
    processing_count: rows.filter((row) => row.order_status === 'processing').length,
    completed_count: rows.filter((row) => row.order_status === 'completed').length,
    pending_count: rows.filter((row) => row.order_status === 'pending' || row.order_status === 'pending_payment').length,
    latest_order_at: safeIsoEdge(rows, true),
    first_order_at: safeIsoEdge(rows, false),
    top_service: topService || null,
    top_service_count: topCount,
    scope: 'latest_120_records_max'
  };
}
function domainAnalytics(rows) {
  let itemCount = 0, renewalReferenceTotal = 0;
  rows.forEach((row) => {
    const items = ownRows(row.domain_order_items, 100);
    itemCount += items.length || (row.domain_name ? 1 : 0);
    items.forEach((item) => {
      const renewal = moneyValue(item.renewal_price);
      if (Number.isSafeInteger(renewalReferenceTotal + renewal)) renewalReferenceTotal += renewal;
    });
  });
  return {
    order_count: rows.length,
    domain_count: itemCount,
    paid_count: rows.filter((row) => row.payment_status === 'paid').length,
    unpaid_count: rows.filter((row) => row.payment_status === 'unpaid').length,
    total_value: rows.reduce((sum, row) => {
      const amount = moneyValue(row.total_price);
      return Number.isSafeInteger(sum + amount) ? sum + amount : sum;
    }, 0),
    renewal_reference_total: renewalReferenceTotal,
    latest_order_at: safeIsoEdge(rows, true)
  };
}
function securityAnalytics(overview) {
  const events = ownRows(overview.events, 120);
  const tickets = ownRows(overview.account_requests, 120);
  const counts = overview.counts && typeof overview.counts === 'object' ? overview.counts : {};
  return {
    event_count: events.length,
    high_risk_count: events.filter((row) => cleanText(row.risk_level, 20).toLowerCase() === 'high').length,
    info_count: events.filter((row) => cleanText(row.status, 20).toLowerCase() === 'info').length,
    latest_event_at: safeIsoEdge(events, true),
    ticket_count: tickets.length,
    ticket_pending: tickets.filter((row) => cleanText(row.status, 30).toLowerCase() === 'pending').length,
    ticket_processing: tickets.filter((row) => cleanText(row.status, 30).toLowerCase() === 'processing').length,
    ticket_completed: tickets.filter((row) => cleanText(row.status, 30).toLowerCase() === 'completed').length,
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
    out.orders = allOrders.filter((order) => orderMatchesView(order, out.view));
    out.summary = orderSummary(out.orders);
    out.analytics = orderAnalytics(out.orders);
    out.account_analytics = orderAnalytics(allOrders);
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
    out.domains = JSON.parse(JSON.stringify(ownRows(payload.data, 120)));
    out.data = ownRows(payload.data, 120);
    out.domain_summary = domainAnalytics(out.domains);
  } else if (action === 'customer_security_overview') {
    const overview = payload.overview && typeof payload.overview === 'object' ? payload.overview : {};
    out.view = view || 'notifications';
    out.tickets = JSON.parse(JSON.stringify(ownRows(overview.account_requests, 120)));
    out.notifications = JSON.parse(JSON.stringify(ownRows(overview.events, 120)));
    out.partial = overview.partial === true || payload.security_data_ready === false;
    out.warnings = Array.isArray(overview.warnings) ? JSON.parse(JSON.stringify(overview.warnings.slice(0, 20))) : [];
    out.security_summary = securityAnalytics(overview);
    out.security_settings = overview.settings && typeof overview.settings === 'object' ? {
      email_active: overview.settings.email_active === true,
      two_factor_enabled: overview.settings.two_factor_enabled === true,
      two_factor_method: cleanText(overview.settings.two_factor_method, 40),
      notify_new_login: overview.settings.notify_new_login === true,
      notify_password_change: overview.settings.notify_password_change === true,
      notify_new_device: overview.settings.notify_new_device === true,
      password_changed_at: overview.settings.password_changed_at || null,
      last_security_check_at: overview.settings.last_security_check_at || null,
      account_locked: overview.settings.account_locked === true,
      locked_until: overview.settings.locked_until || null
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
Object.defineProperty(ptdinHandler, '__diracPtdinCentralGuardedBusinessV402', { value: true });
Object.freeze(ptdinHandler);
module.exports = ptdinHandler;

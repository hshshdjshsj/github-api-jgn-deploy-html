'use strict';

const DIRAC_BASE_DOMAIN = readBaseDomainEnv();
const SITE_URL = process.env.SITE_URL || `https://${DIRAC_BASE_DOMAIN}`;
const CHECK_RESI_URL = process.env.CHECK_RESI_URL || `${SITE_URL.replace(/\/$/, '')}/cekresi.html`;
const WHATSAPP_URL = process.env.WHATSAPP_URL || 'https://wa.me/6287892523968';
const TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 18000);

const STORE = globalThis.__DIRAC_AI_STORE__ || (globalThis.__DIRAC_AI_STORE__ = { rate: new Map() });

function readBaseDomainEnv() {
  const value = String(process.env.DIRAC_BASE_DOMAIN || '').trim().toLowerCase().replace(/\.$/, '');
  if (!value || value.length > 253 || value.includes('://') || value.includes('/') || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) {
    throw new Error('DIRAC_BASE_DOMAIN_INVALID_OR_MISSING');
  }
  return value;
}

function configuredAllowedOrigins() {
  const explicit = String(process.env.AI_ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).filter(Boolean);
  return Array.from(new Set([
    `https://${DIRAC_BASE_DOMAIN}`,
    `https://www.${DIRAC_BASE_DOMAIN}`,
    ...explicit
  ]));
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    return res.status(200).json({
      ok: true,
      service: 'dirac-ai-chat',
      time: new Date().toISOString(),
      providers: {
        gemini: getKeys('GEMINI_API_KEYS', 'GEMINI_API_KEY').length > 0,
        groq: getKeys('GROQ_API_KEYS', 'GROQ_API_KEY').length > 0,
        openai: getKeys('OPENAI_API_KEYS', 'OPENAI_API_KEY').length > 0
      }
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json(makeReply('error', 'Method tidak diizinkan.'));
  }

  const traceId = makeTraceId();
  const startedAt = Date.now();

  try {
    const body = req.body || {};
    const message = String(body.message || '').trim().slice(0, 1200);
    const products = Array.isArray(body.products) ? body.products.slice(0, 100) : [];
    const cart = Array.isArray(body.cart) ? body.cart.slice(0, 30) : [];
    const history = Array.isArray(body.history) ? body.history.slice(-12) : [];
    const sessionId = cleanId(req.headers['x-dirac-session'] || body.sessionId || 'anonymous');

    if (!message) {
      return res.status(400).json(makeReply('error', 'Pertanyaan masih kosong.', { traceId }));
    }

    const limited = rateLimit(getIp(req), sessionId);
    if (!limited.allowed) {
      return res.status(429).json(makeReply('rate_limited', 'AI sedang ramai dipakai. Coba lagi sebentar ya.', {
        traceId,
        retryAfterSeconds: limited.retryAfterSeconds
      }));
    }

    const normalizedMessage = normalize(message);
    const historyRaw = history.map((item) => item && item.content ? item.content : '').join(' ');
    const normalizedHistory = normalize(historyRaw);

    if (isSpam(normalizedMessage)) {
      return res.status(200).json(makeReply('conversation', 'Pesannya terlihat seperti spam. Tulis pertanyaan dengan jelas ya.', { traceId }));
    }

    if (isPromptInjection(normalizedMessage)) {
      return res.status(200).json(makeReply('security', 'Saya tidak bisa membuka instruksi sistem, rahasia, token, atau API key. Silakan tanya hal lain.', { traceId }));
    }

    const forcedGeneral = isGeneralKnowledge(normalizedMessage);
    const recommendationHistory = relevantRecommendationHistory(history);
    const contextSource = forcedGeneral ? message : `${recommendationHistory} ${message}`;
    const context = extractContext(contextSource);
    const intent = detectIntent(normalizedMessage, normalizedHistory, context, forcedGeneral);

    const direct = directAnswer(intent, cart, traceId);
    if (direct) return res.status(200).json(direct);

    if (intent.name === 'recommendation_needs_info') {
      const questions = missingQuestions(context).slice(0, 3);
      return res.status(200).json(makeReply('recommendation', buildInfoReply(context, questions), {
        traceId,
        needMoreInfo: true,
        questions,
        analytics: { intent: intent.name, source: 'router', ms: Date.now() - startedAt }
      }));
    }

    const useProducts = intent.name === 'recommendation_ready' || intent.name === 'product_search' || intent.name === 'compare_products';
    const scoredProducts = useProducts ? scoreProducts(products, context, normalizedMessage).slice(0, 8) : [];
    const topProducts = scoredProducts.slice(0, 3).map((item) => item.product);

    if (useProducts && topProducts.length && !hasProvider()) {
      return res.status(200).json(makeReply('commerce', buildProductReply(topProducts), {
        traceId,
        provider: 'local-product-matcher',
        showProducts: true,
        products: publicProducts(topProducts),
        analytics: { intent: intent.name, source: 'local-product-matcher', ms: Date.now() - startedAt }
      }));
    }

    if (!hasProvider()) {
      const fallbackText = intent.name === 'general'
        ? 'AI utama belum aktif karena API key belum disetel di Vercel. Untuk menjawab pertanyaan umum, pelajaran, matematika, IPA, IPS, bahasa Inggris, coding, atau tugas kompleks, aktifkan API key lalu coba lagi.'
        : 'AI utama belum aktif karena API key belum disetel di Vercel. Saya masih bisa bantu link website, cek resi, cara checkout, dan rekomendasi dasar.';
      return res.status(200).json(makeReply('fallback', fallbackText, { traceId }));
    }

    const prompt = buildPrompt({
      message,
      history,
      cart,
      intent,
      context,
      products: useProducts ? scoredProducts.slice(0, 12).map((item) => item.product) : []
    });

    const ai = await callAI({
      prompt,
      general: intent.name === 'general',
      search: shouldUseSearch(normalizedMessage, intent)
    });

    return res.status(200).json(makeReply(useProducts ? 'commerce' : intent.mode, ai.text, {
      traceId,
      provider: ai.provider,
      showProducts: useProducts && topProducts.length > 0,
      products: useProducts ? publicProducts(topProducts) : [],
      analytics: {
        intent: intent.name,
        source: ai.provider,
        failoverUsed: ai.failoverUsed,
        attempts: ai.attempts,
        ms: Date.now() - startedAt
      }
    }));
  } catch (error) {
    return res.status(500).json(makeReply('error', 'Terjadi kendala pada server AI. Silakan coba lagi.', {
      traceId,
      detail: sanitizeError(error)
    }));
  }
};

function setCors(req, res) {
  const allowed = new Set(configuredAllowedOrigins());
  const origin = req.headers && req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', origin && allowed.has(origin) ? origin : '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Dirac-Session');
  res.setHeader('Cache-Control', 'no-store');
}

function makeReply(mode, text, extra = {}) {
  return {
    mode,
    provider: null,
    showProducts: false,
    products: [],
    links: [],
    needMoreInfo: false,
    questions: [],
    reply: text,
    ...extra
  };
}

function makeTraceId() {
  return `dirac_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function normalize(value) {
  return String(value || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function cleanId(value) {
  return String(value || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80) || 'anonymous';
}

function getIp(req) {
  return String(req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || (req.socket && req.socket.remoteAddress) || 'unknown')
    .split(',')[0]
    .trim()
    .slice(0, 80);
}

function sanitizeError(error) {
  return String((error && error.message) || error || 'Unknown error')
    .replace(/AIza[0-9A-Za-z_-]+/g, '[redacted]')
    .replace(/gsk_[0-9A-Za-z_-]+/g, '[redacted]')
    .replace(/sk-[0-9A-Za-z_-]+/g, '[redacted]')
    .slice(0, 500);
}

function rateLimit(ip, sessionId) {
  const now = Date.now();
  const key = `${ip}:${sessionId}`;
  const bucket = STORE.rate.get(key) || { minute: [], hour: [] };
  bucket.minute = bucket.minute.filter((time) => now - time < 60000);
  bucket.hour = bucket.hour.filter((time) => now - time < 3600000);
  const perMinute = Number(process.env.AI_RATE_LIMIT_PER_MINUTE || 20);
  const perHour = Number(process.env.AI_RATE_LIMIT_PER_HOUR || 100);
  if (bucket.minute.length >= perMinute || bucket.hour.length >= perHour) {
    return { allowed: false, retryAfterSeconds: bucket.minute.length >= perMinute ? 60 : 600 };
  }
  bucket.minute.push(now);
  bucket.hour.push(now);
  STORE.rate.set(key, bucket);
  if (STORE.rate.size > 1000) STORE.rate.delete(STORE.rate.keys().next().value);
  return { allowed: true };
}

function isSpam(text) {
  const compact = text.replace(/\s/g, '');
  return /(.)\1{18,}/.test(compact) || (compact.length > 20 && new Set(compact.split('')).size <= 2);
}

function isPromptInjection(text) {
  return /\b(abaikan instruksi|ignore previous|ignore all|system prompt|developer message|api key|secret key|tampilkan token|bocorkan|reveal prompt|show prompt)\b/.test(text);
}

function isGeneralKnowledge(text) {
  const productTerms = /\b(parfum|perfume|produk parfum|wangi parfum|aroma parfum|botol parfum|ml parfum|stok|ready|rekomendasi parfum|checkout|keranjang|resi|paket|kurir)\b/.test(text);
  const generalTerms = /\b(siapa|apa|apa itu|kenapa|mengapa|bagaimana|berapa|dimana|di mana|kapan|jelaskan|buatkan|hitung|rumus|contoh|ringkas|terjemah|translate|bahasa inggris|english|grammar|essay|tugas|pr|soal|matematika|mtk|aljabar|kalkulus|statistika|geometri|trigonometri|fisika|kimia|biologi|ipa|ips|sejarah|geografi|ekonomi|sosiologi|politik|negara|dunia|benua|sungai|amazon|nil|mekong|gunung|samudra|laut|planet|bulan|matahari|langit|hewan|tumbuhan|sel|atom|molekul|energi|listrik|coding|programming|javascript|python|html|css)\b/.test(text);
  return generalTerms && !productTerms;
}

function relevantRecommendationHistory(history) {
  return history
    .filter((item) => {
      const text = normalize(item && item.content ? item.content : '');
      return /\b(parfum|rekomendasi|aroma|wangi|fresh|manis|woody|harian|kantor|formal|hadiah|budget|pria|wanita|unisex)\b/.test(text);
    })
    .map((item) => item.content || '')
    .join(' ');
}

function extractContext(raw) {
  const text = normalize(raw);
  return {
    category: extractCategory(text),
    usage: pick(text, [
      ['harian', /\b(harian|sehari hari|daily)\b/],
      ['kantor', /\b(kantor|kerja|office)\b/],
      ['formal', /\b(formal|acara|meeting|rapat)\b/],
      ['pesta', /\b(pesta|party|event)\b/],
      ['malam', /\b(malam|date|kencan)\b/],
      ['hadiah', /\b(hadiah|kado|gift)\b/],
      ['sekolah', /\b(sekolah|kuliah|kampus)\b/]
    ]),
    scent: pick(text, [
      ['fresh', /\b(fresh|segar|citrus|aquatic|clean|dingin)\b/],
      ['sweet', /\b(manis|sweet|vanilla|fruity|buah|gourmand)\b/],
      ['woody', /\b(woody|wood|oud|amber|musk|leather)\b/],
      ['floral', /\b(floral|rose|bunga)\b/],
      ['soft', /\b(soft|lembut|kalem|tidak menyengat)\b/],
      ['strong', /\b(strong|kuat|tahan lama|awet|projection)\b/],
      ['spicy', /\b(spicy|rempah|hangat)\b/]
    ]),
    gender: pick(text, [
      ['pria', /\b(pria|laki|lelaki|cowok|cowo|suami|masculine|maskulin)\b/],
      ['wanita', /\b(wanita|perempuan|cewek|cewe|istri|feminim)\b/],
      ['unisex', /\b(unisex|semua gender|cowok cewek|pria wanita)\b/]
    ]),
    budget: extractBudget(text)
  };
}

function pick(text, map) {
  for (const [value, pattern] of map) if (pattern.test(text)) return value;
  return null;
}

function extractBudget(text) {
  const rupiah = text.match(/(?:rp\s*)?(\d{2,4})\s*(rb|ribu|k)\b/);
  if (rupiah) return `${rupiah[1]} ribu`;
  const juta = text.match(/(?:rp\s*)?(\d+(?:\.\d+)?)\s*(jt|juta)\b/);
  if (juta) return `${juta[1]} juta`;
  if (/\b(murah|budget rendah|terjangkau)\b/.test(text)) return 'murah';
  if (/\b(premium|mahal|bebas budget)\b/.test(text)) return 'premium';
  return null;
}

function extractCategory(text) {
  if (/\b(niche|nishe|niche fragrance|parfum niche|koleksi niche|luxury niche)\b/.test(text)) return 'niche';
  if (/\b(designer|desainer|parfum designer|brand designer)\b/.test(text)) return 'designer';
  if (/\b(timur tengah|timteng|middle eastern|arab|oud arab)\b/.test(text)) return 'timur_tengah';
  if (/\b(lokal|local|brand lokal)\b/.test(text)) return 'lokal';
  if (/\b(miniso)\b/.test(text)) return 'miniso';
  return null;
}

function detectIntent(text, history, context, forcedGeneral) {
  if (/^(halo|hallo|helo|hello|hai|hi|hii|hiii|hlo|hllo|lo|yo|yoi|p|pp|test|tes|permisi|salam|assalamualaikum|assalamu alaikum|pagi|siang|sore|malam|selamat pagi|selamat siang|selamat sore|selamat malam)$/.test(text)) return { name: 'greeting', mode: 'conversation' };
  if (/^(makasih|terima kasih|terimakasih|thanks|thank you|thx|sip|oke|ok|okay|baik|mantap|siap|noted|gas|nice|keren)$/.test(text)) return { name: 'thanks', mode: 'conversation' };
  if (/^(goblok+|goblog+|tolol+|bodoh+|bego+|anjing+|bangsat+|kampret+)$/i.test(text)) return { name: 'calm_down', mode: 'conversation' };
  if (/^(siapa kamu|kamu siapa|ini siapa|ini ai apa|kamu bot|kamu robot|kamu bisa apa|bisa apa|fitur kamu apa|jelaskan dirimu)$/.test(text)) return { name: 'identity', mode: 'conversation' };
  if (/^(apa kabar|gimana kabarnya|kamu apa kabar|lagi apa|sedang apa|hai apa kabar|halo apa kabar)$/.test(text)) return { name: 'smalltalk', mode: 'conversation' };

  if (/\b(presiden indonesia|presiden ri|presiden republik indonesia)\b/.test(text) && /\b(ada berapa|berapa jumlah|berapa orang|daftar|urutan)\b/.test(text)) return { name: 'president_id_count', mode: 'conversation' };
  if (/\b(presiden indonesia|presiden ri|presiden republik indonesia)\b/.test(text)) return { name: 'president_id_current', mode: 'conversation' };
  if (/\b(presiden amerika|presiden amerika serikat|presiden as|presiden usa|presiden us)\b/.test(text) && /\b(ada berapa|berapa jumlah|berapa orang|daftar|urutan)\b/.test(text)) return { name: 'president_us_count', mode: 'conversation' };

  if (/\b(apa itu dirac|apa itu dirac group|dirac group itu apa|tentang dirac group|profil dirac group|siapa dirac group|dirac group siapa|dirac itu apa|dirac siapa|apa itu toko dirac|apa itu website dirac)\b/.test(text)) return { name: 'brand_info', mode: 'conversation' };

  if (forcedGeneral) return { name: 'general', mode: 'conversation' };

  if (/\b(website|web|situs|link|company profile|profil perusahaan|profile perusahaan|alamat web|alamat website)\b/.test(text) && !/\b(parfum|produk|resi|checkout|beli)\b/.test(text)) return { name: 'website', mode: 'link' };
  if (/\b(resi|cek resi|lacak|tracking|paket|pengiriman|kurir|jne|jnt|j t|sicepat|anteraja|pos|ninja|lion|sap|id express|tiki)\b/.test(text)) return { name: 'tracking', mode: 'link' };
  if (/\b(komplain|keluhan|belum sampai|belum dikirim|rusak|salah barang|refund|retur|return|admin|cs|customer service|bantuan admin)\b/.test(text)) return { name: 'support', mode: 'support' };
  if (/\b(keranjang|cart|checkout|check out|beli|order|pesan|bayar|whatsapp|wa|cara beli|mau beli)\b/.test(text) && !/\b(parfum|produk|rekomendasi|aroma|wangi)\b/.test(text)) return { name: 'checkout', mode: 'checkout' };

  const recommendation = /\b(rekomendasi|rekomendasikan|saran|sarankan|pilihkan|pilih|cocok|suggest|recommend|mau parfum|pengen parfum|butuh parfum)\b/.test(text) || /\b(rekomendasi|parfum buat apa|aroma apa|budget berapa)\b/.test(history);
  const categoryProduct = !!context.category || /\b(niche|nishe|designer|desainer|timteng|timur tengah|lokal|miniso)\b/.test(text);
  const product = /\b(produk|parfum|perfume|wangi|aroma|botol|ml|stok|ready|harga|budget|mahal|murah)\b/.test(text) || categoryProduct;
  const infoCount = [context.usage, context.scent, context.gender, context.budget].filter(Boolean).length;

  // Jika user minta kategori jelas seperti “parfum niche”, langsung masuk mode produk
  // dan jangan dicampur dengan kategori lain seperti Timur Tengah/Designer.
  if (recommendation && context.category) return { name: 'recommendation_ready', mode: 'commerce' };
  if (!recommendation && context.category && product) return { name: 'product_search', mode: 'commerce' };
  if (!recommendation && infoCount > 0 && infoCount < 3) return { name: 'recommendation_needs_info', mode: 'recommendation' };
  if (recommendation && infoCount < 3) return { name: 'recommendation_needs_info', mode: 'recommendation' };
  if (recommendation && infoCount >= 3) return { name: 'recommendation_ready', mode: 'commerce' };
  if (product) return { name: 'product_search', mode: 'commerce' };
  return { name: 'general', mode: 'conversation' };
}

function directAnswer(intent, cart, traceId) {
  if (intent.name === 'greeting') return makeReply('conversation', 'Halo! Saya Dirac AI Assistant. Mau ngobrol dulu atau butuh bantuan seputar parfum, checkout, website, dan cek resi?', { traceId });
  if (intent.name === 'thanks') return makeReply('conversation', 'Sama-sama. Kalau nanti butuh bantuan lagi, tinggal chat saja ya.', { traceId });
  if (intent.name === 'calm_down') return makeReply('conversation', 'Saya paham Anda kesal. Saya akan bantu perbaiki jawabannya. Tulis pertanyaannya dengan jelas, nanti saya jawab langsung tanpa menawarkan produk kalau memang bukan soal belanja.', { traceId });
  if (intent.name === 'identity') return makeReply('conversation', 'Saya Dirac AI Assistant. Saya bisa diajak ngobrol seperti AI biasa, bantu jawab pertanyaan umum, bantu pilih parfum pelan-pelan, arahkan checkout, beri link website, dan arahkan cek resi.', { traceId });
  if (intent.name === 'smalltalk') return makeReply('conversation', 'Kabar saya baik. Anda sendiri bagaimana? Kita bisa ngobrol dulu, tidak harus langsung bahas produk.', { traceId });
  if (intent.name === 'president_id_current') return makeReply('conversation', 'Presiden Indonesia saat ini adalah Prabowo Subianto. Wakil presidennya adalah Gibran Rakabuming Raka. Mereka menjabat untuk periode 2024-2029.', { traceId });
  if (intent.name === 'president_id_count') return makeReply('conversation', 'Indonesia sudah memiliki 8 presiden: Soekarno, Soeharto, B.J. Habibie, Abdurrahman Wahid, Megawati Soekarnoputri, Susilo Bambang Yudhoyono, Joko Widodo, dan Prabowo Subianto.', { traceId });
  if (intent.name === 'president_us_count') return makeReply('conversation', 'Amerika Serikat memiliki 47 nomor presiden. Karena Grover Cleveland dan Donald Trump dihitung dua kali untuk masa jabatan yang tidak berurutan, jumlah orang yang pernah menjadi presiden AS adalah 45 orang.', { traceId });
  if (intent.name === 'brand_info') return makeReply('conversation', `Dirac Group adalah perusahaan yang bergerak di bidang reseller parfum serta pengembangan dan pembuatan website, dengan fokus pada penyediaan produk parfum berkualitas dan layanan digital profesional yang mendukung kebutuhan individu maupun bisnis; melalui komitmen pada kualitas, inovasi, dan pelayanan yang terpercaya, Dirac Group hadir sebagai mitra strategis dalam memenuhi kebutuhan gaya hidup sekaligus memperkuat kehadiran bisnis pelanggan di era digital.\n${SITE_URL}`, { traceId, links: [{ label: 'Buka website Dirac Group', url: SITE_URL }] });
  if (intent.name === 'website') return makeReply('link', `Website resmi Dirac Group ada di sini:\n${SITE_URL}`, { traceId, links: [{ label: 'Buka website Dirac Group', url: SITE_URL }] });
  if (intent.name === 'tracking') return makeReply('link', `Untuk cek resi, buka halaman Cek Resi Dirac Group lalu masukkan nomor resi dan pilih kurir:\n${CHECK_RESI_URL}`, { traceId, links: [{ label: 'Buka Cek Resi', url: CHECK_RESI_URL }] });
  if (intent.name === 'checkout') return makeReply('checkout', 'Untuk membeli, tambahkan produk ke keranjang dulu, lalu buka keranjang dan klik checkout WhatsApp. Kalau ingin dibantu admin langsung, klik tombol WhatsApp.', { traceId, links: [{ label: 'Chat Admin WhatsApp', url: WHATSAPP_URL }], cartCount: Array.isArray(cart) ? cart.length : 0 });
  if (intent.name === 'support') return makeReply('support', 'Maaf atas kendalanya. Supaya admin bisa bantu lebih cepat, siapkan nomor order atau nomor resi Anda lalu hubungi admin WhatsApp.', { traceId, links: [{ label: 'Hubungi Admin WhatsApp', url: WHATSAPP_URL }] });
  return null;
}

function missingQuestions(context) {
  const questions = [];
  if (!context.usage) questions.push('Dipakai buat apa? Harian, kantor, formal, hadiah, atau malam?');
  if (!context.scent) questions.push('Suka aroma apa? Fresh, manis, soft, strong, woody, floral, atau citrus?');
  if (!context.gender) questions.push('Untuk pria, wanita, atau unisex?');
  if (!context.budget) questions.push('Budget sekitar berapa?');
  return questions;
}

function buildInfoReply(context, questions) {
  const known = [];
  if (context.usage) known.push(`pemakaian: ${context.usage}`);
  if (context.scent) known.push(`aroma: ${context.scent}`);
  if (context.category) known.push(`kategori: ${context.category === 'timur_tengah' ? 'Timur Tengah' : context.category}`);
  if (context.gender) known.push(`untuk: ${context.gender}`);
  if (context.budget) known.push(`budget: ${context.budget}`);
  return `${known.length ? `Oke, saya catat ${known.join(', ')}. ` : 'Boleh. '}Supaya rekomendasinya tidak asal, jawab dulu ini ya: ${questions.join(' ')}`;
}

function scoreProducts(products, context, text) {
  const terms = normalize(text).split(' ').filter((term) => term.length > 2);
  const requestedCategory = context.category || extractCategory(normalize(text));
  const boosts = [context.category, context.usage, context.scent, context.gender].filter(Boolean);
  const related = {
    harian: ['fresh', 'clean', 'soft', 'citrus', 'daily', 'segar'],
    kantor: ['fresh', 'clean', 'woody', 'soft', 'office', 'elegan'],
    formal: ['woody', 'oud', 'amber', 'musk', 'elegan', 'strong'],
    hadiah: ['best seller', 'unisex', 'fresh', 'sweet', 'soft'],
    fresh: ['fresh', 'citrus', 'aquatic', 'clean', 'segar'],
    sweet: ['sweet', 'vanilla', 'fruity', 'manis'],
    woody: ['woody', 'oud', 'amber', 'musk'],
    floral: ['floral', 'rose'],
    pria: ['pria', 'men', 'masculine', 'maskulin', 'woody', 'fresh'],
    wanita: ['wanita', 'women', 'feminim', 'floral', 'sweet'],
    unisex: ['unisex', 'fresh', 'clean', 'musk'],
    niche: ['niche', 'premium', 'unique', 'exclusive', 'luxury', 'artistik'],
    designer: ['designer', 'modern', 'versatile', 'branded'],
    timur_tengah: ['timur tengah', 'timteng', 'oud', 'amber', 'spicy'],
    lokal: ['lokal', 'daily', 'clean', 'terjangkau'],
    miniso: ['miniso']
  };
  for (const boost of [...boosts]) if (related[boost]) boosts.push(...related[boost]);

  return products.map((product) => {
    const haystack = normalize([product.id, product.title, product.name, product.category, product.desc, product.description, product.longDesc, product.notes, product.status].join(' '));
    let score = 0;

    if (requestedCategory) {
      if (!categoryMatchesProduct(product, requestedCategory)) {
        return { product, score: -999 };
      }
      score += 120;
    }

    for (const term of terms) {
      if (haystack.includes(term)) score += 4;
      if (normalize(product.title || product.name).includes(term)) score += 6;
      if (normalize(product.category).includes(term)) score += 18;
    }
    for (const boost of boosts) if (haystack.includes(normalize(boost))) score += 7;
    if (product.isTopSeller) score += 8;
    if (isSold(product)) score -= 100;
    return { product, score };
  }).filter((item) => item.score > 0 && !isSold(item.product)).sort((a, b) => b.score - a.score);
}

function isSold(product) {
  return /\b(sold|sold out|kosong|habis|not ready|tidak menjual)\b/.test(normalize(product && product.status));
}

function categoryMatchesProduct(product, category) {
  const cat = normalize(product && product.category);
  const title = normalize(product && (product.title || product.name));
  const hay = normalize([product && product.category, product && product.title, product && product.name, product && product.desc, product && product.longDesc].join(' '));

  if (category === 'niche') return cat === 'niche';
  if (category === 'designer') return cat === 'designer';
  if (category === 'timur_tengah') return cat === 'timur tengah' || hay.includes('timur tengah') || hay.includes('timteng');
  if (category === 'lokal') return cat === 'lokal';
  if (category === 'miniso') return cat === 'miniso' || title.includes('miniso');
  return true;
}

function publicProducts(list) {
  return list.slice(0, 4).map((product) => ({
    id: product.id,
    title: product.title || product.name || 'Produk Dirac',
    name: product.name || product.title || 'Produk Dirac',
    price: Number(product.price || 0),
    img: product.img || product.image || '',
    category: product.category || '',
    status: product.status || 'ready',
    notes: product.notes || '',
    desc: product.desc || product.description || '',
    reason: productReason(product)
  }));
}

function productReason(product) {
  const parts = [];
  if (product.category) parts.push(`kategori ${product.category}`);
  if (product.notes) parts.push(`notes ${String(product.notes).split(',').slice(0, 2).join(', ')}`);
  if (product.status) parts.push(`status ${product.status}`);
  if (product.price) parts.push(`harga Rp${Number(product.price || 0).toLocaleString('id-ID')}`);
  return parts.length ? `Cocok karena ${parts.slice(0, 3).join(', ')}.` : '';
}

function buildProductReply(list) {
  const names = list.slice(0, 3).map((product) => product.title || product.name || 'Produk Dirac').join(', ');
  return names ? `Saya pilihkan ${names}. Silakan lihat kartu produk di bawah ini dan cek detail sebelum checkout.` : 'Saya belum menemukan produk yang cocok. Coba sebutkan aroma, penggunaan, gender, dan budget lebih detail.';
}

function shouldUseSearch(text, intent) {
  return intent.name === 'general' && /\b(siapa|apa|kapan|dimana|berapa|berita|terbaru|sekarang|saat ini|hari ini|current|presiden|menteri|ceo|harga|jadwal)\b/.test(text);
}

function buildPrompt({ message, history, cart, intent, context, products }) {
  const date = new Date().toISOString().slice(0, 10);
  const effectiveHistory = intent.name === 'general' ? [] : history;
  const historyText = effectiveHistory.map((item) => `${item && item.role === 'assistant' ? 'AI' : 'User'}: ${String((item && item.content) || '').slice(0, 500)}`).join('\n') || '-';
  const productText = products.length ? products.map((product, index) => [
    `${index + 1}. ${product.title || product.name || 'Produk Dirac'}`,
    `Kategori: ${product.category || '-'}`,
    `Harga: Rp${Number(product.price || 0).toLocaleString('id-ID')}`,
    `Status: ${product.status || 'ready'}`,
    `Notes: ${product.notes || '-'}`,
    `Deskripsi: ${product.desc || product.description || '-'}`
  ].join(' | ')).join('\n') : '';
  const cartText = cart && cart.length ? cart.map((item) => `- ${item.title || item.name || 'Produk'} x${item.qty || 1}`).join('\n') : 'Keranjang kosong.';

  let system = 'Kamu adalah Dirac AI Assistant. Jawab bahasa Indonesia yang natural, ramah, jelas, dan akurat.';
  if (intent.name === 'general') {
    system += ` Kamu adalah AI umum sekaligus tutor belajar, bukan hanya AI penjualan. Wajib jawab pertanyaan umum dan tugas kompleks bila aman: sejarah dunia, geografi, IPS, IPA, matematika dasar/lanjut, fisika, kimia, biologi, bahasa Inggris, bahasa Indonesia, coding, logika, ringkasan, terjemahan, dan penjelasan konsep. Jangan menolak hanya karena topik tidak terkait parfum. Jangan menawarkan produk, jangan menampilkan rekomendasi parfum, dan jangan mengarahkan checkout kecuali user memintanya. Jika soal hitungan, berikan langkah ringkas. Jika informasi bisa berubah, jawab hati-hati. Tanggal sistem: ${date}. Untuk Presiden Indonesia saat ini: Prabowo Subianto. Jawaban harus selesai utuh, tidak boleh berhenti di tengah kalimat. Untuk jawaban pelajaran panjang, buat penjelasan ringkas tapi lengkap dengan poin bernomor. Pastikan setiap poin penting selesai, dan akhiri dengan kesimpulan singkat agar user tahu jawaban sudah selesai.`;
  } else if (intent.name === 'recommendation_ready' || intent.name === 'product_search') {
    system += ' Kamu adalah konsultan parfum. Gunakan hanya data produk yang diberikan, hindari sold/kosong/not ready, rekomendasikan maksimal 3 produk, jangan mengarang harga/stok. Jika user meminta kategori tertentu seperti Niche, Designer, Timur Tengah, Lokal, atau Miniso, jangan keluar dari kategori tersebut.';
  } else {
    system += ' Gali kebutuhan user pelan-pelan dan jangan langsung jualan jika belum jelas.';
  }

  return [
    system,
    `Intent: ${intent.name}`,
    `Konteks: ${JSON.stringify(context)}`,
    `Riwayat:\n${historyText}`,
    productText ? `Data produk relevan:\n${productText}` : '',
    productText ? `Keranjang:\n${cartText}` : '',
    `Pertanyaan user:\n${message}`
  ].filter(Boolean).join('\n\n');
}

function getKeys(listName, singleName) {
  const output = [];
  if (process.env[listName]) output.push(...process.env[listName].split(',').map((item) => item.trim()).filter(Boolean));
  if (process.env[singleName]) output.push(process.env[singleName]);
  for (let i = 1; i <= 5; i++) if (process.env[`${singleName}_${i}`]) output.push(process.env[`${singleName}_${i}`]);
  return Array.from(new Set(output));
}

function hasProvider() {
  return getKeys('GEMINI_API_KEYS', 'GEMINI_API_KEY').length > 0 || getKeys('GROQ_API_KEYS', 'GROQ_API_KEY').length > 0 || getKeys('OPENAI_API_KEYS', 'OPENAI_API_KEY').length > 0;
}

async function callAI({ prompt, general, search }) {
  const attempts = [];
  let firstProvider = null;

  for (const key of getKeys('GEMINI_API_KEYS', 'GEMINI_API_KEY')) {
    const models = Array.from(new Set([process.env.GEMINI_MODEL || 'gemini-2.5-flash', 'gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash']));
    for (const model of models) {
      const modes = search && !model.includes('1.5') ? [true, false] : [false];
      for (const useSearch of modes) {
        try {
          firstProvider = firstProvider || 'gemini';
          const text = await callGemini(key, model, prompt, general, useSearch);
          return { provider: `gemini:${model}`, text, attempts, failoverUsed: firstProvider !== 'gemini' || attempts.length > 0 };
        } catch (error) {
          attempts.push({ provider: 'gemini', model, status: error.status || 0, message: sanitizeError(error) });
          if (!shouldFailover(error.status || 500)) break;
        }
      }
    }
  }

  for (const key of getKeys('GROQ_API_KEYS', 'GROQ_API_KEY')) {
    const models = Array.from(new Set([process.env.GROQ_MODEL || 'llama-3.1-8b-instant', 'llama-3.1-8b-instant', 'llama-3.3-70b-versatile']));
    for (const model of models) {
      try {
        firstProvider = firstProvider || 'groq';
        const text = await callGroq(key, model, prompt, general);
        return { provider: `groq:${model}`, text, attempts, failoverUsed: firstProvider !== 'groq' || attempts.length > 0 };
      } catch (error) {
        attempts.push({ provider: 'groq', model, status: error.status || 0, message: sanitizeError(error) });
        if (!shouldFailover(error.status || 500)) break;
      }
    }
  }

  for (const key of getKeys('OPENAI_API_KEYS', 'OPENAI_API_KEY')) {
    const models = Array.from(new Set([process.env.OPENAI_MODEL || 'gpt-4o-mini', 'gpt-4o-mini']));
    for (const model of models) {
      try {
        firstProvider = firstProvider || 'openai';
        const text = await callOpenAI(key, model, prompt, general);
        return { provider: `openai:${model}`, text, attempts, failoverUsed: firstProvider !== 'openai' || attempts.length > 0 };
      } catch (error) {
        attempts.push({ provider: 'openai', model, status: error.status || 0, message: sanitizeError(error) });
        if (!shouldFailover(error.status || 500)) break;
      }
    }
  }

  throw new Error(attempts.map((item) => `${item.provider}:${item.status}:${item.message}`).slice(-6).join(' | ') || 'No AI provider configured');
}

function shouldFailover(status) {
  return status === 0 || status === 408 || status === 409 || status === 425 || status === 429 || status >= 500;
}

async function callGemini(key, model, prompt, general, useSearch) {
  const body = {
    contents: [{ role: 'user', parts: [{ text: prompt }] }],
    generationConfig: { temperature: general ? 0.55 : 0.35, topP: 0.9, maxOutputTokens: general ? 3200 : 1400 }
  };
  if (useSearch) body.tools = [{ google_search: {} }];
  const response = await fetchWithTimeout(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await safeJson(response);
  if (!response.ok) {
    const error = new Error((data && data.error && data.error.message) || `Gemini API error ${response.status}`);
    error.status = response.status;
    throw error;
  }
  const text = data && data.candidates && data.candidates[0] && data.candidates[0].content && Array.isArray(data.candidates[0].content.parts) ? data.candidates[0].content.parts.map((part) => part.text || '').join('').trim() : '';
  if (!text) {
    const error = new Error('Gemini response empty');
    error.status = 502;
    throw error;
  }
  return text;
}

async function callGroq(key, model, prompt, general) {
  const response = await fetchWithTimeout('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: 'Kamu adalah Dirac AI Assistant. Untuk pertanyaan umum, jawab seperti AI umum dan tutor belajar multi-mata-pelajaran: sejarah, geografi, IPA, IPS, matematika, fisika, kimia, biologi, bahasa Inggris, coding, dan tugas kompleks. Jangan menolak hanya karena bukan topik parfum. Jangan menawarkan produk kecuali user membahas produk/parfum.' },
        { role: 'user', content: prompt }
      ],
      temperature: general ? 0.55 : 0.35,
      max_tokens: general ? 3200 : 1400
    })
  });
  const data = await safeJson(response);
  if (!response.ok) {
    const error = new Error((data && data.error && data.error.message) || `Groq API error ${response.status}`);
    error.status = response.status;
    throw error;
  }
  const text = data && data.choices && data.choices[0] && data.choices[0].message ? String(data.choices[0].message.content || '').trim() : '';
  if (!text) {
    const error = new Error('Groq response empty');
    error.status = 502;
    throw error;
  }
  return text;
}

async function callOpenAI(key, model, prompt, general) {
  const response = await fetchWithTimeout('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: 'Kamu adalah Dirac AI Assistant. Untuk pertanyaan umum, jawab seperti AI umum dan tutor belajar multi-mata-pelajaran: sejarah, geografi, IPA, IPS, matematika, fisika, kimia, biologi, bahasa Inggris, coding, dan tugas kompleks. Jangan menolak hanya karena bukan topik parfum. Jangan menawarkan produk kecuali user membahas produk/parfum.' },
        { role: 'user', content: prompt }
      ],
      temperature: general ? 0.55 : 0.35,
      max_tokens: general ? 3200 : 1400
    })
  });
  const data = await safeJson(response);
  if (!response.ok) {
    const error = new Error((data && data.error && data.error.message) || `OpenAI API error ${response.status}`);
    error.status = response.status;
    throw error;
  }
  const text = data && data.choices && data.choices[0] && data.choices[0].message ? String(data.choices[0].message.content || '').trim() : '';
  if (!text) {
    const error = new Error('OpenAI response empty');
    error.status = 502;
    throw error;
  }
  return text;
}

async function fetchWithTimeout(url, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function safeJson(response) {
  try {
    return await response.json();
  } catch (_) {
    return {};
  }
}

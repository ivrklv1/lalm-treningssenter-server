// server.js
// ======================================================
// Treningssenter adgangsserver (Express + TELL Gate Control)
// - Medlemsregister (members.json)
// - Vipps Checkout + orders.json (idempotent callback)
// - Admin-API (NIF-import, TELL-synk, logging)
// - Drop-in token til kl. 23:59 samme dag
// - SMS-innlogging via Eurobate
// - /door/open med TELL-modul (token-baserte medlemmer + drop-in)
// - /access (gammel epost-basert variant, beholdes for kompatibilitet)
// ======================================================

const express = require('express');
const fs = require('fs');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { execFile } = require('child_process');
const util = require('util');
const execFileAsync = util.promisify(execFile);
require('dotenv').config();
const {
  syncMembershipToTripletex,
  approveSubscriptionInvoice,
  stopTripletexSubscriptionForOrder,
} = require('./tripletexClient');


const app = express();
const PORT = Number(process.env.PORT || 3000);

// ----------------------------
// Åpningstid (Europe/Oslo): 05-23
// ----------------------------
const OPENING_HOUR = 5;   // 05:00
const CLOSING_HOUR = 23;  // 23:00 (dvs. siste tillatte tidspunkt er 22:59)

function getOsloHourMinute() {
  // Robust mot DST (sommertid) siden Intl bruker tz-regler
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Oslo',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(new Date());

  const hour = parseInt(parts.find(p => p.type === 'hour')?.value || '0', 10);
  const minute = parseInt(parts.find(p => p.type === 'minute')?.value || '0', 10);
  return { hour, minute };
}

function isWithinOpeningHours() {
  const { hour } = getOsloHourMinute();

  // Tillat fra 05:00:00 til 22:59:59
  // (kl 23:00 og senere skal blokkeres)
  return hour >= OPENING_HOUR && hour < CLOSING_HOUR;
}

function openingHoursGuard(req, res, next) {
  if (isWithinOpeningHours()) return next();

  // Konsistent feilmelding til appen
  return res.status(403).json({
    ok: false,
    error: 'CLOSED',
    message: 'Treningssenteret er stengt. Åpningstid: 05:00–23:00.',
    openingHours: { from: '05:00', to: '23:00', timeZone: 'Europe/Oslo' },
  });
}


// ----------------------------
// Filbasert lagring → persistent /data på Render
// ----------------------------
// NB: Render lager tom /data ved deploy. Ikke bruk .json filer i repo for prod-data.
const DATA_DIR = process.env.DATA_DIR || '/data';

try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    console.log('Opprettet DATA_DIR:', DATA_DIR);
  }
} catch (e) {
  console.error('Kunne ikke opprette DATA_DIR:', e.message);
}

const MEMBERS_FILE = path.join(DATA_DIR, 'members.json');
const ORDERS_FILE  = path.join(DATA_DIR, 'orders.json');
const PLANS_FILE   = path.join(DATA_DIR, 'plans.json');

const TRIPLETEX_SUBSCRIPTION_ENABLED =
  (process.env.TRIPLETEX_SUBSCRIPTION_ENABLED || 'true')
    .toString()
    .toLowerCase() === 'true';

// ----------------------------
// Global state
// ----------------------------
const activeDropins = []; // { token, validUntil, email, mobile, name, createdAt, price }
const loginCodes = new Map(); // phoneNormalized -> { code, codeExpiresAt, lastSentAt }
const dropinTokens = new Map(); // tokenString -> { phone, expiresAt }

// Rate limiting for legacy /access
const openAttempts = {}; // key: email/phone, val: { lastAttempt, count }

// ----------------------------
// Konstanter for IL-rabatt
// ----------------------------
const IL_DISCOUNT_PLANS = [
  'medlem_m_binding', // Treningsavgift medlem m/binding (349/mnd)
];

// ----------------------------
// Logging til access.log
// ----------------------------
const ACCESS_LOG = path.join(__dirname, 'access.log');
function appendAccessLog(line) {
  try {
    fs.appendFileSync(ACCESS_LOG, line, 'utf-8');
  } catch (e) {
    console.error('Kunne ikke skrive til access.log:', e.message);
  }
}
// ----------------------------
// Normalisering av telefonnummer
// ----------------------------
function normalizePhone(raw) {
  if (!raw) return null;

  // Fjern mellomrom, bindestrek, parenteser osv.
  let phone = String(raw).replace(/[\s\-()]/g, '');

  // Bytt ut 00-prefiks med +
  if (phone.startsWith('00')) {
    phone = '+' + phone.slice(2);
  }

  // Hvis den starter med +, behold formatet
  if (phone.startsWith('+')) {
    // Norge: +47 + 8 sifre
    if (/^\+47\d{8}$/.test(phone)) {
      return phone;
    }
    return null; // andre land avvises nå (kan utvides senere)
  }

  // Hvis den starter med 47 og resten er 8 sifre → +47
  if (phone.startsWith('47') && phone.length === 10) {
    return '+47' + phone.slice(2);
  }

  // Hvis det er 8 sifre → antar norsk mobil og legger på +47
  if (/^\d{8}$/.test(phone)) {
    return '+47' + phone;
  }

  // Hvis det er 9 sifre og starter med 0 (0XXXXXXXX) → fjern 0 og legg +47
  if (/^0\d{8}$/.test(phone)) {
    return '+47' + phone.slice(1);
  }

  return null;
}

// ----------------------------
// Tilgangslogikk: "aktiv" + ev. utløpsdato (validUntil)
// - For ordinære medlemskap: ingen validUntil (uendelig til oppsigelse/deaktivering)
// - For korttid/drop-in: validUntil settes ved betaling og sjekkes ved login/døråpning/checkout
// ----------------------------
function isValidUntilOk(memberOrOrder) {
  try {
    const vu = memberOrOrder?.validUntil || memberOrOrder?.expiresAt || null;
    if (!vu) return true;
    const d = new Date(vu);
    if (Number.isNaN(d.getTime())) return true;
    return new Date() <= d;
  } catch (e) {
    return true;
  }
}

function getPlanMeta(membershipKey) {
  try {
    const plans = getPlans();
    if (!plans || !Array.isArray(plans)) return null;
    const p = plans.find((x) => x && (x.id === membershipKey || x.key === membershipKey));
    if (!p) return null;
    return {
      type: p.type || null,
      shortTermDays: Number(p.shortTermDays || 0) || 0,
      name: p.name || p.text || p.id || membershipKey,
    };
  } catch (e) {
    return null;
  }
}

function nowInOslo() {
  // Robust "nå" i Europe/Oslo uten ekstra biblioteker
  return new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Oslo' }));
}

function endOfDayOslo(d) {
  const x = new Date(d);
  x.setHours(23, 59, 59, 999);
  return x;
}

function addDaysOslo(d, days) {
  const x = new Date(d);
  x.setDate(x.getDate() + Number(days || 0));
  return x;
}

// planKey: f.eks. "DROPIN", "dropin", "korttid_3d", osv.
function computeValidUntilForPurchase(planKey) {
  const key = String(planKey || '').trim().toLowerCase();

  // 1) Drop-in: gyldig ut dagen (Oslo)
  if (key === 'dropin' || key === 'drop-in' || key === 'drop_in') {
    const until = endOfDayOslo(nowInOslo());
    return until.toISOString();
  }

  // 2) Korttid: leses fra plans.json via shortTermDays
  const plans = getPlans() || [];
  const plan = plans.find(
    (p) =>
      p &&
      (String(p.id || '').trim().toLowerCase() === key ||
        String(p.key || '').trim().toLowerCase() === key)
  );

  const shortTermDays = plan && Number(plan.shortTermDays || 0);
  if (shortTermDays > 0) {
    const until = endOfDayOslo(addDaysOslo(nowInOslo(), shortTermDays));
    return until.toISOString();
  }

  // 3) Ordinære medlemskap: ingen validUntil (null/fjern)
  return null;
}



// ----------------------------
// Apple testbruker (for App Review)
// ----------------------------
const APPLE_TEST_PHONE = process.env.APPLE_TEST_PHONE || '+4799999999'; // legg inn ditt nr i .env
const APPLE_TEST_CODE = process.env.APPLE_TEST_CODE || '111111';        // koden Apple skal bruke

// ----------------------------
// Hjelpefunksjoner for members.json (persistent /data)
// ----------------------------
function getMembers() {
  try {
    if (!fs.existsSync(MEMBERS_FILE)) {
      return [];
    }
    const raw = fs.readFileSync(MEMBERS_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('Kunne ikke lese members.json fra', MEMBERS_FILE, '- returnerer tom array:', e.message);
    return [];
  }
}

function saveMembers(members) {
  try {
    fs.writeFileSync(
      MEMBERS_FILE,
      JSON.stringify(members, null, 2),
      'utf-8',
    );
  } catch (e) {
    console.error('Kunne ikke skrive members.json til', MEMBERS_FILE, e.message);
  }
}

// -----------------------------------------------------
// Finn eksisterende medlem via telefon / e-post
// -----------------------------------------------------
function findMemberByPhoneOrEmail(phoneFull, email) {
  const members = getMembers();
  const normPhone = normalizePhone(phoneFull || '');
  const digits = normPhone ? normPhone.replace(/\D/g, '') : '';
  const emailLc = (email || '').toLowerCase();

  for (const m of members) {
    const candidatePhone =
      m.phone || m.mobile || m.phoneFull || null;
    const mNormPhone = candidatePhone ? normalizePhone(candidatePhone) : null;
    const mDigits = mNormPhone ? mNormPhone.replace(/\D/g, '') : '';
    const mEmailLc = (m.email || '').toLowerCase();

    // Telefonmatch (slutter på samme 8 sifre)
    if (digits && mDigits && mDigits.endsWith(digits)) {
      return m;
    }

    // E-postmatch
    if (emailLc && mEmailLc && emailLc === mEmailLc) {
      return m;
    }
  }

  return null;
}

// ----------------------------
// Hjelpefunksjoner for orders.json (Vipps-ordrer) – persistent /data
// ----------------------------
function getOrders() {
  try {
    if (!fs.existsSync(ORDERS_FILE)) {
      return [];
    }
    const raw = fs.readFileSync(ORDERS_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('Kunne ikke lese orders.json fra', ORDERS_FILE, '- returnerer tom array:', e.message);
    return [];
  }
}

function saveOrders(orders) {
  try {
    fs.writeFileSync(
      ORDERS_FILE,
      JSON.stringify(orders, null, 2),
      'utf-8',
    );
  } catch (e) {
    console.error('Kunne ikke skrive orders.json til', ORDERS_FILE, e.message);
  }
}


// ----------------------------
// Hjelpefunksjoner for plans.json (medlemskap / produkter)
// ----------------------------
function getPlans() {
  try {
    if (!fs.existsSync(PLANS_FILE)) {
      // Ingen egen plans-fil ennå → returner null og bruk legacy membershipMap
      return null;
    }
    const raw = fs.readFileSync(PLANS_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      console.error('plans.json må være et array. Ignorerer innholdet.');
      return null;
    }
    return parsed;
  } catch (e) {
    console.error('Kunne ikke lese plans.json fra', PLANS_FILE, '- returnerer null:', e.message);
    return null;
  }
}

function savePlans(plans) {
  try {
    fs.writeFileSync(
      PLANS_FILE,
      JSON.stringify(plans, null, 2),
      'utf-8',
    );
  } catch (e) {
    console.error('Kunne ikke skrive plans.json til', PLANS_FILE, e.message);
  }
}



function upsertOrder(order) {
  const orders = getOrders();
  const idx = orders.findIndex(o => o.orderId === order.orderId);
  const now = new Date().toISOString();
  if (idx === -1) {
    orders.push({ ...order, updatedAt: now });
  } else {
    orders[idx] = { ...orders[idx], ...order, updatedAt: now };
  }
  saveOrders(orders);
}

function findOrder(orderId) {
  const orders = getOrders();
  return orders.find(o => o.orderId === orderId) || null;
}

// Finn siste Tripletex-ordre for medlem og stopp abonnementet
async function stopTripletexForMember(member) {
  try {
    const emailNorm = (member.email || '').toLowerCase();
    const memberId = member.id || null;

    const orders = getOrders() || [];

    // Finn alle ordre som tilhører medlemmet og er synket mot Tripletex
    const relevant = orders.filter((o) => {
      const orderEmail = (o.email || '').toLowerCase();
      const sameEmail = emailNorm && orderEmail === emailNorm;
      const sameMemberId = memberId && o.memberId === memberId;

      return (
        o.tripletexSynced &&
        o.tripletexOrderId &&
        (sameEmail || sameMemberId)
      );
    });

    if (!relevant.length) {
      appendAccessLog(
        `[${new Date().toISOString()}] TRIPLETEX_STOP_NO_ORDER email=${emailNorm} memberId=${memberId}\n`
      );
      return;
    }

    // Ta den nyeste ordren basert på createdAt/updatedAt
    relevant.sort((a, b) => {
      const aTs = new Date(a.updatedAt || a.createdAt || 0).getTime();
      const bTs = new Date(b.updatedAt || b.createdAt || 0).getTime();
      return bTs - aTs;
    });

    const latest = relevant[0];

    await stopTripletexSubscriptionForOrder(latest.tripletexOrderId);

    updateOrderStatus(latest.orderId, latest.status || 'CANCELLED', {
      tripletexSubscriptionStoppedAt: new Date().toISOString(),
    });

    appendAccessLog(
      `[${new Date().toISOString()}] TRIPLETEX_STOP_OK orderId=${latest.orderId} tripletexOrderId=${latest.tripletexOrderId} memberId=${memberId}\n`
    );
  } catch (e) {
    console.error('[TRIPLETEX_STOP_ERROR] memberId', member.id, e.message);
    appendAccessLog(
      `[${new Date().toISOString()}] TRIPLETEX_STOP_ERROR memberId=${member.id} err=${e.message}\n`
    );
  }
}


function updateOrderStatus(orderId, status, extra = {}) {
  const orders = getOrders();
  const idx = orders.findIndex(o => o.orderId === orderId);
  if (idx === -1) return null;

  const now = new Date().toISOString();
  orders[idx] = {
    ...orders[idx],
    status,
    updatedAt: now,
    ...extra,
  };

  saveOrders(orders);
  return orders[idx];
}

// ----------------------------
// Enkel basic auth for admin-API
// ----------------------------
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';

function basicAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const [type, credentials] = auth.split(' ');
  if (type === 'Basic' && credentials) {
    const decoded = Buffer.from(credentials, 'base64').toString();
    const [user, pass] = decoded.split(':');
    if (user === ADMIN_USER && pass === ADMIN_PASS) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Admin-sone"');
  return res.status(401).send('Du må logge inn for å få tilgang');
}

// ----------------------------
// Hjelpefunksjoner for navn, telefon, epost
// ----------------------------
function normalizeEmail(email) {
  return (email || '').trim().toLowerCase();
}

function normalizeName(name) {
  return (name || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}


// (normalizePhone er definert tidligere i filen)

// ----------------------------
// Cookie-hjelp (enkelt)
// ----------------------------
function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;

  cookieHeader.split(';').forEach(function (cookie) {
    const parts = cookie.split('=');
    const key = parts[0] && parts[0].trim();
    const val = parts[1] && decodeURIComponent(parts[1].trim());
    if (key) list[key] = val;
  });
  return list;
}

// ----------------------------
// Door-allowlist & mapping
// ----------------------------
const doorConfig = {
  styrkerom: { gateIndex: 1, description: 'Hovedinngang treningssenter' },
};

// ----------------------------
// TELL-konfig (Gate Control PRO)
// ----------------------------
const TELL = {
  base: process.env.TELL_BASE_URL || 'https://api.tell.hu',
  apiKey: process.env.TELL_API_KEY,
  hwId: process.env.TELL_HWID, // f.eks. "FC:0F:E7:CA:63:93"
  appId: process.env.TELL_APP_ID, // AppId fra TELL
  hwName: process.env.TELL_HW_NAME || 'Lalm Treningssenter',
  inserter: process.env.TELL_INSERTER || 'Lalm Treningssenter admin',
  schemes: (process.env.TELL_SCHEMES || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
};

console.log('TELL CONFIG CHECK:', {
  apiKey: !!TELL.apiKey,
  hwId: !!TELL.hwId,
  appId: !!TELL.appId,
});

function tellHeaders() {
  if (!TELL.apiKey || !TELL.hwId || !TELL.appId) {
    console.warn('TELL-konfig ikke komplett (API key / hwId / appId mangler).');
  }
  return {
    'Content-Type': 'application/json',
    'api-key': TELL.apiKey, // NØYAKTIG slik Zoltan skrev
  };
}

// Legg til bruker i TELL
async function tellAddUser(phone, name) {
  const phoneDigits = String(phone).replace(/\D/g, '');
  const headers = tellHeaders();

  // Bygg payload i tråd med dokumentasjonen
  const base = {
    hwId: TELL.hwId,
    hwName: TELL.hwName || 'Lalm Treningssenter',
    appId: TELL.appId,

    name: phoneDigits, // username
    fname: (name && String(name).trim()) ? String(name).trim() : phoneDigits,

    role: 'U',
    inserter: TELL.inserter || 'Lalm Treningssenter admin',

    // Booleans (som i doc-eksempelet)
    go1: true,
    go2: false,
    out1: true,
    out2: false,
    call: false,
    sms: false,
    pushD: false,
    smsD: false,
    doorBell: false,
    cam1: false,
    cam2: false,
    pushE: false,

    specificRuleType: '', // empty string er eksplisitt tillatt i doc
  };

  // Ikke send schemes hvis tom
  if (Array.isArray(TELL.schemes) && TELL.schemes.length > 0) {
    base.schemes = TELL.schemes;
  }

  // Forsøk 1: uten "+"
  const payload1 = { ...base, phoneNumber: phoneDigits };

  // Forsøk 2: med "+" (E.164-lignende)
  const payload2 = { ...base, phoneNumber: `+${phoneDigits}` };

  try {
    console.log('[TELL] adduser payload (try1):', payload1);
    const r = await axios.post(`${TELL.base}/gc/adduser`, payload1, { headers });
    console.log(`✅ [TELL] La til ${payload1.fname} (${payload1.phoneNumber})`, r.data);
    return r.data;
  } catch (e1) {
    const err1 = e1?.response?.data || e1?.message || e1;
    console.error(`❌ [TELL] adduser try1 feilet (${phoneDigits}):`, err1);

    // Bare prøv try2 hvis det er format-feil (eller generelt)
    try {
      console.log('[TELL] adduser payload (try2):', payload2);
      const r2 = await axios.post(`${TELL.base}/gc/adduser`, payload2, { headers });
      console.log(`✅ [TELL] La til ${payload2.fname} (${payload2.phoneNumber})`, r2.data);
      return r2.data;
    } catch (e2) {
      const err2 = e2?.response?.data || e2?.message || e2;
      console.error(`❌ [TELL] adduser try2 feilet (+${phoneDigits}):`, err2);
      throw e2;
    }
  }
}



// Fjern bruker i TELL
async function tellRemoveUser(phone) {
  const phoneNormalized = normalizePhone(phone);
  if (!phoneNormalized) return;

  try {
    const headers = tellHeaders();
    const data = { hwId: TELL.hwId, appId: TELL.appId, phone: phoneNormalized };
    await axios.post(`${TELL.base}/gc/removeuser`, data, { headers });
    console.log(`🗑️ [TELL] Fjernet ${phoneNormalized}`);
  } catch (e) {
    console.error(
      `❌ [TELL] Feil ved remove ${phoneNormalized}:`,
      e?.response?.data || e.message
    );
  }
}

// Åpne dør via TELL
async function gcOpen(gateIndex) {
  const headers = tellHeaders();

  const body = {
    hwid: TELL.hwId,      // merk: hwid, ikke hwId
    appId: TELL.appId,
    data: gateIndex,      // 1 = utgang 1
  };

  const r = await axios.post(`${TELL.base}/gc/open`, body, { headers });
  console.log('[TELL gc/open]', r.data);
  return r.data;
}


// Registrer appId på enheten hos TELL – må typisk gjøres én gang
async function tellRegisterAppId() {
  const headers = tellHeaders();
  const body = { hwId: TELL.hwId, appId: TELL.appId };

  const r = await axios.post(`${TELL.base}/gc/addappid`, body, {
    headers,
    timeout: 5000,
  });

  console.log('[TELL addappid]', r.data);
  return r.data;
}

app.post('/api/admin/tell-schemas', basicAuth, async (req, res) => {
  try {
    const headers = tellHeaders();
    const payload = {
      hwId: TELL.hwId,
      hwName: TELL.hwName || 'Lalm Treningssenter',
      appId: TELL.appId,
    };

    const r = await axios.post(`${TELL.base}/gc/getschemas`, payload, { headers });
    res.json({ ok: true, tell: r.data });
  } catch (e) {
    res.status(500).json({
      ok: false,
      error: 'tell_getschemas_failed',
      detail: e?.response?.data || e?.message || String(e),
    });
  }
});


// Test-endepunkt for TELL: sjekk at API-nøkkel, hwId og appId fungerer
app.post('/api/admin/tell-test', basicAuth, async (req, res) => {
  try {
    const headers = tellHeaders();

    const body = {
      hwid: TELL.hwId,
      appId: TELL.appId,
      data: 1,
    };

    const r = await axios.post(`${TELL.base}/gc/open`, body, { headers });
    console.log('[TELL TEST] gc/open result:', r.data);

    return res.json({ ok: true, response: r.data });
  } catch (e) {
    console.error('[TELL TEST] error:', e?.response?.data || e.message);
    return res.status(500).json({
      ok: false,
      error: e?.response?.data || e.message,
    });
  }
});



// Admin: registrer appId på TELL-enheten via nettleser (GET)
app.get('/api/admin/tell-register-app', basicAuth, async (req, res) => {
  try {
    const data = await tellRegisterAppId();
    return res.json({ ok: true, response: data });
  } catch (e) {
    console.error('[TELL REGISTER APP] error:', e?.response?.data || e.message);
    return res.status(500).json({
      ok: false,
      error: e?.response?.data || e.message,
    });
  }
});

app.get('/debug/tell-open', async (req, res) => {
  try {
    const data = await gcOpen(1);  // åpner utgang 1 med samme logikk som /door/open
    return res.json({ ok: true, response: data });
  } catch (err) {
    console.error('[TELL_DEBUG_ERROR]', err?.response?.data || err.message);
    return res.status(500).json({
      ok: false,
      error: err?.response?.data || err.message,
    });
  }
});



app.get('/debug/tell-addappid', async (req, res) => {
  try {
    const baseUrl = 'https://api.tell.hu/gc/addappid';

    const params = new URLSearchParams({
      hwid: process.env.TELL_HWID,
      password: process.env.TELL_MASTER_PASSWORD,
    });

    const url = `${baseUrl}?${params.toString()}`;

    const r = await fetch(url, {
      method: 'GET',
      headers: { 'api-key': TELL.apiKey },
    });

    const text = await r.text();
    console.log('[TELL_ADDAPPID] status=', r.status, 'body=', text);

    return res.status(200).send(text);
  } catch (err) {
    console.error('[TELL_ADDAPPID_ERROR]', err);
    return res.status(500).json({
      ok: false,
      name: err.name,
      message: err.message,
    });
  }
});





// ----------------------------
// Eurobate SMS-konfig
// ----------------------------
const EUROBATE_API_URL = 'https://api.eurobate.com/json_api.php';

const eurobateConfig = {
  user: process.env.EUROBATE_USER,
  password: process.env.EUROBATE_PASSWORD,
  originator: process.env.EUROBATE_ORIGINATOR || 'LalmTrening',
  simulate: process.env.EUROBATE_SIMULATE === '1' ? 1 : 0,
};

/**
 * Felles helper for å sende SMS via Eurobate
 */
async function sendSms(phone, message) {
  const phoneNormalized = normalizePhone(phone);
  if (!phoneNormalized) {
    throw new Error('Ugyldig telefonnummer');
  }

  const msisdn = Number(phoneNormalized.replace('+', ''));
  if (!Number.isFinite(msisdn)) {
    throw new Error('Ugyldig msisdn etter normalisering');
  }

  const payload = {
    user: eurobateConfig.user,
    password: eurobateConfig.password,
    simulate: eurobateConfig.simulate,
    messages: [
      {
        originator: eurobateConfig.originator,
        msisdn,
        message,
      },
    ],
  };

  const res = await axios.post(EUROBATE_API_URL, payload, {
    headers: { 'Content-Type': 'application/json' },
  });

  const d = res.data || {};
  const errCode = Number(d.error || d.ERROR || 0);
  const status = String(d.STATUS || d.status || '').toUpperCase();

  // Fail-fast: hvis Eurobate ikke svarer OK, skal resten av systemet vite det
  if (errCode && errCode !== 0) {
    console.error('[EUROBATE] sendSms failed error=', errCode, 'status=', status, d);
    throw new Error(`EUROBATE_ERROR_${errCode}`);
  }
  if (status && status !== 'OK') {
    console.warn('[EUROBATE] sendSms non-OK status=', status, d);
    throw new Error(`EUROBATE_STATUS_${status}`);
  }

  console.log(
    '[EUROBATE] sendSms OK uuid=',
    d.uuid || d.UUID || '',
    'parts=',
    d.messageParts || d.MESSAGEPARTS || ''
  );

  return d;
}

/**
 * Spesialisert funksjon for innloggingskode
 */
async function sendSmsLoginCode(phone, code) {
  const message = `Lalm Treningssenter: Din kode er ${code}.\n#${code}`;
  return sendSms(phone, message);
}

/**
 * Velkommen-SMS ved innmelding
 */
async function sendWelcomeMembershipSms(order, member) {
  try {
    const rawPhone =
      member?.phoneFull ||
      member?.phone ||
      order?.phoneFull ||
      order?.phone;

    const phoneNormalized = normalizePhone(rawPhone);
    if (!phoneNormalized) {
      console.warn(
        '[WELCOME_SMS] Fant ikke gyldig telefon for orderId=',
        order?.orderId,
        'memberId=',
        member?.id
      );
      return;
    }

    // Finn et fornavn hvis vi har et ekte navn (ikke e-post)
    let nameSource =
      (member?.name || '').trim() || (order?.name || '').trim() || '';

    // Hvis "navnet" ser ut som en e-post, dropp det
    if (nameSource.includes('@')) {
      nameSource = '';
    }

    let firstName = '';
    if (nameSource) {
      firstName = nameSource.split(/\s+/)[0].trim();
    }

    const greeting = firstName ? `Hei ${firstName}!` : 'Hei!';

    // Plan-key (bruk member.plan først, så order.membershipKey)
    const planKey = String(member?.plan || order?.membershipKey || '')
      .trim()
      .toLowerCase();

    // Hent meta for å vite om det er korttid (shortTermDays)
    const meta = getPlanMeta(planKey) || getPlanMeta(member?.plan || order?.membershipKey);
    const shortDays = Number(meta?.shortTermDays || 0);

    // Korttid-flagg
    const isShortTerm = planKey !== 'dropin' && (shortDays > 0 || !!member?.validUntil);

    // Gyldig-til-dato (Oslo) hvis vi har validUntil
    const validUntilOslo = member?.validUntil
      ? new Date(member.validUntil).toLocaleDateString('nb-NO', { timeZone: 'Europe/Oslo' })
      : null;

    // Felles: innloggingstekst
    const loginLine = `Logg inn i appen for å åpne døren.`;

    let message = '';

    // -------- DROP-IN --------
    if (planKey === 'dropin') {
      message =
        `${greeting}\n` +
        `Drop-in er nå aktiv hos Lalm Treningssenter.\n` +
        `Gyldig ut dagen innenfor åpningstiden (05–23).\n` +
        `${loginLine}\n` +
        `God trening! 💪`;
    }
    // -------- KORTTID (3-dagerspass / 7-dagerspass / osv.) --------
    else if (isShortTerm) {
      const passText = shortDays > 0 ? `${shortDays}-dagerspass` : 'korttidspass';
      message =
        `${greeting}\n` +
        `Ditt ${passText} er nå aktivt hos Lalm Treningssenter.\n` +
        (validUntilOslo
          ? `Gyldig til og med ${validUntilOslo} innenfor åpningstiden (05–23).\n`
          : `Gyldig innen åpningstid (05–23).\n`) +
        `${loginLine}\n` +
        `God trening! 💪`;
    }
    // -------- ORDINÆRT MEDLEMSKAP (beholder teksten du liker) --------
    else {
      message =
        `${greeting} Velkommen som medlem hos Lalm Treningssenter! 🎉\n` +
        `Medlemskapet ditt er nå aktivt.\n` +
        `${loginLine}\n` +
        `Gi oss beskjed hvis du trenger hjelp – God trening! 💪`;
    }

    await sendSms(phoneNormalized, message);

    appendAccessLog(
      `[${new Date().toISOString()}] WELCOME_SMS_SENT orderId=${order?.orderId} phone=${phoneNormalized} plan=${planKey} shortDays=${shortDays}\n`
    );
  } catch (e) {
    console.error('[WELCOME_SMS] Feil ved sending:', e?.response?.data || e.message);
    appendAccessLog(
      `[${new Date().toISOString()}] WELCOME_SMS_ERROR orderId=${order?.orderId} err=${e.message}\n`
    );
  }
}




// ----------------------------
// Middleware
// ----------------------------
app.use(cors());
app.use(express.json());

// ----------------------------
// Statisk servering (admin.html ligger i /public)
// ----------------------------
app.use(express.static(path.join(__dirname, 'public')));

// =====================================================
// OFFENTLIGE MEDLEMS-ENDPOINTS
// =====================================================

app.get('/membership', (req, res) => {
  const email = (req.query.email || '').toLowerCase();
  const members = getMembers();
  const member = members.find(m => (m.email || '').toLowerCase() === email);
  res.json({ email, exists: !!member, active: member?.active || false });
});

app.post('/membership/signup', (req, res) => {
  const { name, email, phone } = req.body || {};
  if (!name || !email || !phone) {
    return res.status(400).json({ ok: false, error: 'name_email_phone_required' });
  }

  const members = getMembers();
  if (members.find(m => (m.email || '').toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ ok: false, error: 'user_already_exists' });
  }

  const phoneNormalized = normalizePhone(phone);

  members.push({
    name,
    email: email.toLowerCase(),
    phone: phoneNormalized,
    active: false,
    plan: null, // settes i admin når dere bestemmer abonnement
    clubMember: false, // settes via NIF-import eller manuelt
  });

  saveMembers(members);
  return res.json({ ok: true, message: 'Registrert! Venter på godkjenning.' });
});

// =====================================================
// ADMIN-API (NYTT) – brukt av admin.html
// =====================================================

// Hent alle medlemmer (nytt admin-UI)
app.get('/admin/members', basicAuth, (req, res) => {
  const members = getMembers();
  res.json(members);
});

// Sett medlem inaktiv (pause) + stopp abonnement i Tripletex
app.post('/admin/members/pause', basicAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const email = (body.email || '').toLowerCase();

    if (!email) {
      return res.status(400).json({ ok: false, error: 'email_required' });
    }

    const members = getMembers();

    // Finn alle medlemmer som matcher telefon (inkl. duplikater)
    const matches = members.filter((m) => {
     const candidatePhone = m?.phone || m?.phoneFull || m?.mobile || null;
     const mPhone = candidatePhone ? normalizePhone(candidatePhone) : null;
     return mPhone === phoneNormalized && m?.active;
    });

    function isCurrentlyValid(m) {
      // Ordinært medlemskap: ingen validUntil => gyldig
      if (!m?.validUntil) return true;
     return new Date(m.validUntil) >= new Date();
    }

    // 1) Prioriter medlem som er gyldig nå
    let member = matches.find(isCurrentlyValid);

    // 2) Hvis ingen er gyldig nå: velg den med nyeste validUntil (for forutsigbarhet)
    if (!member && matches.length) {
     member = [...matches].sort((a, b) => {
       const av = a?.validUntil ? new Date(a.validUntil).getTime() : 0;
       const bv = b?.validUntil ? new Date(b.validUntil).getTime() : 0;
       return bv - av;
      })[0];
    }

    // Returner kun innlogging hvis gyldig nå
    if (member && isCurrentlyValid(member)) {
      return res.json({
        ok: true,
        isMember: true,
        member: {
         email: member.email,
         name: member.name || '',
         phone: phoneNormalized,
         validUntil: member.validUntil || null,
        },
     });
    }

    return res.json({ ok: true, isMember: false, member: null });



    if (!member) {
      return res.status(404).json({ ok: false, error: 'member_not_found' });
    }

    // Sett medlem inaktiv lokalt
    member.active = false;
    member.updatedAt = new Date().toISOString();
    saveMembers(members);

    // Stopp abonnement i Tripletex (best effort)
    await stopTripletexForMember(member);

    return res.json({ ok: true, paused: true });
  } catch (e) {
    console.error('[ADMIN_PAUSE_MEMBER_ERROR]', e.message);
    return res
      .status(500)
      .json({ ok: false, error: 'internal_error', message: e.message });
  }
});


app.post('/admin/members', basicAuth, (req, res) => {
  const body = req.body || {};
  const members = getMembers();

  if (!body.email) {
    return res.status(400).json({ error: 'email må være satt' });
  }

  const emailNorm = normalizeEmail(body.email);
let existing = members.find((m) => normalizeEmail(m.email) === emailNorm);

if (existing) {
  // Oppdater eksisterende, men behold id hvis den finnes
  Object.assign(existing, body);
  if (!existing.id) {
    existing.id = `mem_${Date.now()}_${Math.floor(Math.random() * 100000)}`;
  }
} else {
  // Nytt medlem → sørg for id
  const newMember = {
    id: body.id || `mem_${Date.now()}_${Math.floor(Math.random() * 100000)}`,
    ...body,
  };
  members.push(newMember);
}

  saveMembers(members);
  res.json({ ok: true });
});


// Hent alle Vipps-ordrer (vises i admin)
app.get('/admin/orders', basicAuth, (req, res) => {
  const orders = getOrders();
  res.json(orders);
});

// Legg til/oppdater medlem (nytt admin-UI)
app.post('/admin/members', basicAuth, (req, res) => {
  const body = req.body || {};
  const members = getMembers();

  if (!body.email) {
    return res.status(400).json({ error: 'email må være satt' });
  }

  const emailNorm = normalizeEmail(body.email);
  let existing = members.find((m) => normalizeEmail(m.email) === emailNorm);

  if (existing) {
    Object.assign(existing, body);
  } else {
    members.push(body);
  }

  saveMembers(members);
  res.json({ ok: true });
});

// Søk medlem (nytt admin-UI)
app.get('/admin/members/search', basicAuth, (req, res) => {
  const email = normalizeEmail(req.query.email);
  const phone = normalizePhone(req.query.phone);
  const name = normalizeName(req.query.name);

  const members = getMembers();

  const matches = members.filter((m) => {
    let hit = false;

    if (email && normalizeEmail(m.email) === email) hit = true;
    if (phone && normalizePhone(m.phone) === phone) hit = true;

    if (name && normalizeName(m.name) === name) hit = true;

    return hit;
  });

  res.json({ matches });
});


// -----------------------------------------------------
// Medlemskap / planer – felles API (app/nettside) + admin
// -----------------------------------------------------

// Offentlig API: tilgjengelige medlemskap som kan kjøpes (kun aktive)
app.get('/api/plans', (req, res) => {
  const plans = getPlans() || [];
  const publicPlans = plans
    .filter((p) => !p || p.active !== false ? true : false)
    .sort((a, b) => {
      const ao = typeof a.sortOrder === 'number' ? a.sortOrder : 9999;
      const bo = typeof b.sortOrder === 'number' ? b.sortOrder : 9999;
      return ao - bo;
    });

  res.json(publicPlans);
});

// Admin: hent alle medlemskap (også inaktive)
app.get('/admin/plans', basicAuth, (req, res) => {
  const plans = getPlans() || [];
  res.json(plans);
});

// Admin: opprett nytt medlemskap
app.post('/admin/plans', basicAuth, (req, res) => {
  const body = req.body || {};
  let plans = getPlans() || [];

  const id = (body.id || '').trim();
  if (!id) {
    return res.status(400).json({ ok: false, error: 'id_required' });
  }

  if (plans.some((p) => (p.id || p.key) === id)) {
    return res.status(400).json({ ok: false, error: 'plan_exists' });
  }

  const amountNum = Number(body.amount);
  if (!Number.isFinite(amountNum) || amountNum < 0) {
    return res.status(400).json({ ok: false, error: 'amount_invalid' });
  }

  const signupFeeNum =
    body.signupFee != null ? Number(body.signupFee) || 0 : 0;
  const bindingMonthsNum =
    body.bindingMonths != null ? Number(body.bindingMonths) || 0 : 0;
  const shortTermDaysNum =
    body.shortTermDays != null && body.shortTermDays !== ''
      ? Number(body.shortTermDays) || 0
      : null;

  const sortOrder =
    typeof body.sortOrder === 'number'
      ? body.sortOrder
      : plans.length + 1;

   // Nytt: Tripletex produkt-ID (valgfritt felt)
  let tripletexProductId = null;
  if (
    body.tripletexProductId !== undefined &&
    body.tripletexProductId !== null &&
    body.tripletexProductId !== ''
  ) {
    const pidNum = Number(body.tripletexProductId);
    tripletexProductId = Number.isFinite(pidNum) ? pidNum : null;
  }

const plan = {
  id,
  key: id,
  name: body.name || body.text || id,
  text: body.text || body.name || id,
  type: body.type || 'standard',

  amount: amountNum,
  signupFee: signupFeeNum,
  bindingMonths: bindingMonthsNum,
  shortTermDays: shortTermDaysNum,

  tagline: body.tagline || '',
  description: body.description || '',
  bullets: Array.isArray(body.bullets) ? body.bullets : [],

  campaignLabel: body.campaignLabel || null,
  campaignFrom: body.campaignFrom || null,
  campaignTo: body.campaignTo || null,

  showOnWeb: body.showOnWeb !== false,
  showInApp: body.showInApp !== false,
  prorate: body.prorate !== false,
  active: body.active !== false,

  sortOrder,

  // Nytt felt som blir lagret til plans.json
  tripletexProductId,
};

  plans.push(plan);
  savePlans(plans);

  res.json({ ok: true, plan });
});

// Admin: oppdater eksisterende medlemskap
app.put('/admin/plans/:id', basicAuth, (req, res) => {
  const id = String(req.params.id || '').trim();
  const body = req.body || {};
  let plans = getPlans() || [];

  const idx = plans.findIndex((p) => (p.id || p.key) === id);
  if (idx === -1) {
    return res.status(404).json({ ok: false, error: 'plan_not_found' });
  }

  const plan = plans[idx];

  // Tallfelt
  if (Object.prototype.hasOwnProperty.call(body, 'amount')) {
    const amountNum = Number(body.amount);
    if (!Number.isFinite(amountNum) || amountNum < 0) {
      return res.status(400).json({ ok: false, error: 'amount_invalid' });
    }
    plan.amount = amountNum;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'signupFee')) {
    plan.signupFee = Number(body.signupFee) || 0;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'bindingMonths')) {
    plan.bindingMonths = Number(body.bindingMonths) || 0;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'shortTermDays')) {
    plan.shortTermDays =
      body.shortTermDays != null && body.shortTermDays !== ''
        ? Number(body.shortTermDays) || 0
        : null;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'sortOrder')) {
    plan.sortOrder = Number(body.sortOrder) || 0;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'tripletexProductId')) {
  const raw = body.tripletexProductId;
  if (raw === null || raw === '' || raw === undefined) {
    plan.tripletexProductId = null;
  } else {
    const pidNum = Number(raw);
    if (!Number.isFinite(pidNum) || pidNum <= 0) {
      return res
        .status(400)
        .json({ ok: false, error: 'tripletexProductId_invalid' });
    }
    plan.tripletexProductId = pidNum;
  }
}

  // Tekstfelter
  if (Object.prototype.hasOwnProperty.call(body, 'name')) {
    plan.name = body.name;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'text')) {
    plan.text = body.text;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'description')) {
    plan.description = body.description || '';
  }
  if (Object.prototype.hasOwnProperty.call(body, 'tagline')) {
    plan.tagline = body.tagline || '';
  }
  if (Object.prototype.hasOwnProperty.call(body, 'type')) {
    plan.type = body.type || 'standard';
  }

  if (Object.prototype.hasOwnProperty.call(body, 'bullets')) {
    plan.bullets = Array.isArray(body.bullets) ? body.bullets : [];
  }

  // Kampanjefelt
  if (Object.prototype.hasOwnProperty.call(body, 'campaignLabel')) {
    plan.campaignLabel = body.campaignLabel || null;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'campaignFrom')) {
    plan.campaignFrom = body.campaignFrom || null;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'campaignTo')) {
    plan.campaignTo = body.campaignTo || null;
  }

  // Boolean-felt
  if (Object.prototype.hasOwnProperty.call(body, 'prorate')) {
    plan.prorate = !!body.prorate;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'active')) {
    plan.active = !!body.active;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'showOnWeb')) {
    plan.showOnWeb = !!body.showOnWeb;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'showInApp')) {
    plan.showInApp = !!body.showInApp;
  }

  savePlans(plans);
  res.json({ ok: true, plan });
});


// Admin: "slette" medlemskap → sett active:false
app.delete('/admin/plans/:id', basicAuth, (req, res) => {
  const id = String(req.params.id || '').trim();
  let plans = getPlans() || [];

  const idx = plans.findIndex((p) => (p.id || p.key) === id);
  if (idx === -1) {
    return res.status(404).json({ ok: false, error: 'plan_not_found' });
  }

  plans[idx].active = false;
  savePlans(plans);

  res.json({ ok: true, id, active: false });
});

// -----------------------------------------------------
// Admin: oppdatere / slette medlem via id (nytt admin-UI)
// -----------------------------------------------------

// Oppdatér medlem (navn, e-post, telefon, plan, aktiv m.m.)
app.put('/admin/members/:id', basicAuth, (req, res) => {
  const id = String(req.params.id || '').trim();
  const body = req.body || {};
  const members = getMembers();

  const idx = members.findIndex((m) => String(m.id) === id);
  if (idx === -1) {
    return res.status(404).json({ ok: false, error: 'member_not_found' });
  }

  const member = members[idx];

  const allowed = [
    'name',
    'email',
    'phone',
    'phoneFull',
    'mobile',
    'plan',
    'active',
    'clubMember',
    'clubMemberSource',
    'notes',
  ];

  for (const key of allowed) {
    if (Object.prototype.hasOwnProperty.call(body, key)) {
      member[key] = body[key];
    }
  }

  member.updatedAt = new Date().toISOString();
  saveMembers(members);

  res.json({ ok: true, member });
});

// Slett medlem helt (bruk med forsiktighet!)
app.delete('/admin/members/:id', basicAuth, (req, res) => {
  const id = String(req.params.id || '').trim();
  const members = getMembers();

  const idx = members.findIndex((m) => String(m.id) === id);
  if (idx === -1) {
    return res.status(404).json({ ok: false, error: 'member_not_found' });
  }

  const deleted = members.splice(idx, 1)[0];
  saveMembers(members);

  res.json({ ok: true, deletedId: id });
});

// =====================================================
// ADMIN-API (GAMMELT) – brukt av tidligere admin-verktøy
// =====================================================

app.get('/api/admin/members', basicAuth, (req, res) => {
  res.json(getMembers());
});

app.post('/api/admin/members', basicAuth, async (req, res) => {
  const { email, active = true, name = '', phone = '', plan = null } = req.body || {};
  if (!email) {
    return res.status(400).json({ error: 'email_required' });
  }

  const members = getMembers();
  if (members.some(m => (m.email || '').toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ error: 'member_exists' });
  }

  const phoneNormalized = normalizePhone(phone);

  const member = {
  id: `mem_${Date.now()}_${Math.floor(Math.random() * 100000)}`,
  email: email.toLowerCase(),
  active: !!active,
  name,
  phone: phoneNormalized,
  plan: plan || null,
  clubMember: false,
};

  members.push(member);
  saveMembers(members);

  // TELL-sync fjernet: vi legger ikke lenger brukere automatisk inn i TELL

  res.json({ ok: true, member });
});

app.post('/api/admin/members/toggle', basicAuth, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email_required' });

  const members = getMembers();
  const idx = members.findIndex(m => (m.email || '').toLowerCase() === email.toLowerCase());
  if (idx === -1) return res.status(404).json({ error: 'not_found' });

  members[idx].active = !members[idx].active;
  saveMembers(members);

  // TELL-sync fjernet

  res.json({ ok: true, active: members[idx].active });
});

// Oppdatere plan for medlem (brukes av nytt admin-UI, via e-post)
app.post('/api/admin/members/update-plan', basicAuth, (req, res) => {
  const { email, plan } = req.body || {};
  if (!email || !plan) {
    return res.status(400).json({ ok: false, error: 'email_and_plan_required' });
  }

  const members = getMembers();
  const idx = members.findIndex(
    (m) => (m.email || '').toLowerCase() === String(email).toLowerCase()
  );

  if (idx === -1) {
    return res.status(404).json({ ok: false, error: 'member_not_found' });
  }

  members[idx].plan = plan;
  members[idx].updatedAt = new Date().toISOString();
  saveMembers(members);

  return res.json({ ok: true, member: members[idx] });
});

// Slette medlem (nytt admin-UI, via POST med e-post i body)
app.post('/api/admin/members/delete', basicAuth, (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    return res.status(400).json({ ok: false, error: 'email_required' });
  }

  const emailNorm = String(email).toLowerCase();
  const members = getMembers();
  const filtered = members.filter(
    (m) => (m.email || '').toLowerCase() !== emailNorm
  );

  if (filtered.length === members.length) {
    return res.status(404).json({ ok: false, error: 'member_not_found' });
  }

  // Vi fjerner ikke automatisk fra TELL her (samme praksis som delete-endpointet over)

  saveMembers(filtered);
  return res.json({ ok: true, deleted: 1 });
});

app.delete('/api/admin/members', basicAuth, async (req, res) => {
  const email = (req.query.email || '').toLowerCase();
  if (!email) return res.status(400).json({ error: 'email_required' });

  const members = getMembers();
  const victim = members.find(m => (m.email || '').toLowerCase() === email);
  const filtered = members.filter(m => (m.email || '').toLowerCase() !== email);
  if (filtered.length === members.length) {
    return res.status(404).json({ error: 'not_found' });
  }

  // TELL-sync fjernet (vi fjerner ikke automatisk fra TELL lenger)

  saveMembers(filtered);
  res.json({ ok: true });
});

app.post('/api/admin/tell-sync', basicAuth, async (req, res) => {
  try {
    if (!TELL.apiKey || !TELL.hwId || !TELL.appId) {
      return res.status(503).json({
        ok: false,
        error: 'tell_not_ready',
        detail: 'Mangler TELL_API_KEY / TELL_HWID / TELL_APP_ID',
      });
    }

    const members = getMembers() || [];

    // Velg hvem som skal synkes:
    // - aktiv
    // - og (valgfritt, anbefalt) gyldig validUntil for drop-in/korttid
    const eligible = members.filter((m) => {
      if (!m || !m.active) return false;

      // Hvis dere ønsker å *ignorere* validUntil og synke alle aktive,
      // kommenter ut linjen under.
      if (typeof isValidUntilOk === 'function' && !isValidUntilOk(m)) return false;

      // Må ha telefon i et av feltene
      const raw = m.phone || m.mobile || m.phoneFull;
      return !!raw;
    });

    const seen = new Set();
    const queue = [];

    for (const m of eligible) {
      const raw = m.phone || m.mobile || m.phoneFull;
      const norm = normalizePhone(raw);
      if (!norm) continue;
      if (seen.has(norm)) continue;
      seen.add(norm);

      const displayName = (m.name && String(m.name).trim() && !String(m.name).includes('@'))
        ? String(m.name).trim()
        : '';

      queue.push({ phone: norm, name: displayName });
    }

    if (!queue.length) {
      return res.status(400).json({
        ok: false,
        error: 'no_phones',
        detail: 'Fant ingen aktive medlemmer med gyldig telefonnummer å synke.',
      });
    }

    let attempted = 0;
    let ok = 0;
    let failed = 0;
    const failedPhones = [];

    for (const item of queue) {
      attempted++;
      try {
        await tellAddUser(item.phone, item.name);
        ok++;
      } catch (e) {
        failed++;
        failedPhones.push({
          phone: item.phone,
          err: e?.response?.data || e?.message || 'unknown_error',
        });
      }
      // enkel throttling for å være snill mot APIet
      await new Promise((r) => setTimeout(r, 120));
    }

    return res.json({
      ok: true,
      attempted,
      okCount: ok,
      failed,
      totalEligibleMembers: eligible.length,
      uniquePhones: queue.length,
      failedPhones,
    });
  } catch (e) {
    console.error('[TELL_SYNC_ERROR]', e?.response?.data || e?.message || e);
    return res.status(500).json({ ok: false, error: 'tell_sync_failed' });
  }
});
;

app.post('/api/admin/nif-import', basicAuth, (req, res) => {
  const { csv } = req.body || {};
  if (!csv || typeof csv !== 'string') {
    return res.status(400).json({ ok: false, error: 'csv_required' });
  }

  let members = getMembers();

  // Bygg opp indekser for raskt oppslag
  const byEmail = {};
  const byPhone = {};
  const byName = {};

  for (const m of members) {
    const email = (m.email || '').toLowerCase().trim();
    if (email) byEmail[email] = m;

    if (m.phone) {
      const p = normalizePhone ? normalizePhone(m.phone) : String(m.phone).trim();
      if (p) byPhone[p] = m;
    }

    const fullName = normalizeName(m.name || '');
    if (fullName) {
      if (!byName[fullName]) byName[fullName] = [];
      byName[fullName].push(m);
    }

    // Nullstill tidligere NIF-flagg før vi importerer nytt
    if (m.clubMemberSource === 'nif') {
      m.clubMember = false;
      m.clubMemberSource = undefined;
      m.clubMemberSyncedAt = undefined;
    }
  }

  let matched = 0;
  let unmatched = 0;
  let totalRows = 0;
  const ambiguous = [];

  const lines = csv.split(/\r?\n/).filter(l => l.trim().length > 0);

  for (const line of lines) {
    // hopp over header-rad
    if (line.toLowerCase().includes('fornavn') &&
        line.toLowerCase().includes('medlemsstatus')) {
      continue;
    }

    const parts = line.split(/[;]/).map(p => p.trim());
    if (parts.length < 6) continue;

    totalRows++;

    const fornavn = parts[0];
    const etternavn = parts[1];
    const emailRaw = parts[2];
    const phoneRaw = parts[3];
    const medlemsstatus = parts[5];

    // Vi bryr oss kun om "Aktiv" i NIF-lista
    if (medlemsstatus.toLowerCase() !== 'aktiv') continue;

    const email = (emailRaw || '').toLowerCase().trim();
    const phone = normalizePhone ? normalizePhone(phoneRaw) : String(phoneRaw || '').trim();
    const fullName = normalizeName(`${fornavn} ${etternavn}`);

    let candidate = null;

    // 1) e-post
    if (email && byEmail[email]) {
      candidate = byEmail[email];
    }
    // 2) telefon
    else if (phone && byPhone[phone]) {
      candidate = byPhone[phone];
    }
    // 3) navn (unik)
    else if (fullName && byName[fullName] && byName[fullName].length === 1) {
      candidate = byName[fullName][0];
    }
    // Flere med samme navn → logg, men ikke auto-match
    else if (fullName && byName[fullName] && byName[fullName].length > 1) {
      ambiguous.push({ fullName, count: byName[fullName].length });
      unmatched++;
      continue;
    }

    if (!candidate) {
      unmatched++;
      continue;
    }

    // Sjekk at denne faktisk har en IL-rabatt-plan
    if (!candidate.plan || !IL_DISCOUNT_PLANS.includes(candidate.plan)) {
      unmatched++;
      continue;
    }

    candidate.clubMember = true;
    candidate.clubMemberSource = 'nif';
    candidate.clubMemberSyncedAt = new Date().toISOString();
    matched++;
  }

  saveMembers(members);

  return res.json({
    ok: true,
    totalRows,
    matched,
    unmatched,
    ambiguous,
  });
});

app.get('/api/admin/logs', basicAuth, (req, res) => {
  try {
    if (!fs.existsSync(ACCESS_LOG)) {
      return res.json({ ok: true, lines: [] });
    }
    const raw = fs.readFileSync(ACCESS_LOG, 'utf-8');
    const lines = raw.split('\n').filter(Boolean).slice(-500);
    res.json({ ok: true, lines });
  } catch (e) {
    console.error('Kunne ikke lese access.log:', e.message);
    res.status(500).json({ ok: false, error: 'log_read_failed' });
  }
});

// =====================================================
// Legacy /access (epost-basert åpning)
// =====================================================
app.post('/access', async (req, res) => {
  try {
    const { email, doorId = 'styrkerom' } = req.body || {};
    if (!email) {
      return res.status(400).json({
        status: 'denied',
        ok: false,
        error: 'email_required',
      });
    }

    if (!doorConfig[doorId]) {
      return res.status(400).json({
        status: 'denied',
        ok: false,
        error: 'invalid_doorId',
      });
    }

    const members = getMembers();
    const member = members.find(m => (m.email || '').toLowerCase() === email.toLowerCase());
    if (!member) {
      return res.status(403).json({
        status: 'denied',
        ok: false,
        error: 'not_member',
      });
    }

    if (!member.active) {
      return res.status(403).json({
        status: 'denied',
        ok: false,
        error: 'inactive_member',
      });
    }

    const now = Date.now();
    const key = `legacy:${email}`;
    const info = openAttempts[key] || { lastAttempt: 0, count: 0 };
    if (now - info.lastAttempt < 5000) {
      info.count += 1;
    } else {
      info.count = 1;
    }
    info.lastAttempt = now;
    openAttempts[key] = info;

    if (info.count > 5) {
      appendAccessLog(
        `${new Date().toLocaleString('nb-NO', { timeZone: 'Europe/Oslo' })} email=${email} door=${doorId} gate=${doorConfig[doorId].gateIndex} action=DENY reason=rate_limit\n`,
      );
      return res.status(429).json({
        status: 'denied',
        ok: false,
        error: 'too_many_requests',
      });
    }

    if (!TELL.apiKey || !TELL.hwId || !TELL.appId) {
      console.warn('TELL-konfig ikke komplett – avviser /access');
      return res.status(503).json({
        status: 'error',
        ok: false,
        error: 'tell_not_ready',
      });
    }

    await gcOpen(doorConfig[doorId].gateIndex);

    const ts = new Date().toLocaleString('nb-NO', { timeZone: 'Europe/Oslo' });
    appendAccessLog(`${ts} email=${email} door=${doorId} gate=${doorConfig[doorId].gateIndex} action=OPEN_LEGACY\n`);
    console.log(`🚪 (legacy /access) Dør åpnet for ${email} (${member.name || ''}) kl ${ts}`);

    return res.json({
      status: 'granted',
      ok: true,
      doorId,
      gateIndex: doorConfig[doorId].gateIndex,
      member: {
        email: member.email,
        name: member.name || '',
      },
    });
  } catch (e) {
    console.error('ACCESS error:', e?.response?.data || e.message);
    appendAccessLog(
      `${new Date().toLocaleString('nb-NO', { timeZone: 'Europe/Oslo' })} email=${req.body?.email || '-'} door=${req.body?.doorId || '-'} action=DENY reason=open_failed\n`,
    );
    return res.status(502).json({
      status: 'error',
      ok: false,
      error: 'open_failed',
      detail: e?.response?.data || e.message,
    });
  }
});

// =====================================================
// Drop-in og token-basert adgang / ny variant
// =====================================================
function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Kombinert dropin/create – støtter både ny (phone,name) og gammel (email,mobile,name,price)
app.post('/dropin/create', async (req, res) => {
  try {
    const { phone, name, email, mobile, price } = req.body || {};

    let usedPhone = phone || mobile;
    let usedEmail = email || '';
    let usedPrice = price || 0;
    const personName = name || '';

    if (!usedPhone) {
      return res.status(400).json({ ok: false, error: 'phone_required' });
    }

    const phoneNormalized = normalizePhone(usedPhone);
    const token = generateToken();

    // Gyldig til 23:59 samme dag
    const now = new Date();
    const validUntil = new Date(now);
    validUntil.setHours(23, 59, 59, 999);

    // Nytt system: lagre i dropinTokens (for /dropin/verify)
    dropinTokens.set(token, {
      phone: phoneNormalized,
      expiresAt: validUntil.toISOString(),
    });

    // Gammelt system: activeDropins brukes av /door/open (for kompatibilitet)
    activeDropins.push({
      token,
      email: usedEmail,
      mobile: phoneNormalized,
      name: personName,
      price: usedPrice,
      createdAt: now.toISOString(),
      validUntil: validUntil.toISOString(),
    });

    // TELL-sync for drop-in er fjernet

    appendAccessLog(
      `[${new Date().toISOString()}] DROPIN_CREATE phone=${phoneNormalized} token=${token} validUntil=${validUntil.toISOString()}\n`,
    );

    return res.json({
      ok: true,
      token,
      expiresAt: validUntil.toISOString(),
      validUntil: validUntil.toISOString(),
    });
  } catch (err) {
    console.error('Feil i /dropin/create:', err);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// Ny: Verifiser token (bruker dropinTokens)
app.post('/dropin/verify', (req, res) => {
  const { token } = req.body || {};
  if (!token) {
    return res.status(400).json({ ok: false, error: 'token_required' });
  }

  const entry = dropinTokens.get(token);
  if (!entry) {
    return res.status(404).json({ ok: false, error: 'invalid_token' });
  }

  const now = new Date();
  const expires = new Date(entry.expiresAt);
  if (now > expires) {
    dropinTokens.delete(token);
    return res.status(410).json({ ok: false, error: 'token_expired' });
  }

  return res.json({ ok: true, phone: entry.phone, expiresAt: entry.expiresAt });
});

// Åpne dør via token / medlem – bruker activeDropins
app.post('/door/open', openingHoursGuard, async (req, res) => {
  try {
    const { token, email, phone, doorId = 'styrkerom' } = req.body || {};

    if (!doorConfig[doorId]) {
      return res.status(400).json({ ok: false, error: 'invalid_doorId' });
    }

    // Finn medlem basert på telefon eller e-post
    let member = null;
    if (phone || email) {
      member = findMemberByPhoneOrEmail(phone || null, email || null);
      if (member && (!member.active || !isValidUntilOk(member))) {
        member = null;
      }
    }

    const now = new Date();
    const dropin = activeDropins.find(
      d => d.token === token && new Date(d.validUntil) >= now
    );

    if (!member && !dropin) {
      console.log('[DOOR_NO_ACCESS] {',
        '\n  email:', email,
        '\n  phone:', phone,
        '\n  hasMember:', !!member,
        '\n  hasDropin:', !!dropin,
        '\n}');

      return res.status(403).json({ ok: false, error: 'no_access' });
    }

    if (!TELL.apiKey || !TELL.hwId || !TELL.appId) {
      console.warn('TELL-konfig ikke komplett – kan ikke åpne dør via /door/open');
      return res.status(503).json({ ok: false, error: 'tell_not_ready' });
    }

    await gcOpen(doorConfig[doorId].gateIndex);

    const source = member ? 'MEMBER' : 'DROPIN';
    const who = member
      ? (member.email || member.phone || 'ukjent')
      : `${dropin.email} (dropin)`;

    const ts = new Date().toLocaleString('nb-NO', { timeZone: 'Europe/Oslo' });

    appendAccessLog(
      `${ts} email=${who} door=${doorId} gate=${doorConfig[doorId].gateIndex} action=OPEN_${source}\n`
    );

    return res.json({ ok: true, source });
  } catch (e) {
    console.error('door/open error:', e?.response?.data || e.message);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});



// =====================================================
// Enkel innlogging (gammel epost/passord – beholdes)
// =====================================================
app.post('/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'email_and_password_required' });
  }

  const members = getMembers();
  const user = members.find(
    m => (m.email || '').toLowerCase() === email.toLowerCase() && m.password === password,
  );

  if (!user) return res.status(401).json({ ok: false, error: 'invalid_credentials' });
  if (!user.active) return res.status(403).json({ ok: false, error: 'inactive_member' });

  return res.json({ token: `token-${user.email}`, name: user.name || user.email });
});

// =====================================================
// SMS-innlogging (telefon + engangskode)
// =====================================================
app.post('/auth/send-code', async (req, res) => {
  try {
    const { phone } = req.body || {};
    if (!phone) {
      return res.status(400).json({ ok: false, error: 'phone_required' });
    }

    const phoneNormalized = normalizePhone(phone);
    if (!phoneNormalized) {
      return res.status(400).json({ ok: false, error: 'invalid_phone' });
    }

    // --- Apple testbruker: ikke send SMS, bare registrer testkode ---
    const applePhoneNormalized = normalizePhone(APPLE_TEST_PHONE || '');
    if (applePhoneNormalized && phoneNormalized === applePhoneNormalized) {
      const now = Date.now();
      loginCodes.set(phoneNormalized, {
        code: APPLE_TEST_CODE,
        // Gyldig lenge nok til at Apple rekker å teste (24 timer)
        codeExpiresAt: now + 24 * 60 * 60 * 1000,
        lastSentAt: now,
      });

      console.log('APPLE TEST: /auth/send-code for Apple test user – skipper SMS');
      return res.json({ ok: true, testUser: true });
    }
    // ---------------------------------------------------------------

    const existing = loginCodes.get(phoneNormalized) || {};
    const now = Date.now();
    if (existing.lastSentAt && now - existing.lastSentAt < 60000) {
      return res.status(429).json({ ok: false, error: 'too_many_requests' });
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeExpiresAt = now + 5 * 60 * 1000;

    await sendSmsLoginCode(phoneNormalized, code);

    loginCodes.set(phoneNormalized, { code, codeExpiresAt, lastSentAt: now });

    return res.json({ ok: true });
  } catch (e) {
    console.error('auth/send-code error:', e.message);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});


app.post('/auth/verify-code', async (req, res) => {
  try {
    const { phone, code } = req.body || {};
    if (!phone || !code) {
      return res
        .status(400)
        .json({ ok: false, error: 'phone_and_code_required' });
    }

    const phoneNormalized = normalizePhone(phone);
    if (!phoneNormalized) {
      return res.status(400).json({ ok: false, error: 'invalid_phone' });
    }

    const applePhoneNormalized = normalizePhone(APPLE_TEST_PHONE || '');

    // --- Apple testbruker: bypass vanlig kode-sjekk og medlemsregister ---
    if (
      applePhoneNormalized &&
      phoneNormalized === applePhoneNormalized &&
      String(code) === String(APPLE_TEST_CODE)
    ) {
      console.log('APPLE TEST: /auth/verify-code OK for Apple test user');

      return res.json({
        ok: true,
        isMember: true,
        member: {
          email: 'apple-test@lalmtreningssenter.no',
          name: 'Apple Testbruker',
          phone: phoneNormalized,
        },
        testUser: true,
      });
    }
    // ---------------------------------------------------------------------

    const entry = loginCodes.get(phoneNormalized);
    if (!entry || entry.code !== code) {
      return res.status(401).json({ ok: false, error: 'invalid_code' });
    }

    if (Date.now() > entry.codeExpiresAt) {
      loginCodes.delete(phoneNormalized);
      return res.status(401).json({ ok: false, error: 'code_expired' });
    }

    loginCodes.delete(phoneNormalized);

    const members = getMembers();
    const member = members.find((m) => {
      const candidatePhone = m?.phone || m?.phoneFull || m?.mobile || null;
      const mPhone = candidatePhone ? normalizePhone(candidatePhone) : null;
      return mPhone === phoneNormalized && m?.active && isValidUntilOk(m);
    });

    if (member) {
      return res.json({
        ok: true,
        isMember: true,
        member: {
          email: member.email,
          name: member.name || '',
          phone: phoneNormalized,
          validUntil: member.validUntil || null,
        },
      });
    }

    return res.json({
      ok: true,
      isMember: false,
      member: null,
    });
  } catch (e) {
    console.error('auth/verify-code error:', e.message);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});


// ===============================
// Vipps RETURN -> redirect til app
// ===============================
app.get('/vipps/return', (req, res) => {
  const { orderId, status } = req.query;

  const deeplinkBase =
    process.env.APP_RETURN_URL || 'lalmtreningssenter://payment-result';

  let finalStatus = 'success';

  if (status) {
    // Hvis vi en gang i fremtiden sender inn ?status=... eksplisitt, bruk den
    finalStatus = String(status);
  } else if (orderId) {
    const order = findOrder(String(orderId));

    if (!order) {
      finalStatus = 'unknown';
    } else {
      const os = order.status || order.vippsTransactionStatus || '';

      if (['CAPTURED', 'SALE'].includes(os)) {
        finalStatus = 'success';
      } else if (['CANCELLED', 'CANCELED', 'FAILED'].includes(os)) {
        finalStatus = 'cancelled';
      } else {
        // PENDING / RESERVED / annet → ikke vis som fullført
        finalStatus = 'pending';
      }
    }
  } else {
    finalStatus = 'unknown';
  }

  const deepLink =
    `${deeplinkBase}?status=${encodeURIComponent(finalStatus)}` +
    (orderId ? `&orderId=${encodeURIComponent(String(orderId))}` : '');

  return res.redirect(deepLink);
});

// =====================================================
// Vipps Checkout / eCom payment – NY modell m/orders.json
// =====================================================
app.post('/vipps/checkout', async (req, res) => {
  const ts = new Date().toISOString();
  console.log('MOTTOK /vipps/checkout', req.body);
  appendAccessLog(
    `[${ts}] VIPPS_CHECKOUT_REQUEST body=${JSON.stringify(req.body)}\n`
  );

    try {
    // HENT UT BEGGE FELT
    let {
      membershipKey,
      membershipId,
     phone,
     name,
     email,
     source,
     firstName,
      lastName
    } = req.body || {};

    // Bygg navn hvis web ikke sender "name"
    if (!name || !String(name).trim()) {
     const builtName = `${firstName || ''} ${lastName || ''}`.trim();
     if (builtName) {
       name = builtName;
      }
    }

// Normaliser nøkkelen (appen/web kan sende ulike varianter)
    if (membershipKey != null) membershipKey = String(membershipKey).trim();
    if (membershipId != null && (!membershipKey || !String(membershipKey).trim())) {
      membershipKey = String(membershipId).trim();
    }

    // Validering: vi krever IKKE e-post for drop-in/korttid (og i praksis ikke i checkout)
    // Krav: membershipKey + phone må finnes for å kunne knytte kjøpet til et nummer
    const phoneClean = String(phone || '').trim();
    if (!membershipKey || !String(membershipKey).trim() || !phoneClean) {
      return res.status(400).json({
        ok: false,
        error: 'membershipKey_phone_required',
      });
    }

    // bruk renset telefon videre
    phone = phoneClean;

// 1) Lag orderId
const orderId = 'ORDER-' + Date.now();

// 2) returnUrl
//  - App: via /vipps/return -> deeplink til appen
//  - Web: rett til takkesiden på nettsiden
const src = source || 'app';

let returnUrl;
if (src === 'web') {
  // vipps-takk.html må ligge på samme domene som index.html
  returnUrl = `https://lalmtreningssenter.no/vipps-takk.html?orderId=${orderId}`;
} else {
  returnUrl = `${process.env.SERVER_URL}/vipps/return?orderId=${orderId}`;
}

    // 3) Finn plan (fra plans.json eller fallback-tabell)
    const plans = getPlans();
    let selected = null;

    if (plans && Array.isArray(plans)) {
      const planObj = plans.find(
        (p) =>
          p &&
          (p.id === membershipKey || p.key === membershipKey) &&
          p.active !== false
      );
          if (planObj && typeof planObj.amount === 'number') {
      selected = {
        amount: planObj.amount,
        text: planObj.text || planObj.name || membershipKey,
        prorate: planObj.prorate !== false,
        type: planObj.type || null,
        shortTermDays: planObj.shortTermDays || 0,
        signupFee: planObj.signupFee || 0,
      };
    }
    }

    if (!selected) {
      const membershipMap = {
        LALM_IL_BINDING: {
          amount: 34900,
          text: 'Lalm IL-medlem - 12 mnd binding',
          prorate: true,
        },
        STANDARD_BINDING: {
          amount: 44900,
          text: 'Standard - 12 mnd binding',
          prorate: true,
        },
        HYTTE_BINDING: {
          amount: 16900,
          text: 'Hyttemedlemskap - 12 mnd binding',
          prorate: true,
        },

        // 🧪 TESTMEDLEMSKAP 1 kr
        Test_3kr: {
          amount: 300,
          text: 'TEST – 3 kr (ingen innmeldingsavgift)',
          prorate: false,
        },

        LALM_IL_UBIND: {
          amount: 44900,
          text: 'Lalm IL-medlem – uten binding',
          prorate: true,
        },
        STANDARD_UBIND: {
          amount: 54900,
          text: 'Standard – uten binding',
          prorate: true,
        },
        DROPIN: {
          amount: 14900, // 149 kr i øre (juster pris)
          text: 'Drop-in adgang (gyldig i dag)',
          prorate: false,
        },
      };

      selected = membershipMap[membershipKey] || null;
    }

    if (!selected) {
      return res.status(400).json({
        ok: false,
        error: `unknown_membershipKey`,
        membershipKey,
      });
    }


    // 4) Telefon-normalisering
    const phoneFull = normalizePhone(phone); // f.eks. +4790000000
    if (!phoneFull) {
      return res.status(400).json({ ok: false, error: 'invalid_phone' });
    }

    let digits = String(phoneFull).replace(/\D/g, ''); // f.eks. 4790000000
    if (digits.length === 10 && digits.startsWith('47')) {
      digits = digits.slice(2); // ta siste 8 sifre
    }
    if (digits.length !== 8) {
      return res.status(400).json({
        ok: false,
        error: 'phone_must_be_norwegian_8_digits',
        phoneSent: phone,
      });
    }
    const cleanPhone = digits; // 8 siffer

    // 5) Sjekk om det finnes aktivt medlem med samme tlf/e-post
    const existingMember = findMemberByPhoneOrEmail(phoneFull, email);
    if (existingMember && existingMember.active && isValidUntilOk(existingMember)) {
      appendAccessLog(
        `[${new Date().toISOString()}] VIPPS_CHECKOUT_BLOCKED_EXISTING_MEMBER phone=${phoneFull} email=${(email || '').toLowerCase()} memberId=${existingMember.id}\n`
      );

      return res.status(400).json({
        ok: false,
        error: 'Allerede aktivt medlemskap',
        title: 'Allerede aktivt medlemskap',
        message:
          'Det finnes allerede et aktivt medlemskap registrert på dette telefonnummeret eller denne e-postadressen. ' +
          'Hvis du mener dette er en feil, ta kontakt med Lalm Treningssenter for hjelp.',
      });
    }

    // 6) Dag-proratering første måned / korttid-dropin
    const now = new Date();
    const year = now.getFullYear();
    const month = now.getMonth();
    const day = now.getDate();

    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const remainingDays = daysInMonth - day + 1; // inkl. innmeldingsdagen

    // Korttid/drop-in = ikke prorasjon, ikke admin-gebyr
    const isShortOrDropin =
      (selected.type === 'short_term') ||
      (selected.type === 'dropin') ||
      (selected.shortTermDays && selected.shortTermDays > 0) ||
      String(membershipKey || '').trim().toLowerCase() === 'dropin';

    let fraction = 1;
    let prorationLabel = '';
    let firstMonthTrainingAmount = selected.amount;

    // 7) Innmeldingsavgift / admingebyr
    // Standard-medlemskap: 199,- admin + ev. plan.signupFee
    const ADMIN_FEE = 19900;
    let SIGNUP_FEE = 0;

    if (!isShortOrDropin) {
      SIGNUP_FEE = (selected.signupFee || 0) + ADMIN_FEE;

      // Spesial-test: TEST_1KR uten admin-gebyr
      if (membershipKey === 'TEST_1KR') {
        SIGNUP_FEE = 0;
      }
    }

    // Prorasjon kun for "vanlige" medlemskap der selected.prorate = true
    // UNNTAK: 'Test_3kr' skal ALDRI prorateres
    if (!isShortOrDropin && selected.prorate && selected.key !== 'TEST_1KR') {
      fraction = remainingDays / daysInMonth;
     firstMonthTrainingAmount = Math.round(selected.amount * fraction);
      prorationLabel = ` – første måned: ${remainingDays} av ${daysInMonth} dager`;
    } else {
     // Korttid / dropin / Test_3kr → ingen prorasjon
     fraction = 1;
     firstMonthTrainingAmount = selected.amount;
     prorationLabel = '';
    }

    // Sluttbeløp
    let finalAmount;
    if (isShortOrDropin) {
      // Kun selve beløpet for korttid/dropin
      finalAmount = selected.amount;
      SIGNUP_FEE = 0; // for sikkerhets skyld
    } else {
      finalAmount = firstMonthTrainingAmount + SIGNUP_FEE;
    }

    // Sikkerhet: Vipps krever minst 1 kr (100 øre)
    if (finalAmount < 100) {
      console.warn(
        'finalAmount < 100, justerer opp til 100. membershipKey=',
        membershipKey,
        'beregnet=',
        finalAmount
      );
      finalAmount = 100;
    }

    console.log('VIPPS BELØP', {
      membershipKey,
      selectedAmount: selected.amount,
      firstMonthTrainingAmount,
      SIGNUP_FEE,
      finalAmount,
      isShortOrDropin,
    });
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_AMOUNT_CALC orderId=${orderId} membershipKey=${membershipKey} full=${selected.amount} firstMonth=${firstMonthTrainingAmount} signupFee=${SIGNUP_FEE} final=${finalAmount} shortOrDropin=${isShortOrDropin}\n`
    );

    // Sikkerhet: Vipps krever minst 1 kr (100 øre)
    if (finalAmount < 100) {
      console.warn(
        'finalAmount < 100, justerer opp til 100. membershipKey=',
        membershipKey,
        'beregnet=',
        finalAmount
      );
      finalAmount = 100;
    }

    console.log('VIPPS BELØP', {
      membershipKey,
      selectedAmount: selected.amount,
      firstMonthTrainingAmount,
      SIGNUP_FEE,
      finalAmount,
    });
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_AMOUNT_CALC orderId=${orderId} membershipKey=${membershipKey} full=${selected.amount} firstMonth=${firstMonthTrainingAmount} signupFee=${SIGNUP_FEE} final=${finalAmount}\n`
    );

    const apiBase =
      process.env.VIPPS_ENV === 'test'
        ? 'https://apitest.vipps.no'
        : 'https://api.vipps.no';

    // 8) Hent access token (eCom)
    const tokenRes = await axios.post(
      `${apiBase}/accesstoken/get`,
      {},
      {
        headers: {
          'Content-Type': 'application/json',
          client_id: process.env.VIPPS_CLIENT_ID,
          client_secret: process.env.VIPPS_CLIENT_SECRET,
          'Ocp-Apim-Subscription-Key': process.env.VIPPS_SUBSCRIPTION_KEY,
          'Merchant-Serial-Number': process.env.VIPPS_MSN,
        },
      }
    );

    const accessToken = tokenRes.data.access_token;
    if (!accessToken) {
      throw new Error('Mangler access_token fra Vipps');
    }

    // 9) Initier betaling hos Vipps (reservasjon)
    const paymentBody = {
      customerInfo: {
        mobileNumber: cleanPhone,
      },
      merchantInfo: {
        merchantSerialNumber: process.env.VIPPS_MSN,
        callbackPrefix: process.env.VIPPS_CALLBACK_URL,
        // Vipps åpner denne URL-en etter betaling (fullført / avbrutt)
        fallBack: returnUrl,
      },
      transaction: {
        amount: finalAmount, // i øre – proratert + ev. innmeldingsavgift
        orderId,
        transactionText:
          selected.text +
          prorationLabel +
          (SIGNUP_FEE > 0 ? ' + innmeldingsavgift 199,-' : ''),
      },
    };

    const checkoutRes = await axios.post(
      `${apiBase}/ecomm/v2/payments`,
      paymentBody,
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${accessToken}`,
          'Ocp-Apim-Subscription-Key': process.env.VIPPS_SUBSCRIPTION_KEY,
          'Merchant-Serial-Number': process.env.VIPPS_MSN,
          'Vipps-System-Name': 'lalm-treningssenter',
          'Vipps-System-Version': '1.0.0',
          'Vipps-System-Plugin-Name': 'lalm-app',
          'Vipps-System-Plugin-Version': '1.0.0',
          'X-Request-Id': orderId,
        },
      }
    );

    console.log('Vipps checkout OK:', checkoutRes.data);
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_CHECKOUT_OK orderId=${orderId} amount=${finalAmount}\n`
    );

    const redirectUrl = checkoutRes.data.url || checkoutRes.data.redirectUrl;
    if (!redirectUrl) {
      console.error(
        'Uventet respons fra Vipps, fant ikke url',
        checkoutRes.data
      );
      return res.status(500).json({
        ok: false,
        error: 'missing_redirect_url_from_vipps',
      });
    }

    // 10) Lagre ordren i orders.json
    const nowIso = new Date().toISOString();
    upsertOrder({
      orderId,
      status: 'PENDING',
      membershipKey,
      phone: cleanPhone,
      phoneFull,
      name: name || '',
      email: (email || '').toLowerCase(),

      amount: finalAmount,
      signupFee: SIGNUP_FEE,
      firstMonthTrainingAmount,
      currency: 'NOK',
      daysInMonth,
      remainingDays,
      fraction,

      vippsTransactionStatus: null,
      vippsReference: null,
      memberId: null,
      processedAt: null,
      createdAt: nowIso,
      updatedAt: nowIso,
    });

    // 11) Svar til app/nettside
    return res.json({
      ok: true,
      url: redirectUrl,
      orderId,
      chargedAmount: finalAmount,
      fullMonthAmount: selected.amount,
      signupFee: SIGNUP_FEE,
      firstMonthTrainingAmount,
      currency: 'NOK',
      daysInMonth,
      remainingDays,
      fraction,
    });
  } catch (err) {
    console.error(
      'Vipps Checkout error:',
      err.response?.data || err.message || err
    );
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_CHECKOUT_ERROR err=${
        err.message
      } data=${JSON.stringify(err.response?.data || {})}\n`
    );

    if (!res.headersSent) {
      return res.status(500).json({
        ok: false,
        error: 'vipps_checkout_failed',
        details: err.response?.data || err.message || null,
      });
    }
  }  
});

// -----------------------------------------------------
// Vipps helpers: access token + auto-capture
// -----------------------------------------------------
async function getVippsAccessToken() {
  const apiBase =
    process.env.VIPPS_ENV === 'test'
      ? 'https://apitest.vipps.no'
      : 'https://api.vipps.no';

  const tokenRes = await axios.post(
    `${apiBase}/accesstoken/get`,
    {},
    {
      headers: {
        'Content-Type': 'application/json',
        client_id: process.env.VIPPS_CLIENT_ID,
        client_secret: process.env.VIPPS_CLIENT_SECRET,
        'Ocp-Apim-Subscription-Key': process.env.VIPPS_SUBSCRIPTION_KEY,
        'Merchant-Serial-Number': process.env.VIPPS_MSN,
      },
    }
  );

  const accessToken = tokenRes.data?.access_token;
  if (!accessToken) {
    throw new Error('Mangler access_token fra Vipps (getVippsAccessToken)');
  }
  return accessToken;
}

/**
 * Auto-capture av en Vipps-betaling.
 * - orderId: ORDER-...
 * - amountInOre: beløp i øre (bruk existingOrder.amount)
 * - transactionText: tekst som vises i Vipps
 */
async function vippsAutoCapture(orderId, amountInOre, transactionText) {
  const apiBase =
    process.env.VIPPS_ENV === 'test'
      ? 'https://apitest.vipps.no'
      : 'https://api.vipps.no';

  const accessToken = await getVippsAccessToken();

  const url = `${apiBase}/ecomm/v2/payments/${orderId}/capture`;

  // For full capture: IKKE send amount – Vipps tar hele reservert beløp
  const body = {
    merchantInfo: {
      merchantSerialNumber: process.env.VIPPS_MSN,
    },
    transaction: {
      transactionText:
        transactionText || 'Lalm Treningssenter medlemskap',
    },
  };

  const headers = {
  'Content-Type': 'application/json',
  Authorization: `Bearer ${accessToken}`,
  'Ocp-Apim-Subscription-Key': process.env.VIPPS_SUBSCRIPTION_KEY,
  'Merchant-Serial-Number': process.env.VIPPS_MSN,
  'Vipps-System-Name': 'lalm-treningssenter',
  'Vipps-System-Version': '1.0.0',
  'Vipps-System-Plugin-Name': 'lalm-app',
  'Vipps-System-Plugin-Version': '1.0.0',
  // Må være <= 40 tegn:
  'X-Request-Id': `capture-${orderId}`,
};

  appendAccessLog(
    `[${new Date().toISOString()}] VIPPS_AUTOCAPTURE_START orderId=${orderId} amount=${amountInOre}\n`
  );

  try {
    const res = await axios.post(url, body, { headers });

    if (res.status === 200) {
      appendAccessLog(
        `[${new Date().toISOString()}] VIPPS_AUTOCAPTURE_OK orderId=${orderId}\n`
      );
      return true;
    } else {
      appendAccessLog(
        `[${new Date().toISOString()}] VIPPS_AUTOCAPTURE_BAD_STATUS orderId=${orderId} httpStatus=${res.status} body=${JSON.stringify(
          res.data
        )}\n`
      );
      return false;
    }
  } catch (e) {
    console.error(
      'Feil ved auto-capture for orderId',
      orderId,
      e.response?.status,
      e.response?.data || e.message
    );
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_AUTOCAPTURE_ERROR orderId=${orderId} httpStatus=${
        e.response?.status
      } data=${JSON.stringify(e.response?.data || {})}\n`
    );
    return false;
  }
}

// -----------------------------------------------------
// Hjelpefunksjon: første dag i neste måned (YYYY-MM-DD)
// -----------------------------------------------------
// -----------------------------------------------------
// Tripletex: retry helpers for transient errors
// -----------------------------------------------------
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isTripletexTransientError(err) {
  const msg = String(err?.message || "").toLowerCase();
  const data = String(err?.response?.data || "").toLowerCase();

  // typiske midlertidige feil / gateway-feil / nettverk
  if (
    msg.includes("502") ||
    msg.includes("bad gateway") ||
    msg.includes("timeout") ||
    msg.includes("econnreset") ||
    msg.includes("etimedout") ||
    msg.includes("eai_again")
  ) {
    return true;
  }

  // noen ganger kommer HTML fra reverse proxy i stedet for JSON
  if (data.includes("<html") || data.includes("bad gateway") || data.includes("502")) {
    return true;
  }

  // defensivt: hvis Tripletex-klienten vår ender opp med "ugyldig JSON"
  // pga HTML/feilside, håndter det som transient og prøv igjen.
  if (msg.includes("ugyldig json") || (msg.includes("parse") && msg.includes("json"))) {
    return true;
  }

  return false;
}

async function withRetry(fn, opts = {}) {
  const retries = Number.isFinite(opts.retries) ? opts.retries : 2;
  const baseDelayMs = Number.isFinite(opts.baseDelayMs) ? opts.baseDelayMs : 800;
  const tag = opts.tag || "";

  let lastErr = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;

      const transient = isTripletexTransientError(e);
      console.warn(
        "[TRIPLETEX_RETRY]",
        tag,
        `attempt ${attempt + 1}/${retries + 1}`,
        "transient=",
        transient,
        "err=",
        e?.message || String(e)
      );

      if (!transient || attempt === retries) throw e;

      // enkel eksponentiell backoff
      await sleep(baseDelayMs * Math.pow(2, attempt));
    }
  }

  throw lastErr;
}

// =====================================================
// Tripletex side effects – sync + approve (asynkron, idempotent)
// =====================================================
async function processTripletexForOrder(orderId, newStatus, opts = {}) {
  const tag = opts.tag || `orderId=${orderId}`;
  try {
    const orderAfter = findOrder(orderId);
    if (!orderAfter) return { ok: false, skipped: true, reason: 'order_not_found' };

    const isPaidStatus = newStatus === 'SALE' || newStatus === 'CAPTURED';

    // Drop-in / korttid skal aldri synkes til Tripletex
    const keyLc = String(orderAfter.membershipKey || '').trim().toLowerCase();
    const isShortOrDropin =
     Boolean(orderAfter.isShortOrDropin) ||
     keyLc === 'dropin' ||
     keyLc.startsWith('korttid') ||
     keyLc.startsWith('shortterm');

    if (isShortOrDropin) {
     return { ok: true, skipped: true, reason: 'short_or_dropin' };
    }


    // ---------- A) SYNC TIL TRIPLETEX (kun ved betalt status, og kun én gang) ----------
    if (isPaidStatus && !orderAfter.tripletexSynced) {
      const allPlans = getPlans() || [];
      const originalPlan =
        allPlans.find(
          (pl) =>
            pl &&
            (pl.id === orderAfter.membershipKey || pl.key === orderAfter.membershipKey)
        ) || null;

      if (!originalPlan) {
        throw new Error(`plan_not_found membershipKey=${orderAfter.membershipKey}`);
      }

      // Bygg planobjekt som tripletexClient forventer
      const planForTripletex = {
        name: originalPlan.name || originalPlan.text || originalPlan.id || orderAfter.membershipKey,
        amount: typeof originalPlan.amount === 'number' ? originalPlan.amount : Number(originalPlan.amount || 0),
        tripletexProductId: originalPlan.tripletexProductId || originalPlan.tripletexproductid || originalPlan.tripletexId || originalPlan.tripletexid || null,
      };

      // Finn medlem-objekt (hvis vi har memberId), ellers fall tilbake til ordredata
      const allMembers = getMembers() || [];
      const memberObj =
        (orderAfter.memberId && allMembers.find((m) => m.id === orderAfter.memberId)) || null;

      const tripMember = {
        id: memberObj?.id || orderAfter.memberId || null,
        name: (memberObj?.name || orderAfter.name || orderAfter.email || '').trim(),
        email: (memberObj?.email || orderAfter.email || '').trim(),
        phone:
          memberObj?.phoneFull ||
          memberObj?.phone ||
          orderAfter.phoneFull ||
          normalizePhone(orderAfter.phone) ||
          null,
        address: memberObj?.address || orderAfter.address || null,
        zip: memberObj?.zip || orderAfter.zip || null,
        city: memberObj?.city || orderAfter.city || null,
      };

      const syncAttempts = Number(orderAfter.tripletexSyncAttempts || 0) + 1;
      updateOrderStatus(orderId, orderAfter.status || newStatus, {
        tripletexSyncAttempts: syncAttempts,
        tripletexLastAttemptAt: new Date().toISOString(),
        tripletexLastError: null,
      });

      const invoiceDate = firstDayOfNextMonth();

      // Lagre invoiceDate på ordren slik at approve/retry alltid har tilgang
      try {
        const o = findOrder(orderId) || orderAfter;
        if (o) {
         updateOrderStatus(orderId, o.status || newStatus, {
           tripletexInvoiceDate: invoiceDate, // "YYYY-MM-DD"
         });
        }
      } catch (e) {
       console.log('[TRIPLETEX] could not persist tripletexInvoiceDate:', e?.message || e);
      }

      const tripResult = await withRetry(
        () =>
         syncMembershipToTripletex({
            member: tripMember,
            plan: planForTripletex,
            invoiceDate,
            orderId,
          }),
        { tag: `sync ${tag}` }
      );


      // Forsøk å hente en relevant "ordreId" fra svaret
      const tripletexOrderId =
        tripResult?.order?.id ||
        tripResult?.invoice?.order?.id ||
        tripResult?.subscription?.id ||
        tripResult?.orderId ||
        null;

      updateOrderStatus(orderId, orderAfter.status || newStatus, {
        tripletexSynced: true,
        tripletexSyncedAt: new Date().toISOString(),
        tripletexOrderId: tripletexOrderId || orderAfter.tripletexOrderId || null,
        tripletexLastError: null,
        tripletexLastErrorAt: null,
      });

      appendAccessLog(
        `[${new Date().toISOString()}] TRIPLETEX_SYNC_OK orderId=${orderId} tripletexOrderId=${tripletexOrderId || '?'}\n`
      );
    }

    // ---------- B) AUTOMATISK GODKJENNING AV ABONNEMENT ----------
    const freshOrder = findOrder(orderId) || orderAfter;

    if (
     isPaidStatus &&
     freshOrder &&
     freshOrder.tripletexOrderId &&
      !freshOrder.tripletexSubscriptionApproved
    ) {
     const approveAttempts = Number(freshOrder.tripletexApproveAttempts || 0) + 1;

      // invoiceDate må være med – hent fra ordre hvis retry senere, ellers fra scope
     const invDate =
       freshOrder.tripletexInvoiceDate || invoiceDate || firstDayOfNextMonth();

     updateOrderStatus(orderId, freshOrder.status || newStatus, {
       tripletexApproveAttempts: approveAttempts,
       tripletexApproveLastAttemptAt: new Date().toISOString(),
       tripletexApproveLastError: null,
     });

      await withRetry(
       () => approveSubscriptionInvoice(freshOrder.tripletexOrderId, invDate),
       { tag: `approve ${tag}` }
     );

      updateOrderStatus(orderId, freshOrder.status || newStatus, {
       tripletexSubscriptionApproved: true,
       tripletexSubscriptionApprovedAt: new Date().toISOString(),
       tripletexSubscriptionApproveError: null,
       tripletexApproveLastError: null,
     });

     appendAccessLog(
       `[${new Date().toISOString()}] TRIPLETEX_SUBSCRIPTION_APPROVED orderId=${orderId} tripletexOrderId=${freshOrder.tripletexOrderId} invoiceDate=${invDate}\n`
      );
    }


    return { ok: true };
  } catch (err) {
    const msg = err?.message || String(err);

    console.warn('[TRIPLETEX_SIDEFX_ERROR]', tag, msg);

    // best effort: behold ordren, men logg feil så vi kan retry'e senere
    try {
      updateOrderStatus(orderId, newStatus, {
        tripletexLastError: msg,
        tripletexLastErrorAt: new Date().toISOString(),
      });
    } catch (_) {}

    appendAccessLog(
      `[${new Date().toISOString()}] TRIPLETEX_SIDEFX_ERROR orderId=${orderId} err=${msg}\n`
    );

    return { ok: false, error: msg };
  }
}

async function runTripletexRetryPass(opts = {}) {
  const maxToProcess = Number(opts.maxToProcess || 50);
  const force = Boolean(opts.force);
  const orders = getOrders() || [];
  let processed = 0;
  let ok = 0;
  let failed = 0;
  const details = [];

  for (const o of orders) {
    if (processed >= maxToProcess) break;
    if (!o || !o.orderId) continue;
    if (String(o.membershipKey || '').trim().toLowerCase() === 'dropin') continue;

    const status = o.status || '';
    const isPaid = status === 'SALE' || status === 'CAPTURED';

    const needsSync = isPaid && !o.tripletexSynced;
    const needsApprove =
      isPaid && o.tripletexOrderId && !o.tripletexSubscriptionApproved;

    if (!force && !needsSync && !needsApprove) continue;

    processed += 1;
    const r = await processTripletexForOrder(o.orderId, status, { tag: `retry orderId=${o.orderId}` });
    if (r.ok) ok += 1;
    else failed += 1;
    details.push({ orderId: o.orderId, ok: r.ok, error: r.error || null });
  }

  return { processed, ok, failed, details };
}




// -----------------------------------------------------

// -----------------------------------------------------
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isTripletexTransientError(err) {
  const msg = String(err?.message || '').toLowerCase();
  const data = String(err?.response?.data || '').toLowerCase();

  // typiske midlertidige feil / gateway-feil / nettverk
  if (
    msg.includes('502') ||
    msg.includes('bad gateway') ||
    msg.includes('timeout') ||
    msg.includes('econnreset') ||
    msg.includes('etimedout') ||
    msg.includes('eai_again')
  ) {
    return true;
  }

  // noen ganger kommer HTML fra reverse proxy i stedet for JSON
  if (data.includes('<html') || data.includes('bad gateway') || data.includes('502')) {
    return true;
  }

  // defensivt: hvis Tripletex-klienten vår ender opp med "ugyldig JSON"
  // pga HTML/feilside, håndter det som transient og prøv igjen.
  if (msg.includes('ugyldig json') || (msg.includes('parse') && msg.includes('json'))) {
    return true;
  }

  return false;
}

async function withRetry(fn, opts = {}) {
  const retries = Number.isFinite(opts.retries) ? opts.retries : 2;
  const baseDelayMs = Number.isFinite(opts.baseDelayMs) ? opts.baseDelayMs : 800;
  const tag = opts.tag || '';

  let lastErr = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;

      const transient = isTripletexTransientError(e);
      console.warn(
        '[TRIPLETEX_RETRY]',
        tag,
        `attempt ${attempt + 1}/${retries + 1}`,
        'transient=',
        transient,
        'err=',
        e?.message || String(e)
      );

      if (!transient || attempt === retries) throw e;

      // enkel eksponentiell backoff
      await sleep(baseDelayMs * (2 ** attempt));
    }
  }

  throw lastErr;
}
function firstDayOfNextMonth(fromDate = new Date()) {
  const year = fromDate.getFullYear();
  const month = fromDate.getMonth(); // 0–11

  const nextMonth = (month + 1) % 12;
  const nextYear = year + (month === 11 ? 1 : 0);

  const d = new Date(nextYear, nextMonth, 1);
  return d.toISOString().slice(0, 10); // 'YYYY-MM-DD'
}

// =====================================================
// Vipps callback – idempotent + auto-capture
// =====================================================
app.post('/vipps/callback/v2/payments/:orderId', async (req, res) => {
  const { orderId } = req.params || {};
  const ts = new Date().toISOString();
  const body = req.body || {};

  const callbackStatus =
    (body.transactionInfo && body.transactionInfo.status) ||
    (body.transactionSummary && body.transactionSummary.transactionStatus) ||
    '';

  console.log(
    'MOTTOK Vipps callback for orderId:',
    orderId,
    'status:',
    callbackStatus
  );
  appendAccessLog(
    `[${ts}] VIPPS_CALLBACK orderId=${orderId} statusRaw=${callbackStatus} body=${JSON.stringify(
      body
    )}\n`
  );

  try {
    const status = String(callbackStatus || '').toUpperCase();

    // 1) Finn ordren i orders.json
    const existingOrder = findOrder(orderId);
    if (!existingOrder) {
      appendAccessLog(
        `[${new Date().toISOString()}] VIPPS_CALLBACK_NO_ORDER orderId=${orderId}\n`
      );
      if (!res.headersSent) return res.status(200).send('OK');
      return;
    }

    // 2) Idempotens: hvis vi allerede har en "ferdig" status, gjør ingenting
    const isAlreadyHandled =
     ['SALE', 'CAPTURED'].includes(existingOrder.status);

    if (isAlreadyHandled) {
      appendAccessLog(
       `[${new Date().toISOString()}] VIPPS_CALLBACK_IDEMPOTENT orderId=${orderId} alreadyStatus=${existingOrder.status}\n`
      );
      if (!res.headersSent) return res.status(200).send('OK');
      return;
    }


    // 3) Mappe status fra Vipps -> vår interne status
    let newStatus = existingOrder.status;

    if (['SALE', 'CAPTURED', 'RESERVED', 'RESERVE'].includes(status)) {
      newStatus = status === 'RESERVE' ? 'RESERVED' : status;
    } else if (['CANCELLED', 'CANCELED', 'REFUND', 'REVERSED'].includes(status)) {
      newStatus = 'CANCELLED';
    } else if (status === 'FAILED') {
      newStatus = 'FAILED';
    }

    const vippsReference =
      (body.transactionInfo && body.transactionInfo.transactionId) ||
      (body.transactionSummary && body.transactionSummary.transactionId) ||
      null;

    // 3.1 AUTO-CAPTURE: hvis Vipps sier RESERVED/RESERVE → prøv å belaste
    if (['RESERVE', 'RESERVED'].includes(status)) {
      try {
        const isDropinKey =
          String(existingOrder.membershipKey || '').trim().toLowerCase() === 'dropin';
        const captureText = isDropinKey
          ? 'Drop-in adgang Lalm Treningssenter'
          : 'Medlemskap Lalm Treningssenter';

        const amountInOre = existingOrder.amount; // samme som vi reserverte

        const captureOk = await vippsAutoCapture(
          orderId,
          amountInOre,
          captureText
        );

        if (captureOk) {
          newStatus = 'CAPTURED';
          appendAccessLog(
            `[${new Date().toISOString()}] VIPPS_AUTOCAPTURE_STATUS_UPDATED orderId=${orderId} newStatus=CAPTURED\n`
          );
        } else {
          appendAccessLog(
            `[${new Date().toISOString()}] VIPPS_AUTOCAPTURE_FAILED orderId=${orderId}\n`
          );
        }
      } catch (e) {
        console.error(
          'Feil ved auto-capture for orderId',
          orderId,
          e.message
        );
        appendAccessLog(
          `[${new Date().toISOString()}] VIPPS_AUTOCAPTURE_ERROR orderId=${orderId} err=${e.message}\n`
        );
      }
    }

    // 3.2 Lagre oppdatert status på ordren
    const updatedOrder = updateOrderStatus(orderId, newStatus, {
      vippsTransactionStatus: status,
      vippsReference,
    });

    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_STATUS orderId=${orderId} status=${status} mapped=${newStatus}\n`
    );

    // 4) Ved betalt → aktiver medlem (uten TELL-sync)
    if (['RESERVED', 'SALE', 'CAPTURED'].includes(newStatus)) {
      const members = getMembers();
      const phoneDigits = String(updatedOrder.phone || '').replace(/\D/g, '');
      let membersChanged = false;
      let memberId = updatedOrder.memberId || null;

      // --------------------------------------------------
      // 4.1) Finn eksisterende medlem ved telefon (DROP-IN / KORTTID / ordinært)
      // --------------------------------------------------
      if (updatedOrder.phoneFull || updatedOrder.phone) {
        const phone = updatedOrder.phoneFull || updatedOrder.phone;

        // VIKTIG: finn medlem i SAMME array som skal lagres
        const m = members.find((x) => {
          const candidatePhone = x.phone || x.phoneFull || x.mobile || null;
          const normalized = candidatePhone
            ? String(candidatePhone).replace(/\D/g, '')
            : null;
         return normalized === String(phone).replace(/\D/g, '');
        })

        if (m) {
          console.log('[VIPPS] 4.1 RUNNING for order', orderId);
          // Aktiver medlem
          m.active = true;

          // Normaliser plan (samme format uansett kilde)
          const planKey =
            updatedOrder.membershipKey ||
            updatedOrder.membershipId ||
            updatedOrder.plan ||
            m.plan ||
            '';

          const planKeyLower = String(planKey).trim().toLowerCase();
          m.plan = planKeyLower;

          // Beregn validUntil for DROP-IN / korttid
          const computedValidUntil = computeValidUntilForPurchase(planKeyLower);

          if (computedValidUntil) {
            // DROP-IN eller korttid
            m.validUntil = computedValidUntil;
          } else {
           // Ordinært medlemskap → ingen tidsbegrensning
            if (m.validUntil) delete m.validUntil;
          }

          // Oppdater metadata
          m.updatedAt = new Date().toISOString();

          // VIKTIG: Ikke lagre her, og ikke returner.
          // Sett flagg og memberId så vi:
          //  - persister én gang senere
          //  - knytter order->memberId
          memberId = m.id || memberId;
          membersChanged = true;

         appendAccessLog(
            `[${new Date().toISOString()}] VIPPS_UPDATED_EXISTING_MEMBER orderId=${orderId} memberId=${memberId} plan=${m.plan} validUntil=${m.validUntil || 'null'}\n`
          );

          console.log('[VIPPS] 4.1 eksisterende medlem oppdatert', {
            phone,
            plan: m.plan,
            validUntil: m.validUntil || null,
            memberId,
         });
        }
      }

      // 4.2) Opprett / gjenbruk medlem (match på telefon først, deretter e-post)
      //      - Drop-in/korttid uten e-post støttes (placeholder e-post)
      //      - validUntil settes for drop-in/korttid, fjernes for ordinære medlemskap
      if (!memberId) {
        const phoneRaw = updatedOrder.phoneFull || updatedOrder.phone || '';
        const phoneNormalized = normalizePhone(phoneRaw);

        const planKeyRaw =
          updatedOrder.membershipKey ||
          updatedOrder.membershipId ||
          updatedOrder.plan ||
          null;

        const planKey = String(planKeyRaw || '').trim();
        const planKeyLower = planKey.toLowerCase();

        const placeholderEmail =
          (updatedOrder.email && String(updatedOrder.email).trim())
            ? String(updatedOrder.email).trim().toLowerCase()
            : `temp-${String(phoneRaw).replace(/\D/g, '') || Date.now()}@lalmtreningssenter.no`;

       // 1) Finn eksisterende medlem: primært telefon, sekundært e-post
       //    (for drop-in/korttid kan e-post være placeholder)
        const existing =
          findMemberByPhoneOrEmail(phoneNormalized, null) ||
          findMemberByPhoneOrEmail(null, placeholderEmail);

        const computedValidUntil = computeValidUntilForPurchase(planKey);

        if (existing) {
         // --- Gjenbruk eksisterende ---
         existing.active = true;
         existing.updatedAt = new Date().toISOString();

         // Oppdater plan (men ikke ødelegg hvis planKey mangler)
         if (planKey) {
           existing.plan = planKeyLower;
         } else if (!existing.plan) {
           existing.plan = null;
         }

          // Sett validUntil for drop-in/korttid, ellers fjern
          if (computedValidUntil) {
            existing.validUntil = computedValidUntil;
          } else {
            if (existing.validUntil) delete existing.validUntil;
         }

          // Sørg for at email finnes som streng (app forventer ofte string)
          if (!existing.email) existing.email = placeholderEmail;

          // Sørg for at phone finnes i normalisert form
          if (!existing.phone && phoneNormalized) existing.phone = phoneNormalized;

         memberId = existing.id || null;
          membersChanged = true;

          appendAccessLog(
            `[${new Date().toISOString()}] VIPPS_REUSED_MEMBER orderId=${orderId} memberId=${memberId} plan=${existing.plan} validUntil=${existing.validUntil || 'null'}\n`
         );
        } else {
          // --- Opprett nytt medlem ---
          const newMemberId = `mem_${Date.now()}_${Math.floor(Math.random() * 100000)}`;

         const newMember = {
           id: newMemberId,
           email: placeholderEmail,
           name: updatedOrder.name || '',
           phone: phoneNormalized,
           active: true,
           plan: planKey ? planKeyLower : null,
           clubMember: false,
           createdAt: new Date().toISOString(),
           updatedAt: new Date().toISOString(),
         };

         // validUntil: kun drop-in/korttid
         if (computedValidUntil) {
           newMember.validUntil = computedValidUntil;
         }

         members.push(newMember);
         membersChanged = true;
         memberId = newMemberId;

         appendAccessLog(
            `[${new Date().toISOString()}] VIPPS_CREATED_MEMBER orderId=${orderId} memberId=${memberId} plan=${newMember.plan} validUntil=${newMember.validUntil || 'null'}\n`
         );
       }
      }

      // Persistér kun hvis endringer
      if (membersChanged) {
       saveMembers(members);
       appendAccessLog(
         `[${new Date().toISOString()}] VIPPS_ACTIVATED orderId=${orderId} memberId=${memberId}
`
       );
      } else {
       appendAccessLog(
         `[${new Date().toISOString()}] VIPPS_NO_MEMBER_CHANGE orderId=${orderId}
`
       );
      }

      // Knytt order -> memberId (nyttig for feilsøking og Tripletex)
      if (memberId) {
        try {
          updateOrderStatus(orderId, newStatus, { memberId });
        } catch (_) {}
      }


      // 4.3) Tripletex-sync + automatisk godkjenning av abonnement (asynkron – ikke blokkér Vipps-callback)
      setImmediate(() => {
        processTripletexForOrder(orderId, newStatus, { tag: `vipps-callback orderId=${orderId}` })
          .catch((e) => {
            const msg = e?.message || String(e);
            console.warn('[TRIPLETEX_SIDEFX_UNHANDLED]', orderId, msg);
            appendAccessLog(
              `[${new Date().toISOString()}] TRIPLETEX_SIDEFX_UNHANDLED orderId=${orderId} err=${msg}
`
            );
          });
      });

      // 4.4) Send velkommen-SMS én gang (også DROP-IN og KORTTID)
      try {
        const orderAfter = findOrder(orderId);

        if (
         orderAfter &&
         !orderAfter.welcomeSmsSent && // bare én gang
          (newStatus === 'SALE' || newStatus === 'CAPTURED') // kun når faktisk belastet
       ) {
         const allMembers = getMembers();
          const memberObj =
           (orderAfter.memberId &&
              allMembers.find((m) => m.id === orderAfter.memberId)) || null;

         await sendWelcomeMembershipSms(orderAfter, memberObj);

          updateOrderStatus(orderId, orderAfter.status, {
           welcomeSmsSent: true,
            welcomeSmsAt: new Date().toISOString(),
          });
       }
      } catch (e) {
        console.log('[WELCOME_SMS_ERROR]', e?.message || e);
      }
    }

    if (!res.headersSent) return res.status(200).send('OK');
  } catch (err) {
    console.error(
      'Vipps callback error:',
      err?.response?.data || err.message || err
    );
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_CALLBACK_ERROR orderId=${orderId} err=${err.message}\n`
    );
    if (!res.headersSent) return res.status(200).send('OK');
  }
});


// =====================================================
// Vipps – status-endepunkt for appen (polling)
// =====================================================
app.get('/vipps/order-status/:orderId', (req, res) => {
  const orderId = String(req.params.orderId || '').trim();
  if (!orderId) {
    return res.status(400).json({ ok: false, error: 'orderId_required' });
  }

  const order = findOrder(orderId);
  if (!order) {
    // Ikke teknisk feil – bare at vi ikke har rukket å lagre ordren ennå
    return res.json({ ok: false, found: false });
  }

  const rawStatus = order.status || order.vippsTransactionStatus || 'PENDING';
  const status = String(rawStatus || '').toUpperCase();

  // "Betalt" i vår verden = samme logikk som i callbacken:
  // vi aktiverer medlem ved RESERVED / SALE / CAPTURED.
  const isPaid = ['RESERVED', 'SALE', 'CAPTURED'].includes(status);

  return res.json({
    ok: true,
    found: true,
    status,
    isPaid,
    membershipKey: order.membershipKey || null,
    memberId: order.memberId || null,
    email: order.email || null,
    processedAt: order.processedAt || null,
  });
});


/**
 * Admin-endpoint: send SMS til medlemmer
 * body: { message: string, segment: 'active' | 'inactive' | 'all' }
 */
app.post('/admin/sms/broadcast', basicAuth, async (req, res) => {
  try {
    const { message, segment } = req.body || {};

    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Meldingen kan ikke være tom.' });
    }

    // Bruk eksisterende helper
    const members = getMembers();

    let targets = members;
    if (segment === 'active') {
      targets = members.filter((m) => m.active); // feltet heter "active"
    } else if (segment === 'inactive') {
      targets = members.filter((m) => !m.active);
    }
    // segment === 'all' → ingen ekstra filtrering

    // Plukk ut unike telefonnummer
    const seen = new Set();
    const phones = [];

    for (const m of targets) {
      // vi prøver flere felt, siden gamle og nye members kan ha litt ulik struktur
      const candidatePhone = m.phone || m.mobile || m.phoneFull;
      if (!candidatePhone) continue;

      const norm = normalizePhone(candidatePhone);
      if (!norm) continue;
      if (seen.has(norm)) continue;

      seen.add(norm);
      phones.push(norm);
    }

    if (phones.length === 0) {
      return res.status(400).json({
        error: 'Fant ingen medlemmer med gyldig telefonnummer.',
      });
    }

    let sent = 0;
    let failed = 0;

    for (const phone of phones) {
      try {
        await sendSms(phone, message);
        sent++;
      } catch (err) {
        console.error('Feil ved SMS til', phone, err.message);
        failed++;
      }
    }

    return res.json({
      ok: true,
      segment: segment || 'all',
      totalCandidates: targets.length,
      attempted: phones.length,
      sent,
      failed,
    });
  } catch (err) {
    console.error('Feil i /admin/sms/broadcast:', err);
    return res
      .status(500)
      .json({ error: 'Kunne ikke sende SMS. Sjekk server-loggen.' });
  }
});

// ============================
// Backup to Cloudflare R2 (S3)
// + status logging to /data
// ============================
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

function envBool(v) {
  return String(v || '').toLowerCase() === 'true';
}

function safeNowStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function requireBackupAuth(req) {
  const secret = process.env.BACKUP_CRON_SECRET || '';
  const got = req.headers['x-backup-secret'] || '';
  return secret && got && String(secret) === String(got);
}

function getS3Client() {
  const endpoint = process.env.BACKUP_S3_ENDPOINT; // R2 endpoint
  return new S3Client({
    region: process.env.BACKUP_S3_REGION || 'auto',
    endpoint,
    forcePathStyle: true,
    credentials: {
      accessKeyId: process.env.BACKUP_S3_ACCESS_KEY_ID,
      secretAccessKey: process.env.BACKUP_S3_SECRET_ACCESS_KEY,
    },
  });
}

const BACKUP_DATA_DIR = process.env.BACKUP_DATA_DIR || '/data';
const BACKUP_STATUS_FILE = path.join(BACKUP_DATA_DIR, 'backup-status.json');
const BACKUP_LOG_FILE = path.join(BACKUP_DATA_DIR, 'backup-log.json');

function readJsonSafe(p, fallback) {
  try {
    if (!fs.existsSync(p)) return fallback;
    const raw = fs.readFileSync(p, 'utf8');
    return JSON.parse(raw || 'null') ?? fallback;
  } catch {
    return fallback;
  }
}

function writeJsonSafe(p, obj) {
  try {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(obj, null, 2), 'utf8');
  } catch (e) {
    console.warn('[BACKUP_LOG_WRITE_FAIL]', p, e?.message || e);
  }
}

function appendBackupLog(entry) {
  const arr = readJsonSafe(BACKUP_LOG_FILE, []);
  arr.push(entry);
  // behold f.eks. siste 200 rader
  const trimmed = arr.slice(-200);
  writeJsonSafe(BACKUP_LOG_FILE, trimmed);
  // siste status
  writeJsonSafe(BACKUP_STATUS_FILE, entry);
}

async function runBackupOnce() {
  const bucket = process.env.BACKUP_S3_BUCKET;
  const prefix = process.env.BACKUP_S3_PREFIX || '';

  if (!bucket) throw new Error('BACKUP_S3_BUCKET missing');
  if (!fs.existsSync(BACKUP_DATA_DIR)) throw new Error(`dataDir not found: ${BACKUP_DATA_DIR}`);

  const stamp = safeNowStamp();
  const rand = crypto.randomBytes(4).toString('hex');
  const fileName = `backup-${stamp}-${rand}.tar.gz`;
  const tmpPath = path.join(os.tmpdir(), fileName);

  // tar -czf <tmpPath> -C <dataDir> .
  await new Promise((resolve, reject) => {
    execFile('tar', ['-czf', tmpPath, '-C', BACKUP_DATA_DIR, '.'], (err) => {
      if (err) return reject(err);
      resolve();
    });
  });

  const key = `${prefix}${fileName}`;
  const s3 = getS3Client();

  await s3.send(new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: fs.createReadStream(tmpPath),
    ContentType: 'application/gzip',
  }));

  // filstørrelse for logging
  let bytes = null;
  try { bytes = fs.statSync(tmpPath).size; } catch {}

  // cleanup tmp
  try { fs.unlinkSync(tmpPath); } catch {}

  return { bucket, key, fileName, bytes };
}

// ---- ROUTES ----
// Trigger backup (for cron / manual)
app.post('/internal/backup/run', async (req, res) => {
  const startedAt = new Date().toISOString();

  try {
    if (!envBool(process.env.BACKUP_ENABLED)) {
      return res.status(403).json({ ok: false, error: 'backup_disabled' });
    }
    if (!requireBackupAuth(req)) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }

    const result = await runBackupOnce();

    const entry = {
      ok: true,
      startedAt,
      finishedAt: new Date().toISOString(),
      ...result,
    };
    appendBackupLog(entry);

    return res.json({ ok: true, ...result });
  } catch (e) {
    const entry = {
      ok: false,
      startedAt,
      finishedAt: new Date().toISOString(),
      error: String(e?.message || e),
    };
    appendBackupLog(entry);

    console.error('[BACKUP_ERROR]', e);
    return res.status(500).json({ ok: false, error: 'backup_failed', detail: entry.error });
  }
});

// Read last backup status (useful for admin/monitoring)
app.get('/internal/backup/status', (req, res) => {
  // valgfritt: beskytt også denne med secret
  if (!requireBackupAuth(req)) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }
  const status = readJsonSafe(BACKUP_STATUS_FILE, null);
  return res.json({ ok: true, status });
});

// =====================================================
// Internal Tripletex retry endpoint + optional scheduler
// =====================================================
function requireTripletexAuth(req) {
  const secret = process.env.TRIPLETEX_CRON_SECRET || '';
  const got = req.headers['x-tripletex-secret'] || '';
  return secret && got && String(secret) === String(got);
}

app.post('/internal/tripletex/retry', async (req, res) => {
  if (!requireTripletexAuth(req)) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }

  const maxToProcess = Number(req.query.max || req.body?.max || 50);
  const force = String(req.query.force || req.body?.force || 'false') === 'true';

  try {
    const r = await runTripletexRetryPass({ maxToProcess, force });
    return res.json({ ok: true, ...r });
  } catch (e) {
    const msg = e?.message || String(e);
    appendAccessLog(
      `[${new Date().toISOString()}] TRIPLETEX_RETRY_ENDPOINT_ERROR err=${msg}
`
    );
    return res.status(500).json({ ok: false, error: 'retry_failed', detail: msg });
  }
});

// Optional: run a retry pass periodically (useful if Render Cron is not available).
// Enable by setting TRIPLETEX_RETRY_INTERVAL_MINUTES (e.g. 5).
const TRIPLETEX_RETRY_INTERVAL_MINUTES = Number(process.env.TRIPLETEX_RETRY_INTERVAL_MINUTES || 0);
if (TRIPLETEX_RETRY_INTERVAL_MINUTES > 0) {
  const ms = Math.max(1, TRIPLETEX_RETRY_INTERVAL_MINUTES) * 60 * 1000;
  console.log(`[TRIPLETEX] Retry scheduler enabled: every ${TRIPLETEX_RETRY_INTERVAL_MINUTES} min`);
  setInterval(async () => {
    try {
      const r = await runTripletexRetryPass({ maxToProcess: 30, force: false });
      if (r.failed > 0) {
        console.warn('[TRIPLETEX] retry pass completed with failures', r.failed);
      }
    } catch (e) {
      console.warn('[TRIPLETEX] retry pass error', e?.message || String(e));
    }
  }, ms);
}



// ----------------------------
// Start server
// ----------------------------
app.listen(PORT, () => {
  console.log(`✅ Server kjører på http://localhost:${PORT}`);
});

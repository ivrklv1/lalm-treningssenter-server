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
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

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
// Apple testbruker (for App Review)
// ----------------------------
const APPLE_TEST_PHONE = process.env.APPLE_TEST_PHONE || '+4712345678'; // legg inn ditt nr i .env
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

function normalizePhone(raw) {
  if (!raw) return '';

  let p = String(raw).trim();

  // Fjern mellomrom, bindestrek og parenteser
  p = p.replace(/[\s\-()]/g, '');

  // 00xx → +xx (f.eks. 0047 → +47)
  if (p.startsWith('00')) {
    p = '+' + p.slice(2);
  }

  // Hvis ikke + i starten, prøv å tolke som norsk nummer
  if (!p.startsWith('+')) {
    // 8 siffer → norsk nummer → legg til +47
    if (p.length === 8 && /^\d{8}$/.test(p)) {
      p = '+47' + p;
    }
    // 47 + 8 siffer → lag +47 + 8 siffer
    else if (p.length === 10 && p.startsWith('47') && /^\d+$/.test(p)) {
      p = '+' + p;
    }
  }

  return p;
}

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
  base: 'https://api.tell.hu',
  apiKey: process.env.TELL_API_KEY,
  hwId: process.env.TELL_HWID,                // f.eks. "11:22:33:44:55:D1"
  appId: process.env.TELL_APP_ID,             // 40-tegns appId fra /gc/addappid
  hwName: process.env.TELL_HW_NAME || 'Lalm Treningssenter',
  inserter: process.env.TELL_INSERTER || 'Lalm Treningssenter admin',
  schemes: (process.env.TELL_SCHEMES || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean),
};

// Hjelpefunksjon: lage auth-headere
function tellHeaders() {
  if (!TELL.apiKey || !TELL.hwId || !TELL.appId) {
    console.warn('TELL-konfig ikke komplett (API key / hwId / appId mangler).');
  }
  return {
    'Content-Type': 'application/json',
    'ApiKey': TELL.apiKey,
  };
}

// ----------------------------
// Legg til bruker i TELL (adgang) – /gc/adduser
// NB: Denne funksjonen blir ikke lenger brukt automatisk i systemet
// ----------------------------
async function tellAddUser(phone, name) {
  const phoneNormalized = normalizePhone(phone);
  if (!phoneNormalized) {
    console.warn('[TELL] tellAddUser kalt uten gyldig telefonnummer');
    return;
  }

  // Kun sifre til TELL (ingen + eller mellomrom)
  const phoneDigits = phoneNormalized.replace(/\D/g, '');
  if (!phoneDigits) {
    console.warn('[TELL] tellAddUser: klarte ikke å hente siffer fra telefon:', phone);
    return;
  }

  const headers = tellHeaders();

  // Body bygget etter "ADD USER" i dokumentasjonen
  const body = {
    hwId: TELL.hwId,
    hwName: TELL.hwName,
    appId: TELL.appId,

    // Brukernavn + visningsnavn
    name: phoneDigits,                // "username"
    fname: name || phoneDigits,       // "full name / comment"
    phoneNumber: phoneDigits,

    // Tilgangsskjema – kan være tom array hvis dere ikke bruker templates enda
    schemes: TELL.schemes,

    // Hva brukeren får lov til
    go1: true,       // kan styre utgang 1
    go2: false,      // ingen utgang 2
    out1: true,
    out2: false,

    // Varslinger – slått av til å begynne med
    pushD: false,
    smsD: false,
    call: false,
    sms: false,
    pushE: false,
    doorBell: false,
    cam1: false,
    cam2: false,

    // Hvem som la inn brukeren
    inserter: TELL.inserter,

    // Rolle: U = vanlig bruker
    role: 'U',

    // Ingen spesialregel
    specificRuleType: '',
  };

  console.log('[TELL] adduser payload:', body);

  try {
    const r = await axios.post(`${TELL.base}/gc/adduser`, body, { headers });
    console.log(`✅ [TELL] La til ${name} (${phoneDigits})`, r.data);
    fs.appendFileSync(
      ACCESS_LOG,
      `[${new Date().toISOString()}] [TELL SYNC] La til bruker ${name} ${phoneDigits}\n`
    );
    return r.data;
  } catch (e) {
    console.error(
      `❌ [TELL] Feil ved legg til ${phoneDigits}:`,
      e?.response?.data || e.message
    );
    fs.appendFileSync(
      ACCESS_LOG,
      `[${new Date().toISOString()}] [TELL SYNC ERROR] Klarte ikke legge til ${name} ${phoneDigits}: ${
        JSON.stringify(e?.response?.data || e.message)
      }\n`
    );
    throw e;
  }
}

// Fjern bruker i TELL
// NB: Ikke lenger brukt automatisk
async function tellRemoveUser(phone) {
  const phoneNormalized = normalizePhone(phone);
  if (!phoneNormalized) return;

  try {
    const headers = tellHeaders();
    const data = { hwid: TELL.hwid, appId: TELL.appId, phone: phoneNormalized };
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
  const data = { hwid: TELL.hwid, appId: TELL.appId, gateIndex };
  const r = await axios.post(`${TELL.base}/gc/open`, data, { headers });
  return r.data;
}

// Synk alle aktive medlemmer til TELL
// NB: Ikke lenger brukt via admin-API (endpoint er deaktivert)
async function tellSyncAll() {
  const members = getMembers();
  for (const m of members) {
    if (!m.phone) continue;
    try {
      if (m.active) {
        await tellAddUser(m.phone, m.name || m.email);
      } else {
        await tellRemoveUser(m.phone);
      }
    } catch (e) {
      console.error('[TELL SYNC ALL] Feil for', m.email, e?.response?.data || e.message);
    }
  }
}

// Test-endepunkt for TELL: sjekk at API-nøkkel, hwid og appId fungerer
app.post('/api/admin/tell-test', basicAuth, async (req, res) => {
  try {
    const headers = tellHeaders();
    const data = { hwid: TELL.hwid, appId: TELL.appId, gateIndex: 1 };

    const r = await axios.post(`${TELL.base}/gc/open`, data, { headers });
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

  console.log('Eurobate-respons (sendSms):', res.data);
  return res.data;
}

/**
 * Spesialisert funksjon for innloggingskode
 */
async function sendSmsLoginCode(phone, code) {
  const message = `Lalm Treningssenter: Din kode er ${code}.\n#${code}`;
  return sendSms(phone, message);
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
    email: email.toLowerCase(),
    active: !!active,
    name,
    phone: phoneNormalized,
    plan: plan || null,
    clubMember: false, // settes via NIF-import eller manuelt
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

// TELL-sync endpoint deaktivert
app.post('/api/admin/tell-sync', basicAuth, async (req, res) => {
  return res.status(501).json({ ok: false, error: 'tell_sync_disabled' });
});

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

    if (!TELL.apiKey || !TELL.hwid || !TELL.appId) {
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

// Åpne dør via token (app) – bruker activeDropins
app.post('/door/open', async (req, res) => {
  try {
    const { token, email, doorId = 'styrkerom' } = req.body || {};

    if (!doorConfig[doorId]) {
      return res.status(400).json({ ok: false, error: 'invalid_doorId' });
    }

    const member = getMembers().find(
      m => (m.email || '').toLowerCase() === (email || '').toLowerCase() && m.active,
    );

    const now = new Date();
    const dropin = activeDropins.find(
      d => d.token === token && new Date(d.validUntil) >= now,
    );

    if (!member && !dropin) {
      return res.status(403).json({ ok: false, error: 'no_access' });
    }

    if (!TELL.apiKey || !TELL.hwid || !TELL.appId) {
      console.warn('TELL-konfig ikke komplett – kan ikke åpne dør via /door/open');
      return res.status(503).json({ ok: false, error: 'tell_not_ready' });
    }

    await gcOpen(doorConfig[doorId].gateIndex);

    const source = member ? 'MEMBER' : 'DROPIN';
    const who = member ? member.email : `${dropin.email} (dropin)`;
    const ts = new Date().toLocaleString('nb-NO', { timeZone: 'Europe/Oslo' });
    appendAccessLog(`${ts} email=${who} door=${doorId} gate=${doorConfig[doorId].gateIndex} action=OPEN_${source}\n`);

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
    const member = members.find(
      m => normalizePhone(m.phone) === phoneNormalized && m.active,
    );

    if (member) {
      return res.json({
        ok: true,
        isMember: true,
        member: {
          email: member.email,
          name: member.name || '',
          phone: phoneNormalized,
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

  // Base deeplink kan evt. ligge i .env
  const deeplinkBase =
    process.env.APP_RETURN_URL || 'lalmtreningssenter://payment-result';

  const finalStatus = (status && String(status)) || 'success';

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
  appendAccessLog(`[${ts}] VIPPS_CHECKOUT_REQUEST body=${JSON.stringify(req.body)}\n`);

  try {
    const { membershipKey, phone, name, email } = req.body || {};

// E-post er påkrevd for alle andre enn DROPIN
if (!membershipKey || !phone || (!email && membershipKey !== 'DROPIN')) {
  return res.status(400).json({
    ok: false,
    error:
      membershipKey === 'DROPIN'
        ? 'membershipKey_phone_required'
        : 'membershipKey_phone_email_required'
  });
}


    // 1) Lag orderId
    const orderId = 'ORDER-' + Date.now();

    // 2) ⭐ returnUrl som peker til backend -> /vipps/return
    const returnUrl = `${process.env.SERVER_URL}/vipps/return?orderId=${orderId}`

    // Medlemskap og full månedspris (i øre)
    const membershipMap = {
      LALM_IL_BINDING: {
        amount: 34900,
        text: 'Lalm IL-medlem – 12 mnd binding',
        prorate: true
      },
      STANDARD_BINDING: {
        amount: 44900,
        text: 'Standard – 12 mnd binding',
        prorate: true
      },
      HYTTE_BINDING: {
        amount: 16900,
        text: 'Hyttemedlemskap – 12 mnd binding',
        prorate: true
      },

      // 🧪 TESTMEDLEMSKAP 1 kr
      TEST_1KR: {
        amount: 100,
        text: 'TEST – 1 kr (ingen innmeldingsavgift)',
        prorate: false
      },

      LALM_IL_UBIND: {
        amount: 44900,
        text: 'Lalm IL-medlem – uten binding',
        prorate: true
      },
      STANDARD_UBIND: {
        amount: 54900,
        text: 'Standard – uten binding',
        prorate: true
      },
      DROPIN: {
  amount: 14900, // 50 kr i øre (juster pris)
  text: 'Drop-in adgang (gyldig i dag)',
  prorate: false
},
    };

    const selected = membershipMap[membershipKey];
    if (!selected) {
      return res.status(400).json({
        ok: false,
        error: `unknown_membershipKey`,
        membershipKey
      });
    }

    // Telefon-normalisering
    const phoneFull = normalizePhone(phone); // f.eks. +4790000000
    if (!phoneFull) {
      return res.status(400).json({ ok: false, error: 'invalid_phone' });
    }

    // Vipps forventer 8-sifret norsk mobil i dette oppsettet
    let digits = String(phoneFull).replace(/\D/g, ''); // f.eks. 4790000000
    if (digits.length === 10 && digits.startsWith('47')) {
      digits = digits.slice(2); // ta siste 8 sifre
    }
    if (digits.length !== 8) {
      return res.status(400).json({
        ok: false,
        error: 'phone_must_be_norwegian_8_digits',
        phoneSent: phone
      });
    }

    const cleanPhone = digits; // 8 siffer

    // Dag-proratering første måned
    const now = new Date();
    const year = now.getFullYear();
    const month = now.getMonth();
    const day = now.getDate();

    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const remainingDays = daysInMonth - day + 1; // inkl. innmeldingsdagen

    let fraction = 1;
    let prorationLabel = '';
    let firstMonthTrainingAmount = selected.amount;

    if (selected.prorate) {
      fraction = remainingDays / daysInMonth;
      firstMonthTrainingAmount = Math.round(selected.amount * fraction);
      prorationLabel = ` – første måned: ${remainingDays} av ${daysInMonth} dager`;
    }

    // Innmeldingsavgift 199,-
let SIGNUP_FEE = 19900;
if (membershipKey === 'TEST_1KR' || membershipKey === 'DROPIN') {
  SIGNUP_FEE = 0;
}

    const finalAmount = firstMonthTrainingAmount + SIGNUP_FEE;

    const apiBase =
      process.env.VIPPS_ENV === 'test'
        ? 'https://apitest.vipps.no'
        : 'https://api.vipps.no';

    // 1. Hent access token
    const tokenRes = await axios.post(
      `${apiBase}/accesstoken/get`,
      {},
      {
        headers: {
          'Content-Type': 'application/json',
          client_id: process.env.VIPPS_CLIENT_ID,
          client_secret: process.env.VIPPS_CLIENT_SECRET,
          'Ocp-Apim-Subscription-Key': process.env.VIPPS_SUBSCRIPTION_KEY,
          'Merchant-Serial-Number': process.env.VIPPS_MSN
        }
      }
    );

    const accessToken = tokenRes.data.access_token;
    if (!accessToken) {
      throw new Error('Mangler access_token fra Vipps');
    }

    const paymentBody = {
      customerInfo: {
        mobileNumber: cleanPhone
      },
      merchantInfo: {
        merchantSerialNumber: process.env.VIPPS_MSN,
        callbackPrefix: process.env.VIPPS_CALLBACK_URL,
        // Vipps åpner denne URL-en etter betaling (fullført / avbrutt)
        // Her peker vi til backend, som igjen redirecter videre inn i appen via deeplink.
        fallBack: returnUrl
      },
      transaction: {
        amount: finalAmount, // i øre – proratert + innmeldingsavgift
        orderId,
        transactionText:
          selected.text +
          prorationLabel +
          (SIGNUP_FEE > 0 ? ' + innmeldingsavgift 199,-' : '')
      }
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
          'X-Request-Id': orderId
        }
      }
    );

    console.log('Vipps checkout OK:', checkoutRes.data);
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_CHECKOUT_OK orderId=${orderId} amount=${finalAmount}\n`
    );

    const redirectUrl = checkoutRes.data.url || checkoutRes.data.redirectUrl;
    if (!redirectUrl) {
      console.error('Uventet respons fra Vipps, fant ikke url', checkoutRes.data);
      return res.status(500).json({
        ok: false,
        error: 'missing_redirect_url_from_vipps'
      });
    }

    // Lagre ordren i orders.json
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
      updatedAt: nowIso
    });

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
      fraction
    });
  } catch (err) {
    console.error('Vipps Checkout error:', err.response?.data || err.message || err);
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_CHECKOUT_ERROR err=${err.message} data=${JSON.stringify(err.response?.data || {})}\n`
    );

    if (!res.headersSent) {
      return res.status(500).json({ ok: false, error: 'vipps_checkout_failed' });
    }
  }
});

// =====================================================
// Vipps callback – idempotent
// =====================================================
app.post('/vipps/callback/v2/payments/:orderId', async (req, res) => {
  const { orderId } = req.params || {};
  const ts = new Date().toISOString();
  const body = req.body || {};

  const callbackStatus =
    (body.transactionInfo && body.transactionInfo.status) ||
    (body.transactionSummary && body.transactionSummary.transactionStatus) ||
    '';

  console.log('MOTTOK Vipps callback for orderId:', orderId, 'status:', callbackStatus);
  appendAccessLog(
    `[${ts}] VIPPS_CALLBACK orderId=${orderId} statusRaw=${callbackStatus} body=${JSON.stringify(body)}\n`
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

    // 2) Idempotens
    if (['RESERVED', 'SALE', 'CAPTURED'].includes(existingOrder.status)) {
      appendAccessLog(
        `[${new Date().toISOString()}] VIPPS_CALLBACK_IDEMPOTENT orderId=${orderId} alreadyStatus=${existingOrder.status}\n`
      );
      if (!res.headersSent) return res.status(200).send('OK');
      return;
    }

    // 3) Oppdater ordrestatus
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

    const updatedOrder = updateOrderStatus(orderId, newStatus, {
      vippsTransactionStatus: status,
      vippsReference
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

      // 4.1) Finn ved telefon
      if (!memberId) {
        for (const m of members) {
          if (!m.phone) continue;
          const memberPhoneDigits = normalizePhone(m.phone).replace(/\D/g, '');
          if (memberPhoneDigits && memberPhoneDigits.endsWith(phoneDigits)) {
            m.active = true;
            m.plan = updatedOrder.membershipKey || m.plan || null;
            m.updatedAt = new Date().toISOString();
            membersChanged = true;

            memberId = m.id || null;
            // TELL-sync fjernet
          }
        }
      }

      // 4.2) Opprett nytt medlem hvis ingen match
      if (!memberId && updatedOrder.email) {
        const newMemberId = `mem_${Date.now()}_${Math.floor(Math.random() * 100000)}`;
        const newMember = {
          id: newMemberId,
          email: updatedOrder.email,
          name: updatedOrder.name || updatedOrder.email,
          phone: updatedOrder.phoneFull || normalizePhone(updatedOrder.phone),
          active: true,
          plan: updatedOrder.membershipKey || null,
          clubMember: false,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };

        members.push(newMember);
        membersChanged = true;
        memberId = newMemberId;

        // TELL-sync for nye medlemmer er fjernet

        appendAccessLog(
          `[${new Date().toISOString()}] VIPPS_CREATED_MEMBER orderId=${orderId} email=${newMember.email}\n`
        );
      }

      if (membersChanged) {
        saveMembers(members);
        appendAccessLog(
          `[${new Date().toISOString()}] VIPPS_ACTIVATED orderId=${orderId} phone=${phoneDigits} memberId=${memberId}\n`
        );
      } else {
        appendAccessLog(
          `[${new Date().toISOString()}] VIPPS_NO_MATCH orderId=${orderId} phone=${phoneDigits}\n`
        );
      }

      if (!updatedOrder.processedAt) {
        updateOrderStatus(orderId, newStatus, {
          memberId: memberId || updatedOrder.memberId || null,
          processedAt: new Date().toISOString()
        });
      }
    }

    if (!res.headersSent) return res.status(200).send('OK');
  } catch (err) {
    console.error('Vipps callback error:', err?.response?.data || err.message || err);
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_CALLBACK_ERROR orderId=${orderId} err=${err.message}\n`
    );
    if (!res.headersSent) return res.status(200).send('OK');
  }
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
      targets = members.filter((m) => m.active);   // merk: feltet heter "active"
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
      return res
        .status(400)
        .json({ error: 'Fant ingen medlemmer med gyldig telefonnummer.' });
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
    return res.status(500).json({ error: 'Kunne ikke sende SMS. Sjekk server-loggen.' });
  }
});

// ----------------------------
// Start server
// ----------------------------
app.listen(PORT, () => {
  console.log(`✅ Server kjører på http://localhost:${PORT}`);
});

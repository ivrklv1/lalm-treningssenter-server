// server.js
// ======================================================
// Treningssenter adgangsserver (Express + TELL Gate Control)
// - Medlemsregister (members.json)
// - Admin-API
// - Drop-in token til kl. 23:59 samme dag
// - /door/open med TELL-modul (token-baserte medlemmer + drop-in)
// - /access (gammel epost-basert variant, beholdes for kompatibilitet)
// ======================================================

const express = require('express');
const fs = require('fs');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
require('dotenv').config();
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);

// ----------------------------
// Global state
// ----------------------------
const activeDropins = []; // { token, validUntil, email, mobile, name, createdAt, price }
const loginCodes = new Map(); // phoneNormalized -> { code, codeExpiresAt, lastSentAt }
// Vipps: husk hvilket medlemskap/telefon som hører til en orderId
const vippsOrders = new Map(); // orderId -> { membershipKey, phone }

// ----------------------------
// Middleware
// ----------------------------
app.use(cors());
app.use(express.json());

// ----------------------------
// Statisk servering
// ----------------------------
app.use(express.static(path.join(__dirname, 'public')));

// ----------------------------
// Hjelpefunksjoner for members.json
// ----------------------------
function getMembers() {
  try {
    const raw = fs.readFileSync(path.join(__dirname, 'members.json'), 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('Kunne ikke lese members.json, returnerer tom array:', e.message);
    return [];
  }
}

function saveMembers(members) {
  try {
    fs.writeFileSync(
      path.join(__dirname, 'members.json'),
      JSON.stringify(members, null, 2),
      'utf-8',
    );
  } catch (e) {
    console.error('Kunne ikke skrive members.json:', e.message);
  }
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
// Door-allowlist & mapping
// ----------------------------
const doorConfig = {
  // Eksempel-konfig:
  // "styrkerom": { gateIndex: 1, description: "Hovedinngang treningssenter" },
  styrkerom: { gateIndex: 1, description: 'Hovedinngang treningssenter' },
};

// Hvilke treningsabonnement gir IL-medlemspris (rabatt)?
// Disse verdiene bruker vi som "plan"-koder på medlemmene.
const IL_DISCOUNT_PLANS = [
  'medlem_m_binding',   // Treningsavgift medlem m/binding (349/mnd)
  // 'medlem_u_binding', // legg til flere hvis du vil at disse også skal regnes som IL-rabatt
];

// ----------------------------
// Rate limiting (enkel)
// ----------------------------
const openAttempts = {}; // key: email/phone, val: { lastAttempt, count }

// ----------------------------
// Logging til access.log
// ----------------------------
function appendAccessLog(line) {
  try {
    fs.appendFileSync(path.join(__dirname, 'access.log'), line);
  } catch (e) {
    console.error('Kunne ikke skrive til access.log:', e.message);
  }
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
// Eurobate SMS-konfig
// ----------------------------
const EUROBATE_API_URL = 'https://api.eurobate.com/json_api.php';

const eurobateConfig = {
  user: process.env.EUROBATE_USER,
  password: process.env.EUROBATE_PASSWORD,
  originator: process.env.EUROBATE_ORIGINATOR || 'LalmTrening',
  simulate: process.env.EUROBATE_SIMULATE === '1' ? 1 : 0,
};

async function sendSmsLoginCode(phone, code) {
  const phoneNormalized = normalizePhone(phone);
  if (!phoneNormalized) {
    throw new Error('Ugyldig telefonnummer');
  }

  const msisdn = Number(phoneNormalized.replace('+', ''));
  if (!Number.isFinite(msisdn)) {
    throw new Error('Ugyldig msisdn etter normalisering');
  }

  const message = `Lalm Treningssenter: Din kode er ${code}.\n#${code}`;

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
    timeout: 10000,
  });

  const body = res.data;
  if (body && typeof body.error !== 'undefined' && body.error !== 0) {
    const reason = body.reason || body.info || 'ukjent feil';
    throw new Error(`Eurobate error ${body.error}: ${reason}`);
  }

  return body;
}

// ----------------------------
// TELL-konfig
// ----------------------------
const TELL = {
  base: 'https://api.tell.hu',
  apiKey: process.env.TELL_API_KEY,
  hwid: process.env.TELL_HWID,            // Hardware ID
  appId: process.env.TELL_APP_ID,         // App-ID / Channel ID
};

// Hjelpefunksjon: lage auth-headere
function tellHeaders() {
  if (!TELL.apiKey || !TELL.hwid || !TELL.appId) {
    console.warn('TELL-konfig ikke komplett, mangler env-variabler.');
  }
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${TELL.apiKey}`,
  };
}

// ----------------------------
// Åpne dør via TELL
// ----------------------------
async function gcOpen(gateIndex = 1) {
  const headers = tellHeaders();
  const payload = { hwid: TELL.hwid, appId: TELL.appId, data: Number(gateIndex || 1) };

  try {
    const r = await axios.get(`${TELL.base}/gc/open`, { headers, data: payload });
    console.log('✅ Døråpning sendt til TELL (GET)');
    return r.data;
  } catch (e) {
    console.warn('GET /gc/open feilet, prøver POST.', e?.response?.data || e.message);
  }

  const r2 = await axios.post(`${TELL.base}/gc/open`, payload, { headers });
  console.log('✅ Døråpning sendt til TELL (POST)');
  return r2.data;
}

// ----------------------------
// TELL: brukersynk (add/remove/sync)
// ----------------------------
async function tellAddUser(phone, name) {
  const phoneNormalized = normalizePhone(phone);
  if (!phoneNormalized) {
    console.warn('[TELL] tellAddUser kalt uten gyldig telefonnummer');
    return;
  }

  try {
    const headers = tellHeaders();
    const data = { hwid: TELL.hwid, appId: TELL.appId, phone: phoneNormalized, name };
    const r = await axios.post(`${TELL.base}/gc/adduser`, data, { headers });
    console.log(`✅ [TELL] La til ${name} (${phoneNormalized})`);
    fs.appendFileSync('access.log', `[${new Date().toISOString()}] [TELL SYNC] La til bruker ${name} ${phoneNormalized}\n`);
    return r.data;
  } catch (e) {
    console.error(`❌ [TELL] Feil ved legg til ${phoneNormalized}:`, e?.response?.data || e.message);
  }
}

async function tellRemoveUser(phone) {
  const phoneNormalized = normalizePhone(phone);
  if (!phoneNormalized) {
    console.warn('[TELL] tellRemoveUser kalt uten gyldig telefonnummer');
    return;
  }

  try {
    const headers = tellHeaders();
    const data = { hwid: TELL.hwid, appId: TELL.appId, phone: phoneNormalized };
    const r = await axios.post(`${TELL.base}/gc/deleteuser`, data, { headers });
    console.log(`🗑️ [TELL] Fjernet ${phoneNormalized}`);
    fs.appendFileSync('access.log', `[${new Date().toISOString()}] [TELL SYNC] Fjernet ${phoneNormalized}\n`);
    return r.data;
  } catch (e) {
    console.error(`❌ [TELL] Feil ved sletting av ${phoneNormalized}:`, e?.response?.data || e.message);
  }
}

async function tellSyncAll() {
  const members = getMembers().filter(m => m.active && m.phone);
  console.log(`🔄 [TELL SYNC] Starter synkronisering (${members.length} aktive medlemmer)`);
  for (const m of members) {
    const phoneNormalized = normalizePhone(m.phone);
    if (!phoneNormalized) continue;
    await tellAddUser(phoneNormalized, m.name || m.email);
  }
  console.log('✅ [TELL SYNC] Ferdig');
}

// ----------------------------
// H E A L T H
// ----------------------------
app.get('/health', (req, res) => {
  const tellReady = Boolean(TELL.apiKey && TELL.hwid && TELL.appId);
  res.json({
    status: 'ok',
    time: new Date().toISOString(),
    tellReady,
  });
});

// ----------------------------
// Admin-grensesnitt (HTML)
// ----------------------------
app.get('/admin', basicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// -------------------------------------------------
// SMS-innlogging (Eurobate)
// -------------------------------------------------
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

    const now = Date.now();
    const existing = loginCodes.get(phoneNormalized);
    if (existing && existing.lastSentAt && (now - existing.lastSentAt.getTime()) < 60 * 1000) {
      return res.status(429).json({ ok: false, error: 'too_many_requests' });
    }

    const code = String(crypto.randomInt(100000, 1000000));
    const expiresAt = new Date(now + 10 * 60 * 1000); // 10 minutter

    loginCodes.set(phoneNormalized, {
      code,
      expiresAt,
      lastSentAt: new Date(now),
    });

    await sendSmsLoginCode(phoneNormalized, code);

    return res.json({ ok: true });
  } catch (e) {
    console.error('auth/send-code error:', e?.response?.data || e.message);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

app.post('/auth/verify-code', (req, res) => {
  try {
    const { phone, code } = req.body || {};
    if (!phone || !code) {
      return res.status(400).json({ ok: false, error: 'phone_and_code_required' });
    }

    const phoneNormalized = normalizePhone(phone);
    if (!phoneNormalized) {
      return res.status(400).json({ ok: false, error: 'invalid_phone' });
    }

    const entry = loginCodes.get(phoneNormalized);
    if (!entry) {
      return res.status(400).json({ ok: false, error: 'code_not_found' });
    }

    const now = new Date();
    if (entry.expiresAt < now) {
      loginCodes.delete(phoneNormalized);
      return res.status(400).json({ ok: false, error: 'code_expired' });
    }

    if (String(entry.code) !== String(code).trim()) {
      return res.status(401).json({ ok: false, error: 'invalid_code' });
    }

    loginCodes.delete(phoneNormalized);

    const members = getMembers();
    const member = members.find(
      m => m.active && m.phone && normalizePhone(m.phone) === phoneNormalized
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

// -------------------------------------------------
// Drop-in og token-basert adgang
// -------------------------------------------------
function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

app.post('/dropin/create', async (req, res) => {
  const { email, mobile, name, price } = req.body || {};
  if (!email || !mobile || !name || !price) {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }

  const now = new Date();
  const validUntil = new Date(now);
  validUntil.setHours(23, 59, 59, 999);

  const token = generateToken();

  activeDropins.push({
    token,
    email,
    mobile,
    name,
    price,
    createdAt: now.toISOString(),
    validUntil: validUntil.toISOString()
  });

  return res.json({
    ok: true,
    token,
    validUntil: validUntil.toISOString()
  });
});

// -------------------------------------------------
// Åpne dør via token (app)
// -------------------------------------------------
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

// ----------------------------
// Medlems-API (offentlig)
// ----------------------------
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
  plan: null,          // settes i admin når dere bestemmer abonnement
  clubMember: false,   // settes via NIF-import eller manuelt
});

  saveMembers(members);
  return res.json({ ok: true, message: 'Registrert! Venter på godkjenning.' });
});

// ----------------------------
// Admin-API
// ----------------------------
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
    clubMember: false,           // settes via NIF-import eller manuelt
  };

  members.push(member);
  saveMembers(members);

  try {
    if (member.active && member.phone) {
      await tellAddUser(member.phone, member.name || member.email);
    }
  } catch (e) {
    console.error('tellAddUser error:', e?.response?.data || e.message);
  }

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

  try {
    const { phone, name, active } = members[idx];
    if (phone) {
      active
        ? await tellAddUser(phone, name || email.toLowerCase())
        : await tellRemoveUser(phone);
    }
  } catch (e) {
    console.error('TELL toggle sync error:', e?.response?.data || e.message);
  }

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

  try {
    if (victim?.phone) await tellRemoveUser(victim.phone);
  } catch (e) {
    console.error('tellRemoveUser error:', e?.response?.data || e.message);
  }

  saveMembers(filtered);
  res.json({ ok: true });
});

app.post('/api/admin/tell-sync', basicAuth, async (req, res) => {
  try {
    await tellSyncAll();
    res.json({ ok: true });
  } catch (e) {
    console.error('tellSyncAll error:', e?.response?.data || e.message);
    res.status(500).json({ ok: false, error: 'tell_sync_failed' });
  }
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

    const parts = line.split(/[;,]/).map(p => p.trim());
    if (parts.length < 6) continue;

    totalRows++;

    const fornavn = parts[0];
    const etternavn = parts[1];
    const emailRaw = parts[2];
    const phoneRaw = parts[3];
    // const statusdato = parts[4];
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
      // Finnes i NIF som aktiv, men har ikke IL-rabatt-abonnement i treningssenteret
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
    const logPath = path.join(__dirname, 'access.log');
    if (!fs.existsSync(logPath)) {
      return res.json({ ok: true, lines: [] });
    }
    const raw = fs.readFileSync(logPath, 'utf-8');
    const lines = raw.split('\n').filter(Boolean).slice(-500);
    res.json({ ok: true, lines });
  } catch (e) {
    console.error('Kunne ikke lese access.log:', e.message);
    res.status(500).json({ ok: false, error: 'log_read_failed' });
  }
});

// ----------------------------
// Legacy /access (epost-basert åpning)
// ----------------------------
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

// ----------------------------
// Enkel innlogging for appen (gammel epost/passord, kan beholdes)
// ----------------------------
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

// ----------------------------
// Vipps Checkout / eCom payment
// Dag-proratering + innmeldingsavgift 199,-
// ----------------------------
app.post('/vipps/checkout', async (req, res) => {
  console.log('MOTTOK /vipps/checkout', req.body);

  try {
    const { membershipKey, phone } = req.body;

    if (!membershipKey || !phone) {
      return res.status(400).json({
        error: 'membershipKey og phone må sendes i body'
      });
    }

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
        amount: 100, // 1 kr i øre
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
      // Hvis dere senere vil ha Vipps-dropin kan den inn her, uten prorate:
      // DROPIN: { amount: 14900, text: 'Drop-in', prorate: false }
    };

    const selected = membershipMap[membershipKey];
    if (!selected) {
      return res.status(400).json({
        error: `Ukjent membershipKey: ${membershipKey}`
      });
    }

    // Rens telefonnummer: kun 8 sifre (uten +47)
    const cleanPhone = String(phone).replace(/\D/g, '');
    if (cleanPhone.length !== 8) {
      return res.status(400).json({
        error: 'phone må være norsk mobilnummer med 8 siffer, uten +47'
      });
    }

    // ----------------------------
    // Dag-proratering første måned
    // ----------------------------
    const now = new Date();
    const year = now.getFullYear();
    const month = now.getMonth();      // 0-11
    const day = now.getDate();         // 1-31

    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const remainingDays = daysInMonth - day + 1; // inkl. innmeldingsdagen

    let fraction = 1;
    let prorationLabel = '';
    let firstMonthTrainingAmount = selected.amount; // bare trening, uten innmeldingsavgift

    if (selected.prorate) {
      fraction = remainingDays / daysInMonth;
      firstMonthTrainingAmount = Math.round(selected.amount * fraction);
      prorationLabel = ` – første måned: ${remainingDays} av ${daysInMonth} dager`;
    }

    // ----------------------------
    // Innmeldingsavgift 199,-
    // ----------------------------
// Innmeldingsavgift 199,- (men ikke for testmedlemskap)
let SIGNUP_FEE = 19900;

if (membershipKey === 'TEST_1KR') {
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

    const orderId = `LALM-${Date.now()}-${Math.floor(Math.random() * 100000)}`;

    const paymentBody = {
      customerInfo: {
        mobileNumber: cleanPhone
      },
      merchantInfo: {
        merchantSerialNumber: process.env.VIPPS_MSN,
        callbackPrefix: process.env.VIPPS_CALLBACK_URL,
        fallBack: `${process.env.VIPPS_FALLBACK_URL || 'https://lalmtreningssenter.no/takk'}?orderId=${orderId}`
      },
      
      transaction: {
        amount: finalAmount, // i øre – proratert + innmeldingsavgift
        orderId,
        transactionText:
          selected.text +
          prorationLabel +
          ' + innmeldingsavgift 199,-'
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

    const redirectUrl = checkoutRes.data.url || checkoutRes.data.redirectUrl;
    if (!redirectUrl) {
      console.error('Uventet respons fra Vipps, fant ikke url', checkoutRes.data);
      return res.status(500).json({
        error: 'Mangler redirect-url fra Vipps'
      });
    }
        // 🔹 LAGRE ORDREN LOKALT SLIK AT CALLBACK KAN KNYTTE DEN TIL MEDLEM
    vippsOrders.set(orderId, {
      membershipKey,
      phone: cleanPhone, // 8 siffer
    });

    // Send nyttig info tilbake til appen også
    return res.json({
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

    // Ikke prøv å sende nytt svar hvis vi allerede har svart
    if (!res.headersSent) {
      return res.status(500).json({ error: 'Vipps Checkout failed' });
    }
  }
});

// ----------------------------
// Vipps callback – blir kalt av Vipps etter betaling
// ----------------------------
app.post('/vipps/callback/v2/payments/:orderId', async (req, res) => {
  const { orderId } = req.params || {};
  const ts = new Date().toISOString();

  console.log('MOTTOK Vipps callback for orderId:', orderId);
  appendAccessLog(
    `[${ts}] VIPPS_CALLBACK orderId=${orderId} body=${JSON.stringify(req.body)}\n`
  );

  // Hent info vi lagret da vi startet betalingen
  const meta = vippsOrders.get(orderId);

  try {
    const apiBase =
      process.env.VIPPS_ENV === 'test'
        ? 'https://apitest.vipps.no'
        : 'https://api.vipps.no';

    // 1. Hent nytt access token
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
      throw new Error('Mangler access_token fra Vipps (callback)');
    }

    // 2. Hent detaljer om betalingen
    const detailsRes = await axios.get(
      `${apiBase}/ecomm/v2/payments/${orderId}/details`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Ocp-Apim-Subscription-Key': process.env.VIPPS_SUBSCRIPTION_KEY,
          'Merchant-Serial-Number': process.env.VIPPS_MSN,
        },
      }
    );

    const details = detailsRes.data || {};
    const status =
      details?.transactionSummary?.transactionStatus ||
      details?.transactionInfo?.status ||
      '';

    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_STATUS orderId=${orderId} status=${status}\n`
    );

    // 3. Hvis betalt → prøv å aktivere medlem
    if (
      meta &&
      typeof status === 'string' &&
      ['SALE', 'CAPTURED', 'RESERVED', 'RESERVE'].includes(
        status.toUpperCase()
      )
    ) {
      const members = getMembers();
      const phoneDigits = String(meta.phone || '').replace(/\D/g, '');

      let updated = false;

      for (const m of members) {
        if (!m.phone) continue;
        const memberPhoneDigits = normalizePhone(m.phone)
          .replace(/\D/g, '');

        if (
          memberPhoneDigits &&
          memberPhoneDigits.endsWith(phoneDigits)
        ) {
          m.active = true;
          // Lagre hvilken plan som ble valgt – enkelt: bruk membershipKey
          m.plan = meta.membershipKey || m.plan || null;
          updated = true;

          try {
            // Synkroniser til TELL hvis mulig
            await tellAddUser(m.phone, m.name || m.email);
          } catch (e) {
            console.error(
              'TELL sync fra Vipps callback feilet:',
              e?.response?.data || e.message
            );
          }
        }
      }

      if (updated) {
        saveMembers(members);
        appendAccessLog(
          `[${new Date().toISOString()}] VIPPS_ACTIVATED orderId=${orderId} phone=${phoneDigits}\n`
        );
      } else {
        appendAccessLog(
          `[${new Date().toISOString()}] VIPPS_NO_MATCH orderId=${orderId} phone=${phoneDigits}\n`
        );
      }
    }

    // Vipps krever bare 200 OK tilbake
    res.status(200).send('OK');
  } catch (e) {
    console.error(
      'Vipps callback error:',
      e?.response?.data || e.message || e
    );
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_CALLBACK_ERROR orderId=${orderId} error=${e.message}\n`
    );
    // Svar 200 likevel for å unngå at Vipps spammer callbacken
    res.status(200).send('OK');
  }
});


// ----------------------------
// Start server
// ----------------------------
app.listen(PORT, () => {
  console.log(`✅ Server kjører på http://localhost:${PORT}`);
});
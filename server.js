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

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------------
// Les inn medlemmer fra JSON-fil
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
// Hjelpefunksjoner for orders.json (Vipps-ordrer)
// ----------------------------
function getOrders() {
  try {
    const raw = fs.readFileSync(path.join(__dirname, 'orders.json'), 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('Kunne ikke lese orders.json, returnerer tom array:', e.message);
    return [];
  }
}

function saveOrders(orders) {
  try {
    fs.writeFileSync(
      path.join(__dirname, 'orders.json'),
      JSON.stringify(orders, null, 2),
      'utf-8',
    );
  } catch (e) {
    console.error('Kunne ikke skrive orders.json:', e.message);
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
// Data for drop-in tokens i minnet (ikke persistent)
// ----------------------------
const dropinTokens = new Map(); // tokenString -> { phone, expiresAt }

// ----------------------------
// Loggfil for debugging / sporing
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

  // Fjern eventuelle ledende nuller
  p = p.replace(/^00/, '+');

  // Hvis det står 8 siffer: anta norsk nummer
  if (/^\d{8}$/.test(p)) {
    return '+47' + p;
  }

  // Hvis det allerede starter med +, behold
  if (p.startsWith('+')) {
    return p;
  }

  // Hvis det starter med 47 og har 10 siffer, gjør om til +47
  if (/^47\d{8}$/.test(p)) {
    return '+'.concat(p);
  }

  // Som fallback, returner opprinnelig
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
// Legg til bruker i TELL (adgang)
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
    fs.appendFileSync(
      'access.log',
      `[${new Date().toISOString()}] [TELL SYNC] La til bruker ${name} ${phoneNormalized}\n`
    );
    return r.data;
  } catch (e) {
    console.error(
      `❌ [TELL] Feil ved legg til ${phoneNormalized}:`,
      e?.response?.data || e.message
    );
    fs.appendFileSync(
      'access.log',
      `[${new Date().toISOString()}] [TELL SYNC ERROR] Klarte ikke legge til ${name} ${phoneNormalized}: ${
        e?.response?.data?.message || e.message
      }\n`
    );
  }
}

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
// Hent alle medlemmer (admin)
// ----------------------------
app.get('/admin/members', basicAuth, (req, res) => {
  const members = getMembers();
  res.json(members);
});

// ----------------------------
// Legg til/oppdater medlem (admin)
// ----------------------------
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

// ----------------------------
// Enkelt medlemsoppslag (admin)
// ----------------------------
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

// ----------------------------
// Enkel innlogging (for testing)
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
// DROP-IN: Opprett token for dagsbruk
// ----------------------------
app.post('/dropin/create', async (req, res) => {
  try {
    const { phone, name } = req.body || {};
    if (!phone) {
      return res.status(400).json({ ok: false, error: 'phone_required' });
    }

    const normalizedPhone = normalizePhone(phone);
    const token = `DROPIN-${Date.now()}-${Math.floor(Math.random() * 100000)}`;

    const now = new Date();
    const expiresAt = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate(),
      23,
      59,
      59,
    );

    dropinTokens.set(token, {
      phone: normalizedPhone,
      expiresAt: expiresAt.toISOString(),
    });

    try {
      await tellAddUser(normalizedPhone, name || normalizedPhone);
    } catch (e) {
      console.error('Feil ved sync mot TELL for drop-in:', e?.message);
    }

    appendAccessLog(
      `[${new Date().toISOString()}] DROPIN_CREATE phone=${normalizedPhone} token=${token} expiresAt=${expiresAt.toISOString()}\n`,
    );

    return res.json({
      ok: true,
      token,
      expiresAt: expiresAt.toISOString(),
    });
  } catch (err) {
    console.error('Feil i /dropin/create:', err);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ----------------------------
// DROP-IN: Verifiser token
// ----------------------------
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

// ----------------------------
// Vipps Checkout / eCom payment
// Dag-proratering + innmeldingsavgift 199,-
// ----------------------------
app.post('/vipps/checkout', async (req, res) => {
  const ts = new Date().toISOString();
  console.log('MOTTOK /vipps/checkout', req.body);
  appendAccessLog(`[${ts}] VIPPS_CHECKOUT_REQUEST body=${JSON.stringify(req.body)}\n`);

  try {
    const { membershipKey, phone, name, email } = req.body || {};

    if (!membershipKey || !phone || !email) {
      return res.status(400).json({
        ok: false,
        error: 'membershipKey_phone_email_required'
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
      // Ev. senere: DROPIN, etc.
    };

    const selected = membershipMap[membershipKey];
    if (!selected) {
      return res.status(400).json({
        ok: false,
        error: `unknown_membershipKey`,
        membershipKey
      });
    }

    // ----------------------------
    // Telefon-normalisering
    // ----------------------------
    // full versjon til members/TELL
    const phoneFull = normalizePhone(phone);      // f.eks. +4790000000
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

    // 🔹 LAGRE ORDREN I orders.json SLIK AT CALLBACK KAN KNYTTE DEN TIL MEDLEM
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

    // Send nyttig info tilbake til appen også
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

// ----------------------------
// Vipps callback – blir kalt av Vipps etter betaling (idempotent)
// ----------------------------
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
      // Vipps forventer alltid 200 OK
      if (!res.headersSent) return res.status(200).send('OK');
      return;
    }

    // 2) Idempotens:
    // Hvis ordren allerede er i en endelig betalt-tilstand, gjør INGENTING.
    if (['RESERVED', 'SALE', 'CAPTURED'].includes(existingOrder.status)) {
      appendAccessLog(
        `[${new Date().toISOString()}] VIPPS_CALLBACK_IDEMPOTENT orderId=${orderId} alreadyStatus=${existingOrder.status}\n`
      );
      if (!res.headersSent) return res.status(200).send('OK');
      return;
    }

    // 3) Oppdater ordrestatus basert på Vipps-status
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

    // 4) Bare hvis ordren nå er "betalt"/reservasjon OK → aktiver medlem
    if (['RESERVED', 'SALE', 'CAPTURED'].includes(newStatus)) {
      const members = getMembers();
      const phoneDigits = String(updatedOrder.phone || '').replace(/\D/g, '');
      let membersChanged = false;
      let memberId = updatedOrder.memberId || null;

      // 4.1) Hvis vi ikke allerede har en memberId, prøv å finne via telefon
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
            try {
              await tellAddUser(m.phone, m.name || m.email);
            } catch (e) {
              console.error('TELL sync feilet:', e?.response?.data || e.message);
            }
          }
        }
      }

      // 4.2) Hvis fortsatt ingen match, opprett nytt medlem
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

        try {
          if (newMember.phone) {
            await tellAddUser(newMember.phone, newMember.name || newMember.email);
          }
        } catch (e) {
          console.error('TELL sync (nytt medlem) feilet:', e?.response?.data || e.message);
        }

        appendAccessLog(
          `[${new Date().toISOString()}] VIPPS_CREATED_MEMBER orderId=${orderId} email=${newMember.email}\n`
        );
      }

      // 4.3) Lagre members.json hvis vi gjorde endringer
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

      // 4.4) Marker at ordren er behandlet (første gang) – idempotent
      if (!updatedOrder.processedAt) {
        updateOrderStatus(orderId, newStatus, {
          memberId: memberId || updatedOrder.memberId || null,
          processedAt: new Date().toISOString()
        });
      }
    }

    // Vipps forventer alltid 200 OK
    if (!res.headersSent) return res.status(200).send('OK');
  } catch (err) {
    console.error('Vipps callback error:', err?.response?.data || err.message || err);
    appendAccessLog(
      `[${new Date().toISOString()}] VIPPS_CALLBACK_ERROR orderId=${orderId} err=${err.message}\n`
    );
    if (!res.headersSent) return res.status(200).send('OK'); // fortsatt 200 til Vipps
  }
});

// ----------------------------
// Start server
// ----------------------------
app.listen(PORT, () => {
  console.log(`✅ Server kjører på http://localhost:${PORT}`);
});

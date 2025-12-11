// tripletexClient.js
const fetch = require('node-fetch');

const TRIPLETEX_BASE = 'https://tripletex.no/v2';

const CONSUMER_TOKEN = process.env.TRIPLETEX_CONSUMER_TOKEN;
const EMPLOYEE_TOKEN = process.env.TRIPLETEX_EMPLOYEE_TOKEN;
const APP_NAME = process.env.TRIPLETEX_APP_NAME || 'LalmTreningssenter';

if (!CONSUMER_TOKEN || !EMPLOYEE_TOKEN) {
  console.warn('[TRIPLETEX] Mangler CONSUMER/EMPLOYEE token i env!');
}

// Enkel cache i minne
let cachedSessionToken = null;
let cachedSessionExpires = null; // 'YYYY-MM-DD'

// -----------------------------
// 1) Lag sessionToken
//    PUT /token/session/:create
// -----------------------------
async function createSessionToken() {
  // Sett utløpsdato f.eks. 3 måneder fram i tid (må være fram i tid)
  const d = new Date();
  d.setMonth(d.getMonth() + 3);
  const expirationDate = d.toISOString().slice(0, 10); // YYYY-MM-DD

  const url =
    `${TRIPLETEX_BASE}/token/session/:create` +
    `?consumerToken=${encodeURIComponent(CONSUMER_TOKEN)}` +
    `&employeeToken=${encodeURIComponent(EMPLOYEE_TOKEN)}` +
    `&expirationDate=${encodeURIComponent(expirationDate)}` +
    `&appName=${encodeURIComponent(APP_NAME)}`;

  console.log(
    '[TRIPLETEX] Oppretter session token med expirationDate=',
    expirationDate
  );

  const res = await fetch(url, { method: 'PUT' });
  const text = await res.text();

  let json;
  try {
    json = JSON.parse(text);
  } catch (e) {
    console.error('[TRIPLETEX] Klarte ikke å parse session-respons:', text);
    throw new Error('Tripletex sessionToken: ugyldig JSON');
  }

  if (!res.ok) {
    console.error('[TRIPLETEX] Feil ved sessionToken:', res.status, json);
    throw new Error(`Tripletex sessionToken error: ${res.status}`);
  }

  // Typisk struktur: { value: { token, expirationDate, employeeId, companyId } }
  const value = json.value || json;
  if (!value || !value.token) {
    console.error('[TRIPLETEX] Session-respons mangler token:', json);
    throw new Error('Tripletex sessionToken mangler token');
  }

  cachedSessionToken = value.token;
  cachedSessionExpires = value.expirationDate || expirationDate;

  return cachedSessionToken;
}

// -----------------------------
// 2) Hent gyldig sessionToken
// -----------------------------
function isSessionValid() {
  if (!cachedSessionToken || !cachedSessionExpires) return false;
  const today = new Date().toISOString().slice(0, 10);
  // Token utløper ved midnatt på expirationDate → vi er forsiktige og fornyer
  return today <= cachedSessionExpires;
}

async function getSessionToken() {
  if (isSessionValid()) return cachedSessionToken;
  return await createSessionToken();
}

// -----------------------------
// 3) Generell request-helper
// -----------------------------
async function tripletexRequest(path, options = {}) {
  const token = await getSessionToken();

  // 0 = "mitt selskap" jf. Tripletex-dokumentasjon
  const auth = Buffer.from(`0:${token}`).toString('base64');
  const url = `${TRIPLETEX_BASE}${path}`;

  const res = await fetch(url, {
    method: options.method || 'GET',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch (e) {
    console.error('[TRIPLETEX] Klarte ikke å parse JSON for', path, '=>', text);
    throw new Error(`Tripletex JSON-feil på ${path}`);
  }

  if (!res.ok) {
    console.error('[TRIPLETEX] HTTP-feil', res.status, 'på', path, json);
    throw new Error(`Tripletex error ${res.status} på ${path}`);
  }

  return json;
}

// Hjelper for å hente første value fra svar {value: [.]} eller {values: [.]}
function firstValueFromList(json) {
  if (!json) return undefined;
  if (Array.isArray(json.value) && json.value.length > 0) return json.value[0];
  if (Array.isArray(json.values) && json.values.length > 0) return json.values[0];
  return undefined;
}

// ------------------------------------
// 4) Finn / opprett kunde i Tripletex
// ------------------------------------
async function findOrCreateCustomer(member) {
  const email = member.email && member.email.trim();
  const phone = member.phone && member.phone.trim();
  const name = member.name && member.name.trim();

  if (!name) {
    throw new Error('findOrCreateCustomer: member.name mangler');
  }

  // 4.1 Finn kunde på e-post hvis mulig
  if (email) {
    try {
      const query = `/customer?email=${encodeURIComponent(email)}&pageSize=1`;
      const existing = await tripletexRequest(query, { method: 'GET' });
      const found = firstValueFromList(existing);
      if (found) {
        console.log(
          '[TRIPLETEX] Fant eksisterende kunde via e-post:',
          email,
          'id=',
          found.id
        );
        return found;
      }
    } catch (e) {
      console.warn(
        '[TRIPLETEX] Klarte ikke å søke kunde på e-post:',
        e.message
      );
    }
  }

  // 4.2 Hvis ikke, opprett ny kunde
  const body = {
    name,
    email: email || undefined,
    phoneNumber: phone || undefined,
    isPrivateIndividual: true,
    // Hvordan eFaktura/Avtalegiro sendes styres primært i Tripletex-oppsettet.
  };

  const created = await tripletexRequest('/customer', {
    method: 'POST',
    body,
  });

  // Respons kan være { value: { ... } } eller direkte objekt
  const customer = created.value || created;

  console.log(
    '[TRIPLETEX] Opprettet ny kunde id=',
    customer.id,
    'navn=',
    customer.name
  );
  return customer;
}

// --------------------------------------------------
// 5) Opprett abonnementsordre for medlemskap
// --------------------------------------------------
async function createMembershipOrder(customerId, plan) {
  if (!customerId) throw new Error('createMembershipOrder: customerId mangler');
  if (!plan || !plan.name || typeof plan.amount !== 'number') {
    throw new Error('createMembershipOrder: plan mangler name/amount');
  }

  const today = new Date().toISOString().slice(0, 10);

  const order = {
    customer: { id: customerId },
    orderDate: today,
    deliveryDate: today,
    isPrioritizeAmountsIncludingVat: true,

    // Abonnement-felter – kopiert fra ordren du laget i Tripletex
    isSubscription: true,
    subscriptionDuration: 1,
    subscriptionDurationType: 'MONTHS',
    subscriptionPeriodsOnInvoice: 1,
    subscriptionPeriodsOnInvoiceType: 'MONTHS',
    subscriptionInvoicingTimeInAdvanceOrArrears: 'ADVANCE',
    subscriptionInvoicingTime: 0,
    subscriptionInvoicingTimeType: 'MONTHS',
    // Vi lar auto-fakturering være av (samme som manuelt skjermbilde).
    // Hvis du senere aktiverer auto-fakturering i Tripletex, kan vi sette denne til true.
    isSubscriptionAutoInvoicing: false,

    orderLines: [
      {
        description: `Medlemskap ${plan.name}`,
        count: 1,
        unitPriceIncludingVatCurrency: plan.amount,
        ...(plan.tripletexProductId
          ? { product: { id: plan.tripletexProductId } }
          : {}),
      },
    ],
  };

  const json = await tripletexRequest('/order', {
    method: 'POST',
    body: order,
  });

  const createdOrder = json.value || json;
  console.log('[TRIPLETEX] Opprettet ordre id=', createdOrder.id);
  return createdOrder;
}

// --------------------------------------------------
// 6) Hovedfunksjon: kall denne etter Vipps-betaling
// --------------------------------------------------
async function syncMembershipToTripletex({ member, plan }) {
  const customer = await findOrCreateCustomer(member);
  const order = await createMembershipOrder(customer.id, plan);
  return { customer, order };
}

module.exports = {
  syncMembershipToTripletex,
  findOrCreateCustomer,
  createMembershipOrder,
};

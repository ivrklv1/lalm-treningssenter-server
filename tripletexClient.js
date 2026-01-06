const fetch = require('node-fetch');

const TRIPLETEX_BASE = process.env.TRIPLETEX_BASE || 'https://tripletex.no/v2';

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
// 0) Små dato-hjelpere
// -----------------------------
function toISODate(d) {
  return d.toISOString().slice(0, 10); // YYYY-MM-DD
}

function firstDayOfNextMonthISO(fromDate = new Date()) {
  const year = fromDate.getFullYear();
  const month = fromDate.getMonth(); // 0-11
  const nextMonth = (month + 1) % 12;
  const nextYear = year + (month === 11 ? 1 : 0);
  const d = new Date(nextYear, nextMonth, 1);
  return toISODate(d);
}

function addMonthsISO(isoDate, months) {
  // isoDate: 'YYYY-MM-DD'
  const [y, m, d] = isoDate.split('-').map((n) => parseInt(n, 10));
  const dt = new Date(y, (m - 1) + months, d);
  return toISODate(dt);
}


// -----------------------------
// Abonnement-regler
// -----------------------------
function isSubscriptionPlan(plan) {
  // Drop-in / korttid (shortTermDays) skal ikke være abonnement.
  // TEST-planen ønskes som abonnement (for å få checkbox + start/slutt i UI).
  const planType = String(plan?.type || '').toLowerCase();
  const planName = String(plan?.name || '').toLowerCase();

  const isShortOrDropIn =
    !!plan?.shortTermDays ||
    ['dropin', 'drop-in', 'korttid', 'short', 'shortterm'].includes(planType) ||
    planName.includes('drop') ||
    planName.includes('drop-in') ||
    planName.includes('korttid');

  return !isShortOrDropIn;
}

// -----------------------------
// 1) Lag sessionToken
//    PUT /token/session/:create
// -----------------------------
async function createSessionToken() {
  // Sett utløpsdato f.eks. 3 måneder fram i tid (må være fram i tid)
  const d = new Date();
  d.setMonth(d.getMonth() + 3);
  const expirationDate = toISODate(d); // YYYY-MM-DD

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
  const today = toISODate(new Date());
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
    // Ta med Tripletex sin valideringsfeil i feilmeldingen for logging
    const msg =
      json?.message ||
      json?.developerMessage ||
      `Tripletex error ${res.status} på ${path}`;
    throw new Error(msg);
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

// --------------------------------------------------
// Abonnements-hjelpere
// --------------------------------------------------

// Godkjenn ordre for abonnementsfakturering
async function approveSubscriptionInvoice(orderId, invoiceDate) {
  if (!orderId) throw new Error('approveSubscriptionInvoice: orderId mangler');
  if (!invoiceDate)
    throw new Error('approveSubscriptionInvoice: invoiceDate mangler');

  return await tripletexRequest(
    `/order/${orderId}/:approveSubscriptionInvoice?invoiceDate=${encodeURIComponent(
      invoiceDate
    )}`,
    { method: 'PUT' }
  );
}

// Stopp abonnement-fakturering (unapprove)
async function unapproveSubscriptionInvoice(orderId) {
  if (!orderId) throw new Error('unapproveSubscriptionInvoice: orderId mangler');
  return await tripletexRequest(
    `/order/${orderId}/:unApproveSubscriptionInvoice`,
    { method: 'PUT' }
  );
}

// Enkel wrapper vi kan bruke fra server.js
async function stopTripletexSubscriptionForOrder(orderId) {
  try {
    await unapproveSubscriptionInvoice(orderId);
    console.log('[TRIPLETEX] Stoppet abonnement for ordre id=', orderId);
  } catch (e) {
    console.error(
      '[TRIPLETEX] Klarte ikke å stoppe abonnement for ordre id=',
      orderId,
      e.message
    );
    throw e;
  }
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

    // VIKTIG: tving utsendelse til e-post, ellers kan Tripletex forsøke eFaktura og feile
    invoiceSendMethod: 'EMAIL',
  };

  const created = await tripletexRequest('/customer', {
    method: 'POST',
    body,
  });

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
async function createMembershipOrder(customerId, plan, invoiceDate) {
  if (!customerId) throw new Error('createMembershipOrder: customerId mangler');
  if (!plan || !plan.name || typeof plan.amount !== 'number') {
    throw new Error('createMembershipOrder: plan mangler name/amount');
  }

  const today = toISODate(new Date());

  // plan.amount er i øre → konverter til NOK
  const unitPriceNok = plan.amount / 100;

  // Hvis ikke oppgitt: første dag i neste måned
  const safeInvoiceDate = invoiceDate || firstDayOfNextMonthISO(new Date());

  // Avgjør om dette skal være abonnement i Tripletex
  const isSubscription = isSubscriptionPlan(plan);

  // Start: invoiceDate (typisk 1. i neste måned)
  const subscriptionPeriodStart = safeInvoiceDate;

  // Slutt: hvis bindingMonths > 0 → sett sluttdato, ellers lar vi den stå tom
  const bindingMonths = Number(plan.bindingMonths || 0);
  const subscriptionPeriodEnd =
    isSubscription && bindingMonths > 0
      ? addMonthsISO(subscriptionPeriodStart, bindingMonths)
      : isSubscription
      ? addMonthsISO(subscriptionPeriodStart, 120) // uten binding → sett langt fram i tid
      : null;

  const order = {
    customer: { id: customerId },
    orderDate: today,

    // Leveringsdato i UI bør normalt matche fakturaperiodens start (ikke "i dag")
    deliveryDate: subscriptionPeriodStart,

    isPrioritizeAmountsIncludingVat: true,

    // Abonnement (ordre-nivå) – beholdes for kompatibilitet, men linjenivå er det som vises i UI
    ...(isSubscription
      ? {
          isSubscription: true,
          subscriptionDuration: 1,
          subscriptionDurationType: 'MONTHS',
          subscriptionPeriodsOnInvoice: 1,
          subscriptionPeriodsOnInvoiceType: 'MONTHS',
          subscriptionInvoicingTimeInAdvanceOrArrears: 'ADVANCE',
          subscriptionInvoicingTime: 0,
          subscriptionInvoicingTimeType: 'MONTHS',
          isSubscriptionAutoInvoicing: true,
        }
      : {}),

    orderLines: [
      {
        description: `Medlemskap ${plan.name}`,
        count: 1,
        unitPriceIncludingVatCurrency: unitPriceNok,

        // Abonnement (linjenivå) – dette styrer checkbox + start/slutt i ordrelinja
        ...(isSubscription
          ? {
              isSubscription: true,
              subscriptionPeriodStart,
              ...(subscriptionPeriodEnd
                ? { subscriptionPeriodEnd }
                : {}),
            }
          : {}),

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
  console.log(
    '[TRIPLETEX] Opprettet ordre id=',
    createdOrder.id,
    'invoiceDate=',
    safeInvoiceDate
  );
  return createdOrder;
}

// 6) Hovedfunksjon: kall denne etter Vipps-betaling
async function syncMembershipToTripletex({ member, plan, invoiceDate }) {
  const customer = await findOrCreateCustomer(member);

  const safeInvoiceDate = invoiceDate || firstDayOfNextMonthISO(new Date());

  // Bruk invoiceDate både på ordre og på godkjenning
  const order = await createMembershipOrder(customer.id, plan, safeInvoiceDate);

  // Godkjenn ordre for abonnementsfakturering (kun hvis abonnement)
  if (isSubscriptionPlan(plan)) {
    await approveSubscriptionInvoice(order.id, safeInvoiceDate);
    console.log(
      '[TRIPLETEX] approveSubscriptionInvoice OK for ordre id=',
      order.id,
      'invoiceDate=',
      safeInvoiceDate
    );
  } else {
    console.log('[TRIPLETEX] Ikke abonnement – hopper over approveSubscriptionInvoice');
  }

  return { customer, order };
}

module.exports = {
  syncMembershipToTripletex,
  findOrCreateCustomer,
  createMembershipOrder,
  approveSubscriptionInvoice,
  stopTripletexSubscriptionForOrder,
};


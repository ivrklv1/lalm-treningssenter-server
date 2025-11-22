// tripletex-test.js
require("dotenv").config();
const axios = require("axios");

const BASE_URL = process.env.TRIPLETEX_BASE_URL || "https://api-test.tripletex.tech/v2";
const CONSUMER_TOKEN = process.env.TRIPLETEX_CONSUMER_TOKEN;
const EMPLOYEE_TOKEN = process.env.TRIPLETEX_EMPLOYEE_TOKEN;
console.log("BASE_URL:", BASE_URL);
console.log("Consumer token start/len:", CONSUMER_TOKEN?.slice(0, 10), CONSUMER_TOKEN?.length);
console.log("Employee token start/len:", EMPLOYEE_TOKEN?.slice(0, 10), EMPLOYEE_TOKEN?.length);


if (!CONSUMER_TOKEN || !EMPLOYEE_TOKEN) {
  console.error("Mangler CONSUMER_TOKEN eller EMPLOYEE_TOKEN i .env");
  process.exit(1);
}

// 1) Lag sessionToken
async function createSessionToken() {
  const expirationDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30) // +30 dager
    .toISOString()
    .slice(0, 10); // YYYY-MM-DD

  const url = `${BASE_URL}/token/session/:create`;

  try {
    const res = await axios.put(url, null, {
      params: {
        consumerToken: CONSUMER_TOKEN,
        employeeToken: EMPLOYEE_TOKEN,
        expirationDate: expirationDate,
      },
      headers: {
        "Content-Type": "application/json",
      },
    });

    const sessionToken = res.data.value.token;
    return sessionToken;
  } catch (err) {
    console.error("Feil fra Tripletex (session token):", err.response?.status, err.response?.data || err.message);
    throw err;
  }
}


// 2) Kall et vanlig endepunkt (her: customer)
async function getCustomers(sessionToken) {
  // Basic auth: username = "0", password = sessionToken
  const basic = Buffer.from(`0:${sessionToken}`).toString("base64");

  const res = await axios.get(`${BASE_URL}/customer`, {
    params: {
      count: 10, // hent 10 kunder
    },
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/json",
    },
  });

  return res.data;
}

// 3) Kjør alt
(async () => {
  try {
    console.log("Lager sessionToken...");
    const sessionToken = await createSessionToken();
    console.log("SessionToken:", sessionToken);

    console.log("Henter kunder...");
    const customers = await getCustomers(sessionToken);
    console.log(JSON.stringify(customers, null, 2));
  } catch (err) {
    if (err.response) {
      console.error("Feil fra Tripletex:", err.response.status, err.response.data);
    } else {
      console.error("Teknisk feil:", err.message);
    }
  }
})();

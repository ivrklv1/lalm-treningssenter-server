const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

test('Tripletex invoice reader paginates with only GET calls and required fields', async () => {
  const calls = [];
  const fakeFetch = async (url, options) => {
    calls.push({ url: String(url), method: options.method });
    if (String(url).includes('/token/session/:create')) {
      return { ok: true, text: async () => JSON.stringify({ value: { token: 'synthetic-token', expirationDate: '2099-01-01' } }) };
    }
    const parsed = new URL(url);
    const offset = Number(parsed.searchParams.get('from'));
    return { ok: true, text: async () => JSON.stringify({
      values: offset === 0 ? [{ id: 1, orders: [{ id: 411 }] }, { id: 2, orders: [{ id: 422 }] }] : [],
    }) };
  };
  const originalLoad = Module._load;
  const originalConsumer = process.env.TRIPLETEX_CONSUMER_TOKEN;
  const originalEmployee = process.env.TRIPLETEX_EMPLOYEE_TOKEN;
  process.env.TRIPLETEX_CONSUMER_TOKEN = 'synthetic-consumer';
  process.env.TRIPLETEX_EMPLOYEE_TOKEN = 'synthetic-employee';
  Module._load = function load(request, parent, isMain) {
    if (request === 'node-fetch') return fakeFetch;
    return originalLoad.call(this, request, parent, isMain);
  };
  let client;
  try {
    delete require.cache[require.resolve('../tripletexClient')];
    client = require('../tripletexClient');
  } finally {
    Module._load = originalLoad;
    if (originalConsumer === undefined) delete process.env.TRIPLETEX_CONSUMER_TOKEN;
    else process.env.TRIPLETEX_CONSUMER_TOKEN = originalConsumer;
    if (originalEmployee === undefined) delete process.env.TRIPLETEX_EMPLOYEE_TOKEN;
    else process.env.TRIPLETEX_EMPLOYEE_TOKEN = originalEmployee;
  }
  const invoices = await client.listMembershipInvoices('2024-01-01');
  assert.equal(invoices.length, 2);
  assert.deepEqual(calls.map(call => call.method), ['PUT', 'GET', 'GET']);
  const first = new URL(calls[1].url);
  assert.equal(first.searchParams.get('invoiceDateFrom'), '2024-01-01');
  assert.match(first.searchParams.get('fields'), /orders\(id\)/);
  assert.equal(new URL(calls[2].url).searchParams.get('from'), '2');
});

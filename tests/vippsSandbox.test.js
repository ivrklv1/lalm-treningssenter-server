const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const test = require('node:test');
const { validateVippsSandbox } = require('../vippsSandbox');

const root = path.resolve(__dirname, '..');
const token = 'synthetic-sandbox-token-32-characters-long';
const serverUrl = 'https://vipps-sandbox.example.invalid';

function sandboxEnv(dataDir) {
  return {
    VIPPS_SANDBOX_ONLY: '1', VIPPS_ENV: 'test', VIPPS_MSN: '411837',
    VIPPS_CLIENT_ID: 'synthetic', VIPPS_CLIENT_SECRET: 'synthetic',
    VIPPS_SUBSCRIPTION_KEY: 'synthetic', VIPPS_SANDBOX_ACCESS_TOKEN: token,
    SERVER_URL: serverUrl,
    VIPPS_CALLBACK_URL: `${serverUrl}/vipps/callback/v2/payments`,
    DATA_DIR: dataDir,
  };
}

test('sandbox refuses live Vipps, production integrations and shared storage', () => {
  const env = sandboxEnv('/tmp/lalm-vipps-sandbox-unit');
  assert.doesNotThrow(() => validateVippsSandbox(env));
  assert.throws(() => validateVippsSandbox({ ...env, VIPPS_ENV: 'production' }), /VIPPS_ENV=test/);
  assert.throws(() => validateVippsSandbox({ ...env, VIPPS_MSN: '411836' }), /VIPPS_MSN=411837/);
  assert.throws(() => validateVippsSandbox({ ...env, TELL_API_KEY: 'synthetic' }), /TELL_API_KEY/);
  assert.throws(() => validateVippsSandbox({ ...env, EUROBATE_USER: 'synthetic' }), /EUROBATE_USER/);
  assert.throws(() => validateVippsSandbox({ ...env, TRIPLETEX_EMPLOYEE_TOKEN: 'synthetic' }), /TRIPLETEX_EMPLOYEE_TOKEN/);
  assert.throws(() => validateVippsSandbox({ ...env, DATA_DIR: '/data' }), /egen lagring/);
  assert.throws(() => validateVippsSandbox({ ...env, SERVER_URL: 'https://lalm-treningssenter-server.onrender.com' }), /egen HTTPS-adresse/);
  assert.throws(() => validateVippsSandbox({ ...env, VIPPS_CALLBACK_URL: 'https://elsewhere.invalid/callback' }), /callback/);
});

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

test('sandbox exposes only protected Vipps test routes; reservation is unpaid', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-vipps-sandbox-test-'));
  const port = await freePort();
  const orders = [{ orderId: 'synthetic-reserve', status: 'RESERVED', amount: 100,
    email: 'test@example.invalid', membershipKey: 'TEST_BINDING_12M' }];
  fs.writeFileSync(path.join(dataDir, 'orders.json'), JSON.stringify(orders));
  let output = '';
  const child = spawn(process.execPath, [
    '--require', path.join(__dirname, 'blockExternal.cjs'),
    '--require', path.join(__dirname, 'mockVippsDetails.cjs'), path.join(root, 'server.js'),
  ], {
    cwd: root,
    env: {
      PATH: process.env.PATH,
      NODE_PATH: path.resolve(root, '../legal-test-server/node_modules'),
      PORT: String(port), ...sandboxEnv(dataDir),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  try {
    for (let i = 0; i < 100 && !output.includes(`Server kjører på http://localhost:${port}`); i += 1) {
      if (child.exitCode !== null) throw new Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.match(output, /Server kjører/);
    const base = `http://127.0.0.1:${port}`;
    for (const [method, route] of [
      ['GET', '/'], ['GET', '/admin/members'], ['POST', '/door/open'],
      ['POST', '/auth/send-code'], ['POST', '/internal/backup/run'],
    ]) {
      const response = await fetch(base + route, { method });
      assert.equal(response.status, 404, `${method} ${route}`);
    }
    const statusUrl = `${base}/vipps/order-status/synthetic-reserve`;
    assert.equal((await fetch(statusUrl)).status, 403);
    const authUrl = `${base}/vipps/sandbox-auth-check`;
    assert.equal((await fetch(authUrl)).status, 403);
    const authResponse = await fetch(authUrl, { headers: { 'x-sandbox-token': token } });
    assert.equal(authResponse.status, 200);
    assert.deepEqual(await authResponse.json(), { ok: true, vippsEnv: 'test', merchantSerialNumber: '411837' });
    const status = await fetch(statusUrl, { headers: { 'x-sandbox-token': token } });
    assert.equal(status.status, 200);
    assert.equal((await status.json()).isPaid, false);
    const checkoutUrl = `${base}/vipps/checkout`;
    assert.equal((await fetch(checkoutUrl, { method: 'POST' })).status, 403);
    const invalidPlan = await fetch(checkoutUrl, {
      method: 'POST', headers: { 'x-sandbox-token': token, 'content-type': 'application/json' },
      body: JSON.stringify({ membershipKey: 'STANDARD_BINDING', name: 'Test Person',
        email: 'test@example.invalid', phone: '12345678' }),
    });
    assert.equal(invalidPlan.status, 400);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dataDir, 'orders.json'))), orders);
    assert.equal(output.includes('TEST BLOCKED AN OUTBOUND CONNECTION'), false, output);
  } finally {
    child.kill('SIGTERM');
    await new Promise(resolve => child.once('exit', resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

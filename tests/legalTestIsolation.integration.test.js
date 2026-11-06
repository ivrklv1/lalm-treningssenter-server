const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');

test('legal test service allows synthetic acknowledgement while blocking operational actions', async () => {
  const dataDir = '/tmp/lalm-legal-test-data';
  if (fs.existsSync(dataDir)) throw new Error('Test data directory already exists');
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  const root = path.resolve(__dirname, '..');
  let output = '';
  const child = spawn(process.execPath,
    ['--require', path.join(__dirname, 'blockExternal.cjs'), path.join(root, 'server.js')], {
      cwd: root,
      env: { PATH: process.env.PATH, NODE_PATH: path.resolve(root, '../legal-test-server/node_modules'),
        DATA_DIR: dataDir, PORT: String(port), LEGAL_TEST_ONLY: 'true',
        APPLE_TEST_PHONE: '+4710000000', APPLE_TEST_CODE: '123456',
        ADMIN_USER: 'test-admin', ADMIN_PASS: 'synthetic-password',
        TRIPLETEX_RETRY_INTERVAL_MINUTES: '0' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  const base = `http://127.0.0.1:${port}`;
  const json = (route, method = 'GET', body, authorization) => fetch(base + route, {
    method,
    headers: { 'Content-Type': 'application/json', ...(authorization ? { Authorization: authorization } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const admin = `Basic ${Buffer.from('test-admin:synthetic-password').toString('base64')}`;
  try {
    for (let attempt = 0; attempt < 80 && !output.includes(`Server kjører på http://localhost:${port}`); attempt++) {
      if (child.exitCode !== null) throw new Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.match(output, /Server kjører på/);
    assert.equal((await (await json('/')).json()).legalTestOnly, true);
    for (const route of ['/door/open', '/vipps/checkout', '/admin/sms/send']) {
      assert.equal((await json(route, 'POST', {})).status, 403);
    }
    assert.equal((await json('/auth/send-code', 'POST', { phone: '+4799999999' })).status, 403);
    assert.equal((await json('/auth/send-code', 'POST', { phone: '+4710000000' })).status, 200);
    const login = await (await json('/auth/verify-code', 'POST', { phone: '+4710000000', code: '123456' })).json();
    assert.match(login.sessionToken, /^legal1\./);
    assert.equal((await json('/admin/legal/terms/draft', 'PUT', {
      expectedRevision: 0, version: 'test-1', title: 'Testvilkår', content: 'Oppdiktet tekst',
      requiresAcknowledgement: true,
    }, admin)).status, 200);
    assert.equal((await json('/admin/legal/terms/publish', 'POST', { expectedRevision: 1 }, admin)).status, 200);
    assert.equal((await (await json('/api/legal/acknowledgements/pending', 'GET', null,
      `Bearer ${login.sessionToken}`)).json()).pending.length, 1);
  } finally {
    child.kill('SIGTERM');
    await new Promise(resolve => child.once('exit', resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

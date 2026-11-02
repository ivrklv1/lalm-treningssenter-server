const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { createLegalMemberSession } = require('../legalMemberSession');

test('admin required version gates only the matching member until acknowledged', async () => {
  const root = path.resolve(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-legal-flow-'));
  fs.writeFileSync(path.join(dataDir, 'members.json'), JSON.stringify([
    { id: 'member-a', name: 'Test A', active: true },
    { id: 'member-b', name: 'Test B', active: true },
  ]));
  const socket = net.createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  let output = '';
  const child = spawn(process.execPath,
    ['--require', path.join(__dirname, 'blockExternal.cjs'), path.join(root, 'server.js')], {
      cwd: root,
      env: { PATH: process.env.PATH, NODE_PATH: path.resolve(root, '../legal-test-server/node_modules'),
        DATA_DIR: dataDir, PORT: String(port), ADMIN_USER: 'editor', ADMIN_PASS: 'synthetic-password',
        LEGAL_ACK_APP_READY: 'true', TRIPLETEX_RETRY_INTERVAL_MINUTES: '0' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  child.stdout.on('data', data => { output += data; });
  child.stderr.on('data', data => { output += data; });
  const base = `http://127.0.0.1:${port}`;
  const admin = `Basic ${Buffer.from('editor:synthetic-password').toString('base64')}`;
  const request = (route, method, body, auth) => fetch(base + route, {
    method, headers: { Authorization: auth, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  try {
    for (let i = 0; i < 80 && !output.includes(`Server kjører på http://localhost:${port}`); i++) {
      if (child.exitCode !== null) throw new Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.match(output, /Server kjører på/);
    const tokenA = `Bearer ${createLegalMemberSession({ dataDir }).issue('member-a')}`;
    const tokenB = `Bearer ${createLegalMemberSession({ dataDir }).issue('member-b')}`;
    const appleLogin = await fetch(base + '/auth/verify-code', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: '+4799999999', code: '111111' }),
    });
    assert.equal(appleLogin.status, 200);
    const appleToken = `Bearer ${(await appleLogin.json()).sessionToken}`;
    assert.equal((await request('/api/legal/acknowledgements/pending', 'GET', null, appleToken)).status, 200);
    assert.equal((await request('/api/legal/acknowledgements/pending', 'GET', null, 'Bearer member:fake')).status, 401);
    assert.deepEqual((await (await request('/api/legal/acknowledgements/pending', 'GET', null, tokenA)).json()).pending, []);
    assert.equal((await request('/admin/legal/terms/draft', 'PUT', {
      expectedRevision: 0, version: 't1', title: 'Vilkår', content: 'Testtekst', requiresAcknowledgement: true,
    }, admin)).status, 200);
    assert.equal((await request('/admin/legal/terms/publish', 'POST', { expectedRevision: 1 }, admin)).status, 200);
    assert.equal((await (await request('/api/legal/acknowledgements/pending', 'GET', null, tokenA)).json()).pending[0].version, 't1');
    assert.equal((await request('/api/legal/acknowledgements', 'POST', { documents: [{ kind: 'terms', version: 't0' }] }, tokenA)).status, 409);
    assert.equal((await request('/api/legal/acknowledgements', 'POST', { documents: [{ kind: 'terms', version: 't1' }] }, tokenA)).status, 200);
    assert.deepEqual((await (await request('/api/legal/acknowledgements/pending', 'GET', null, tokenA)).json()).pending, []);
    assert.equal((await (await request('/api/legal/acknowledgements/pending', 'GET', null, tokenB)).json()).pending.length, 1);
    assert.equal((await request('/api/legal/acknowledgements', 'POST', { documents: [{ kind: 'terms', version: 't1' }] }, 'Bearer member:fake')).status, 401);
  } finally {
    child.kill('SIGTERM');
    await new Promise(resolve => child.once('exit', resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

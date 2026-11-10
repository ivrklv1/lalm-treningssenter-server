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
  const membersFile = path.join(dataDir, 'members.json');
  const members = [
    { id: 'member-a', name: 'Test A', active: true, phone: '+4712345678', plan: 'standard',
      membershipStartDate: '2026-01-01', bindingEndDate: '2027-01-01', bindingMonthsAtStart: 12 },
    { id: 'member-b', name: 'Test B', active: true, phone: '+4712345679' },
  ];
  fs.writeFileSync(membersFile, JSON.stringify(members));
  fs.writeFileSync(path.join(dataDir, 'plans.json'), JSON.stringify([
    { id: 'standard-plan', key: 'Standard', name: 'Standard med binding', price: 449 },
  ]));
  const socket = net.createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  const mock = path.join(dataDir, 'sms-mock.cjs');
  fs.writeFileSync(mock, `
    const axios = require('axios');
    const fs = require('node:fs');
    axios.post = async (url, payload) => {
      if (url !== 'https://api.eurobate.com/json_api.php') throw Error('Unexpected external call');
      fs.writeFileSync(process.env.DATA_DIR + '/code', payload.messages[0].message.match(/#(\\d{6})/)[1]);
      return { data: { status: 'OK' } };
    };
  `);
  let output = '';
  const child = spawn(process.execPath,
    ['--require', path.join(__dirname, 'blockExternal.cjs'), '--require', mock, path.join(root, 'server.js')], {
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
    assert.equal((await request('/auth/send-code', 'POST', { phone: members[0].phone })).status, 200);
    const login = await request('/auth/verify-code', 'POST', {
      phone: members[0].phone, code: fs.readFileSync(path.join(dataDir, 'code'), 'utf8'),
    });
    assert.equal(login.status, 200);
    const loginResult = await login.json();
    assert.equal(createLegalMemberSession({ dataDir }).verify(loginResult.sessionToken), 'member-a');
    assert.equal(loginResult.member.planName, 'Standard med binding');
    const tokenA = `Bearer ${loginResult.sessionToken}`;
    const tokenB = `Bearer ${createLegalMemberSession({ dataDir }).issue('member-b')}`;
    const overview = '/api/membership/me';
    assert.equal((await fetch(base + overview)).status, 401);
    assert.equal((await request(overview, 'GET', null, 'Bearer member:fake')).status, 401);
    const response = await request(overview + '?memberId=member-b', 'GET', null, tokenA);
    assert.equal(response.headers.get('cache-control'), 'private, no-store');
    assert.deepEqual((await response.json()).membership, {
      planName: 'Standard med binding', active: true, membershipStartDate: '2026-01-01',
      bindingEndDate: '2027-01-01', bindingMonthsAtStart: 12, membershipSample: false,
      canBuyDropIn: false, canBuyMembership: false,
    });
    assert.equal((await (await request(overview, 'GET', null, tokenB)).json()).membership.planName, null);
    members[0].bindingEndDate = '2027-02-01';
    fs.writeFileSync(membersFile, JSON.stringify(members));
    assert.equal((await (await request(overview, 'GET', null, tokenA)).json()).membership.bindingEndDate, '2027-02-01');
    const appleLogin = await fetch(base + '/auth/verify-code', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: '+4799999999', code: '111111' }),
    });
    assert.equal(appleLogin.status, 200);
    const appleToken = `Bearer ${(await appleLogin.json()).sessionToken}`;
    assert.equal((await request('/api/legal/acknowledgements/pending', 'GET', null, appleToken)).status, 200);
    assert.equal((await request('/api/legal/acknowledgements/pending', 'GET', null, 'Bearer member:fake')).status, 401);
    assert.deepEqual((await (await fetch(base + '/api/legal/acknowledgements/required')).json()).required, []);
    assert.deepEqual((await (await request('/api/legal/acknowledgements/pending', 'GET', null, tokenA)).json()).pending, []);
    assert.equal((await request('/admin/legal/privacy/draft', 'PUT', {
      expectedRevision: 0, version: 'p1', title: 'Personvern', content: 'Testtekst',
    }, admin)).status, 200);
    assert.equal((await request('/admin/legal/privacy/publish', 'POST', { expectedRevision: 1 }, admin)).status, 200);
    assert.equal((await (await fetch(base + '/api/legal/privacy')).json()).version, 'p1');
    assert.deepEqual((await (await fetch(base + '/api/legal/acknowledgements/required')).json()).required, []);
    assert.equal((await request('/admin/legal/terms/draft', 'PUT', {
      expectedRevision: 0, version: 't1', title: 'Vilkår', content: 'Testtekst', requiresAcknowledgement: true,
    }, admin)).status, 200);
    assert.deepEqual((await (await fetch(base + '/api/legal/acknowledgements/required')).json()).required, []);
    assert.equal((await request('/admin/legal/terms/publish', 'POST', { expectedRevision: 1 }, admin)).status, 200);
    assert.deepEqual((await (await fetch(base + '/api/legal/acknowledgements/required')).json()).required,
      [{ kind: 'terms', version: 't1' }]);
    assert.equal((await (await request('/api/legal/acknowledgements/pending', 'GET', null, tokenA)).json()).pending[0].version, 't1');
    assert.equal((await request('/api/legal/acknowledgements', 'POST', { documents: [{ kind: 'terms', version: 't0' }] }, tokenA)).status, 409);
    assert.equal((await request('/api/legal/acknowledgements', 'POST', { documents: [{ kind: 'terms', version: 't1' }] }, tokenA)).status, 200);
    assert.deepEqual((await (await request('/api/legal/acknowledgements/pending', 'GET', null, tokenA)).json()).pending, []);
    assert.equal((await (await request('/api/legal/acknowledgements/pending', 'GET', null, tokenB)).json()).pending.length, 1);
    assert.equal((await request('/api/legal/acknowledgements', 'POST', { documents: [{ kind: 'terms', version: 't1' }] }, 'Bearer member:fake')).status, 401);
    for (const invalid of ['Bearer member:+4712345678', tokenA + 'x',
      `Bearer ${createLegalMemberSession({ dataDir, now: () => 0 }).issue('member-a')}`]) {
      assert.equal((await request(overview, 'GET', null, invalid)).status, 401);
      assert.equal((await request('/api/legal/acknowledgements/pending', 'GET', null, invalid)).status, 401);
    }
    const receiptFile = path.join(dataDir, 'legal-acknowledgements.json');
    const receipt = fs.readFileSync(receiptFile, 'utf8');
    assert.equal((await request('/api/legal/acknowledgements', 'POST', {
      documents: [{ kind: 'terms', version: 't1' }], memberId: 'member-b',
    }, tokenA)).status, 200);
    assert.equal(fs.readFileSync(receiptFile, 'utf8'), receipt);
    assert.equal((await (await request('/api/legal/acknowledgements/pending', 'GET', null, tokenB)).json()).pending.length, 1);
    for (const state of [{ active: false }, { active: true, validUntil: '2000-01-01' }]) {
      Object.assign(members[0], state);
      fs.writeFileSync(membersFile, JSON.stringify(members));
      assert.equal((await (await request(overview, 'GET', null, tokenA)).json()).membership.active, false);
      assert.equal((await request('/api/legal/acknowledgements/pending', 'GET', null, tokenA)).status, 401);
    }

  } finally {
    child.kill('SIGTERM');
    await new Promise(resolve => child.once('exit', resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

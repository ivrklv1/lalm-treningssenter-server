const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

test('a verified member can refresh only their own membership without billing guesses', async () => {
  const root = path.resolve(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-membership-overview-'));
  const membersFile = path.join(dataDir, 'members.json');
  const members = [
    { id: 'a', name: 'Test A', active: true, phone: '+4712345678', plan: 'STANDARD',
      membershipStartDate: '2026-01-01', bindingEndDate: '2027-01-01', bindingMonthsAtStart: 12 },
    { id: 'b', name: 'Test B', active: true, phone: '+4712345679', plan: 'other' },
  ];
  fs.writeFileSync(membersFile, JSON.stringify(members));
  fs.writeFileSync(path.join(dataDir, 'plans.json'), JSON.stringify([{ id: 'standard', name: 'Standard', price: 449 }]));
  const mock = path.join(dataDir, 'sms-mock.cjs');
  fs.writeFileSync(mock, `
    const axios = require('axios');
    const fs = require('node:fs');
    axios.post = async (url, payload) => {
      if (url !== 'https://api.eurobate.com/json_api.php') throw Error('Unexpected network call');
      fs.writeFileSync(process.env.DATA_DIR + '/code', payload.messages[0].message.match(/#(\\d{6})/)[1]);
      return { data: { status: 'OK' } };
    };
  `);
  const listener = net.createServer();
  await new Promise((resolve, reject) => listener.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  const child = spawn(process.execPath, ['--require', path.join(__dirname, 'blockExternal.cjs'),
    '--require', mock, path.join(root, 'server.js')], {
    cwd: root,
    env: { PATH: process.env.PATH, NODE_PATH: process.env.NODE_PATH || path.join(root, 'node_modules'),
      DATA_DIR: dataDir, PORT: String(port), TRIPLETEX_RETRY_INTERVAL_MINUTES: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  const exited = new Promise(resolve => child.once('exit', resolve));
  const base = 'http://127.0.0.1:' + port;
  const post = (route, data) => fetch(base + route, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
  });
  const overview = (token, query = '') => fetch(base + '/api/membership/me' + query,
    token ? { headers: { Authorization: 'Bearer ' + token } } : {});
  const login = async phone => {
    assert.equal((await post('/auth/send-code', { phone })).status, 200);
    const code = fs.readFileSync(path.join(dataDir, 'code'), 'utf8');
    const response = await post('/auth/verify-code', { phone, code });
    assert.equal(response.status, 200);
    return response.json();
  };
  try {
    for (let i = 0; i < 80 && !output.includes('Server kjører på'); i++) {
      if (child.exitCode !== null) throw Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.match(output, /Server kjører på/);
    assert.equal((await overview()).status, 401);
    assert.equal((await overview('member:+4712345678')).status, 401);
    const result = await login(members[0].phone);
    assert.match(result.sessionToken, /^legal1\./);
    assert.equal(result.member.planName, 'Standard');
    const response = await overview(result.sessionToken, '?memberId=b');
    assert.equal(response.headers.get('cache-control'), 'private, no-store');
    assert.deepEqual((await response.json()).membership, {
      planName: 'Standard', active: true, membershipStartDate: '2026-01-01',
      bindingEndDate: '2027-01-01', bindingMonthsAtStart: 12, membershipSample: false,
    });
    members[0].active = false;
    members[0].bindingEndDate = '2027-02-01';
    members.push({ ...members[1], id: 'c' });
    fs.writeFileSync(membersFile, JSON.stringify(members));
    const refreshed = (await (await overview(result.sessionToken)).json()).membership;
    assert.equal(refreshed.active, false);
    assert.equal(refreshed.bindingEndDate, '2027-02-01');
    const ambiguous = await login(members[1].phone);
    assert.equal(ambiguous.isMember, true);
    assert.equal(ambiguous.sessionToken, undefined);
  } finally {
    child.kill();
    await exited;
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

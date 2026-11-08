const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

test('membership refresh and the door preview use the signed member identity', async () => {
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
    const { DateTimeFormat } = Intl;
    Intl.DateTimeFormat = function (locale, options) {
      const formatter = new DateTimeFormat(locale, options);
      if (options?.timeZone === 'Europe/Oslo' && options.hourCycle === 'h23') {
        formatter.formatToParts = () => [{
          type: 'hour', value: fs.existsSync(process.env.DATA_DIR + '/closed') ? '23' : '12'
        }];
      }
      return formatter;
    };
    axios.post = async (url, payload) => {
      if (url === 'https://tell.test/gc/open') {
        if (payload.data !== 1) throw Error('Unexpected gate');
        fs.appendFileSync(process.env.DATA_DIR + '/door-calls', 'open\\n');
        return { data: { ok: true } };
      }
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
      DATA_DIR: dataDir, PORT: String(port), TRIPLETEX_RETRY_INTERVAL_MINUTES: '0',
      MEMBER_DOOR_PREVIEW_ID: 'a', TELL_BASE_URL: 'https://tell.test',
      TELL_API_KEY: 'fake', TELL_HWID: 'fake', TELL_APP_ID: 'fake' },
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
  const doorPreview = (token, body = { doorId: 'styrkerom' }) => fetch(base + '/api/member-door-preview/open', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token && { Authorization: 'Bearer ' + token }) },
    body: JSON.stringify(body),
  });
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
    assert.equal((await doorPreview(null, { doorId: 'styrkerom', phone: members[0].phone })).status, 401);
    assert.equal((await doorPreview(result.sessionToken + 'x')).status, 401);
    assert.equal((await doorPreview((await login(members[1].phone)).sessionToken)).status, 403);
    assert.equal((await doorPreview(result.sessionToken, {})).status, 400);
    assert.equal((await doorPreview(result.sessionToken, { doorId: '__proto__' })).status, 400);
    fs.writeFileSync(path.join(dataDir, 'closed'), '');
    const closed = await doorPreview(result.sessionToken);
    assert.equal(closed.status, 403);
    assert.equal((await closed.json()).error, 'CLOSED');
    fs.unlinkSync(path.join(dataDir, 'closed'));
    const opened = await doorPreview(result.sessionToken, { doorId: 'styrkerom', phone: members[1].phone });
    assert.deepEqual(await opened.json(), { ok: true, source: 'MEMBER' });
    assert.match(fs.readFileSync(path.join(dataDir, 'access.log'), 'utf8'), /name=Test A .*action=OPEN_MEMBER/);

    members[0].validUntil = '2000-01-01';
    fs.writeFileSync(membersFile, JSON.stringify(members));
    assert.equal((await doorPreview(result.sessionToken)).status, 403);
    members[0].active = false;
    members[0].bindingEndDate = '2027-02-01';
    members.push({ ...members[1], id: 'c' });
    fs.writeFileSync(membersFile, JSON.stringify(members));
    const refreshed = (await (await overview(result.sessionToken)).json()).membership;
    assert.equal(refreshed.active, false);
    assert.equal(refreshed.bindingEndDate, '2027-02-01');
    assert.equal((await doorPreview(result.sessionToken)).status, 403);
    const ambiguous = await login(members[1].phone);
    assert.equal(ambiguous.isMember, true);
    assert.equal(ambiguous.sessionToken, undefined);
    assert.equal(fs.readFileSync(path.join(dataDir, 'door-calls'), 'utf8'), 'open\n');
  } finally {
    child.kill();
    await exited;
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

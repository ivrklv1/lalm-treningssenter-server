const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

test('admin keeps shared-email members separate and previews NIF changes before saving', async () => {
  const root = path.resolve(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-admin-safety-'));
  const members = [
    { id: 'member-a', name: 'Test A', email: 'shared@example.invalid', phone: '+4711111111', plan: 'standard', active: true },
    { id: 'member-b', name: 'Test B', email: 'shared@example.invalid', phone: '+4722222222', plan: 'standard', active: true },
    { id: 'member-c', name: 'Test C', email: 'c@example.invalid', phone: '+4733333333', plan: 'medlem_m_binding', active: true, clubMember: true, clubMemberSource: 'nif' },
    { id: 'member-d', name: 'Test D', email: 'd@example.invalid', phone: '+4744444444', plan: 'medlem_m_binding', active: true, clubMember: false },
    { id: 'member-short', name: 'Korttidstest', email: 'short@example.invalid', phone: '+4755555555', plan: 'korttid_7dager', active: true },
  ];
  fs.writeFileSync(path.join(dataDir, 'members.json'), JSON.stringify(members));
  fs.writeFileSync(path.join(dataDir, 'orders.json'), '[]');
  fs.writeFileSync(path.join(dataDir, 'plans.json'), JSON.stringify([{ id: 'standard' }, { id: 'medlem_m_binding' }, { id: 'Korttid_7dager', shortTermDays: 7 }]));
  fs.writeFileSync(path.join(dataDir, 'access.log'), [
    '[2026-10-30T10:00:00Z] DROPIN_CREATE phone=12345678 token=synthetic-token',
    '[2026-10-30T10:01:00Z] VIPPS_CHECKOUT_REQUEST body={"name":"Test A","membershipKey":"standard"}',
    '[2026-10-30T10:02:00Z] VIPPS_CHECKOUT_BLOCKED_EXISTING_MEMBER email=test@example.invalid memberId=member-a',
    '30.10.2026, 12:00:00 name=Test A door=styrkerom gate=1 action=OPEN_MEMBER',
    '30.10.2026, 12:01:00 email=test@example.invalid door=styrkerom action=DENY reason=rate_limit',
  ].join('\n'));
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  let output = '';
  const child = spawn(process.execPath, ['--require', path.join(__dirname, 'blockExternal.cjs'), path.join(root, 'server.js')], {
    cwd: root,
    env: {
      PATH: process.env.PATH, NODE_PATH: path.resolve(root, '../legal-test-server/node_modules'),
      DATA_DIR: dataDir, PORT: String(port), ADMIN_USER: 'test-admin', ADMIN_PASS: 'synthetic-password',
      TRIPLETEX_RETRY_INTERVAL_MINUTES: '0',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  const base = `http://127.0.0.1:${port}`;
  const headers = {
    Authorization: `Basic ${Buffer.from('test-admin:synthetic-password').toString('base64')}`,
    'Content-Type': 'application/json',
  };
  const readMembers = () => JSON.parse(fs.readFileSync(path.join(dataDir, 'members.json')));
  const post = (route, body) => fetch(base + route, { method: 'POST', headers, body: JSON.stringify(body) });

  try {
    for (let attempt = 0; attempt < 80 && !output.includes(`Server kjører på http://localhost:${port}`); attempt++) {
      if (child.exitCode !== null) throw new Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.match(output, /Server kjører på/);

    const doorLog = await (await fetch(base + '/api/admin/logs?kind=door', { headers })).json();
    assert.equal(doorLog.lines.length, 2);
    assert.ok(doorLog.lines.every(line => /action=(OPEN_MEMBER|DENY)/.test(line)));
    const checkoutLog = await (await fetch(base + '/api/admin/logs?kind=checkout', { headers })).json();
    assert.equal(checkoutLog.lines.length, 2);
    assert.ok(checkoutLog.lines.every(line => line.includes('VIPPS_CHECKOUT_')));
    assert.equal((await (await fetch(base + '/api/admin/logs', { headers })).json()).lines.length, 5);

    const smsPreview = await post('/admin/sms/preview', {
      recipientMode: 'plan', planKeys: ['Korttid_7dager'], onlyActive: true,
    });
    assert.equal(smsPreview.status, 200);
    const smsRecipients = await smsPreview.json();
    assert.equal(smsRecipients.attempted, 1);
    assert.equal(smsRecipients.sample[0].planKey, 'korttid_7dager');

    assert.equal((await post('/api/admin/members/delete', { email: 'shared@example.invalid' })).status, 409);
    assert.equal(readMembers().length, 5);
    assert.equal((await post('/api/admin/members/toggle', { memberId: 'member-b' })).status, 200);
    assert.equal(readMembers().find(m => m.id === 'member-a').active, true);
    assert.equal(readMembers().find(m => m.id === 'member-b').active, false);
    assert.equal((await fetch(base + '/admin/members/member-a', { method: 'DELETE', headers })).status, 200);
    assert.equal(readMembers().filter(m => m.email === 'shared@example.invalid').length, 1);

    const csv = 'Fornavn;Etternavn;E-post;Telefon;Annet;Medlemsstatus\nTest;D;d@example.invalid;44444444;;Aktiv';
    const previewResponse = await post('/api/admin/nif-import/preview', { csv });
    assert.equal(previewResponse.status, 200);
    const preview = await previewResponse.json();
    assert.equal(preview.added, 1);
    assert.equal(preview.removed, 1);
    assert.equal(readMembers().find(m => m.id === 'member-c').clubMember, true);
    assert.equal((await post('/api/admin/nif-import', { csv })).status, 409);
    assert.equal((await post('/api/admin/nif-import/preview', { csv: 'wrong file' })).status, 400);
    assert.equal(readMembers().find(m => m.id === 'member-c').clubMember, true);

    const edit = await fetch(base + '/admin/members/member-d/details', {
      method: 'PATCH', headers, body: JSON.stringify({ notes: 'Endret etter forhåndsvisning' }),
    });
    assert.equal(edit.status, 200);
    assert.equal((await post('/api/admin/nif-import', { csv, previewToken: preview.previewToken })).status, 409);
    const freshPreview = await (await post('/api/admin/nif-import/preview', { csv })).json();
    assert.equal((await post('/api/admin/nif-import', { csv, previewToken: freshPreview.previewToken })).status, 200);
    assert.equal(readMembers().find(m => m.id === 'member-c').clubMember, false);
    assert.equal(readMembers().find(m => m.id === 'member-d').clubMember, true);

    const planEdit = await fetch(base + '/admin/members/member-b/details', {
      method: 'PATCH', headers, body: JSON.stringify({ plan: 'medlem_m_binding' }),
    });
    assert.equal(planEdit.status, 200);
    assert.equal(readMembers().find(m => m.id === 'member-b').tripletexFollowUp.status, 'pending');
    assert.equal((await post('/admin/members/member-b/tripletex-follow-up/resolve', {})).status, 200);
    assert.equal(readMembers().find(m => m.id === 'member-b').tripletexFollowUp.status, 'resolved');
  } finally {
    child.kill();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

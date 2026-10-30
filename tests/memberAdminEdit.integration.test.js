const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

test('admin edits a synthetic member without changing orders or activation', async () => {
  const root = path.resolve(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-member-admin-'));
  const member = { id: 'synthetic-member', name: 'Før', email: 'before@example.invalid', phone: '+4712345678', plan: 'standard', active: true };
  const order = { orderId: 'synthetic-order', memberId: member.id, status: 'CAPTURED', amount: 100 };
  fs.writeFileSync(path.join(dataDir, 'members.json'), JSON.stringify([member]));
  fs.writeFileSync(path.join(dataDir, 'orders.json'), JSON.stringify([order]));
  fs.writeFileSync(path.join(dataDir, 'plans.json'), JSON.stringify([{ id: 'standard' }]));
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  let output = '';
  const child = spawn(process.execPath, [
    '--require', path.join(__dirname, 'blockExternal.cjs'), path.join(root, 'server.js'),
  ], {
    cwd: root,
    env: {
      PATH: process.env.PATH,
      NODE_PATH: path.resolve(root, '../legal-test-server/node_modules'),
      DATA_DIR: dataDir, PORT: String(port),
      ADMIN_USER: 'test-admin', ADMIN_PASS: 'synthetic-password',
      TRIPLETEX_RETRY_INTERVAL_MINUTES: '0',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  try {
    for (let attempt = 0; attempt < 80 && !output.includes(`Server kjører på http://localhost:${port}`); attempt++) {
      if (child.exitCode !== null) throw new Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.match(output, /Server kjører på/);
    const url = `http://127.0.0.1:${port}/admin/members/${member.id}/details`;
    const headers = { Authorization: `Basic ${Buffer.from('test-admin:synthetic-password').toString('base64')}`, 'Content-Type': 'application/json' };
    assert.equal((await fetch(url, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
    const body = JSON.stringify({
      name: 'Etter', email: 'after@example.invalid',
      membershipStartDate: '2026-01-31', bindingMonthsAtStart: 12,
      reason: 'Kontrollert oppdiktet Vipps-ordre',
    });
    const response = await fetch(url, { method: 'PATCH', headers, body });
    assert.equal(response.status, 200, output);
    const result = await response.json();
    assert.deepEqual(result.changedFields.sort(), ['name', 'email', 'membershipStartDate', 'bindingEndDate', 'bindingMonthsAtStart'].sort());
    const saved = JSON.parse(fs.readFileSync(path.join(dataDir, 'members.json')))[0];
    assert.equal(saved.name, 'Etter');
    assert.equal(saved.bindingEndDate, '2027-01-31');
    assert.equal(saved.active, true);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dataDir, 'orders.json'))), [order]);
    const rejected = await fetch(url, { method: 'PATCH', headers, body: JSON.stringify({ orderId: 'other-order' }) });
    assert.equal(rejected.status, 400);
  } finally {
    child.kill();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

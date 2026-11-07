const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { bindingBackfillRevision } = require('../bindingBackfill');

test('binding backfill requires a fresh backup and a current snapshot and saves the batch together', async () => {
  const root = path.resolve(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-backfill-'));
  const members = [{ id: 'm1', name: 'Første', active: true }, { id: 'm2', name: 'Andre', active: false }];
  const orders = members.map(({ id }, i) => ({
    orderId: `o${i + 1}`, memberId: id, tripletexOrderId: i + 1, status: 'CAPTURED', amount: 100,
  }));
  const plans = [];
  const write = (name, data) => fs.writeFileSync(path.join(dataDir, name + '.json'), JSON.stringify(data));
  const savedMembers = () => JSON.parse(fs.readFileSync(path.join(dataDir, 'members.json'), 'utf8'));
  write('members', members);
  write('orders', orders);
  write('plans', plans);
  const listener = net.createServer();
  await new Promise((resolve, reject) => listener.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  const child = spawn(process.execPath, ['--require', path.join(__dirname, 'blockExternal.cjs'), 'server.js'], {
    cwd: root,
    env: { PATH: process.env.PATH, NODE_PATH: process.env.NODE_PATH, DATA_DIR: dataDir, BACKUP_DATA_DIR: dataDir,
      PORT: String(port), BACKUP_CRON_SECRET: 'fixture-secret', ADMIN_USER: 'test', ADMIN_PASS: 'synthetic', TRIPLETEX_RETRY_INTERVAL_MINUTES: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exited = new Promise(resolve => child.once('exit', resolve));
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  const revision = bindingBackfillRevision(members, orders, plans);
  const entries = members.map(({ id }, i) => ({ memberId: id, orderId: `o${i + 1}`, startDate: '2025-12-25' }));
  const payload = { revision, backupKey: 'fixture-backup', entries };
  const url = `http://127.0.0.1:${port}/admin/members/binding-dates/backfill`;
  const run = (body, backupSecret = 'fixture-secret') => fetch(url, { method: 'POST', headers: {
    Authorization: 'Basic ' + Buffer.from('test:synthetic').toString('base64'), 'Content-Type': 'application/json',
    'x-backup-secret': backupSecret,
  }, body: JSON.stringify(body) });
  try {
    for (let i = 0; i < 80 && !output.includes('Server kjører på'); i++) {
      if (child.exitCode !== null) throw new Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.match(output, /Server kjører på/);
    assert.equal((await fetch(url, { method: 'POST' })).status, 401);
    assert.equal((await run(payload, 'wrong-secret')).status, 401);
    assert.equal((await run(payload)).status, 409);
    const status = { ok: true, key: payload.backupKey, bytes: 100 };
    write('backup-status', { ...status, finishedAt: new Date(Date.now() - 16 * 60 * 1000).toISOString() });
    assert.equal((await run(payload)).status, 409);
    write('backup-status', { ...status, finishedAt: new Date().toISOString() });
    assert.equal((await run({ ...payload, revision: 'stale' })).status, 409);
    assert.equal((await run({ ...payload, entries: [entries[0], { ...entries[1], orderId: 'unrelated' }] })).status, 400);
    assert.deepEqual(savedMembers(), members);
    const response = await run(payload);
    assert.equal(response.status, 200, await response.clone().text());
    assert.deepEqual(await response.json(), { ok: true, updated: 2 });
    const updated = savedMembers();
    for (let i = 0; i < members.length; i++) {
      assert.equal(updated[i].membershipStartDate, '2025-12-25');
      assert.equal(updated[i].bindingEndDate, '2026-12-25');
      assert.equal(updated[i].active, members[i].active);
      assert.equal(updated[i].name, members[i].name);
    }
    assert.equal((await run(payload)).status, 409);
    assert.equal((await run({ ...payload, revision: bindingBackfillRevision(updated, orders, plans) })).status, 400);
    assert.deepEqual(savedMembers(), updated);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dataDir, 'orders.json'), 'utf8')), orders);
  } finally {
    child.kill();
    await exited;
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

test('admin billing status reads synthetic invoices without changing members or access', async () => {
  const root = path.resolve(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-billing-status-'));
  const member = { id: 'member-1', name: 'Oppdiktet medlem', active: true, plan: 'standard' };
  const order = { orderId: 'vipps-order', memberId: member.id, tripletexOrderId: 411, status: 'CAPTURED' };
  fs.writeFileSync(path.join(dataDir, 'members.json'), JSON.stringify([member]));
  fs.writeFileSync(path.join(dataDir, 'orders.json'), JSON.stringify([order]));
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  let output = '';
  const child = spawn(process.execPath, [
    '--require', path.join(__dirname, 'blockExternal.cjs'),
    '--require', path.join(__dirname, 'mockTripletexInvoices.cjs'), path.join(root, 'server.js'),
  ], {
    cwd: root,
    env: { PATH: process.env.PATH, NODE_PATH: path.resolve(root, '../legal-test-server/node_modules'),
      DATA_DIR: dataDir, PORT: String(port), ADMIN_USER: 'test-admin', ADMIN_PASS: 'synthetic-password',
      TRIPLETEX_RETRY_INTERVAL_MINUTES: '0' },
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
    const url = `http://127.0.0.1:${port}/admin/billing-status`;
    assert.equal((await fetch(url)).status, 401);
    const response = await fetch(url, { headers: {
      Authorization: `Basic ${Buffer.from('test-admin:synthetic-password').toString('base64')}`,
    } });
    assert.equal(response.status, 200, output);
    const body = await response.json();
    assert.equal(body.statuses[0].code, 'overdue');
    assert.equal(body.statuses[0].memberId, member.id);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dataDir, 'members.json'))), [member]);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dataDir, 'orders.json'))), [order]);
  } finally {
    child.kill();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

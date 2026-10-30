const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const test = require('node:test');

const root = path.resolve(__dirname, '..');

test('admin check flags refund without changing member or paid order', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-refund-review-'));
  const member = { id: 'synthetic-member', email: 'person@example.invalid', active: true, plan: 'standard', bindingEndDate: '2027-10-30' };
  const order = { orderId: 'synthetic-order', memberId: member.id, amount: 100, status: 'CAPTURED', membershipKey: 'standard', createdAt: '2026-10-30T12:00:00Z' };
  fs.writeFileSync(path.join(dataDir, 'members.json'), JSON.stringify([member]));
  fs.writeFileSync(path.join(dataDir, 'orders.json'), JSON.stringify([order]));
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  let output = '';
  const child = spawn(process.execPath, [
    '--require', path.join(__dirname, 'blockExternal.cjs'),
    '--require', path.join(__dirname, 'mockVippsDetails.cjs'),
    path.join(root, 'server.js'),
  ], {
    cwd: root,
    env: {
      PATH: process.env.PATH,
      NODE_PATH: path.resolve(root, '../legal-test-server/node_modules'),
      DATA_DIR: dataDir,
      PORT: String(port),
      ADMIN_USER: 'test-admin', ADMIN_PASS: 'synthetic-password',
      MOCK_VIPPS_REFUNDED_AMOUNT: '40',
      TRIPLETEX_RETRY_INTERVAL_MINUTES: '0',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  const auth = { Authorization: `Basic ${Buffer.from('test-admin:synthetic-password').toString('base64')}` };
  try {
    for (let attempt = 0; attempt < 80 && !output.includes(`Server kjører på http://localhost:${port}`); attempt++) {
      if (child.exitCode !== null) throw new Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.match(output, /Server kjører på/);
    const url = `http://127.0.0.1:${port}/admin/orders/${order.orderId}`;
    assert.equal((await fetch(`${url}/check-refund`, { method: 'POST' })).status, 401);
    const checked = await fetch(`${url}/check-refund`, { method: 'POST', headers: auth });
    assert.equal(checked.status, 200, output);
    assert.equal((await checked.json()).refundReview.state, 'pending');
    const reviewed = await fetch(`${url}/refund-reviewed`, { method: 'POST', headers: auth });
    assert.equal(reviewed.status, 200);
    assert.equal((await reviewed.json()).refundReview.state, 'reviewed');
    const members = JSON.parse(fs.readFileSync(path.join(dataDir, 'members.json')));
    const orders = JSON.parse(fs.readFileSync(path.join(dataDir, 'orders.json')));
    assert.deepEqual(members, [member]);
    assert.equal(orders[0].status, 'CAPTURED');
    assert.equal(orders[0].refundReview.refundedAmount, 40);
    assert.equal(orders[0].refundReview.reviewedBy, 'test-admin');
  } finally {
    child.kill();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

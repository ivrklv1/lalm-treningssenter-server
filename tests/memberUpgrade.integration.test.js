const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const test = require('node:test');

const root = path.resolve(__dirname, '..');

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function waitForServer(port, child, output) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Local server exited: ${output()}`);
    if (output().includes(`Server kjører på http://localhost:${port}`)) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Local server did not start: ${output()}`);
}

for (const { initialPlan, storedPhone, bindingMonths } of [
  { initialPlan: 'dropin', storedPhone: '+4712345678', bindingMonths: 12 },
  { initialPlan: 'korttid', storedPhone: '+4712345678', bindingMonths: 0 },
  { initialPlan: 'standard_uten_binding', storedPhone: '+4712345678', bindingMonths: 12 },
]) {
  test(`simulated paid upgrade from ${initialPlan} (${storedPhone}) keeps member and updates dates`, async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-member-upgrade-'));
    const port = await freePort();
    const memberId = `synthetic-${initialPlan}`;
    const orderId = `synthetic-order-${initialPlan}`;
    const previousMembership = initialPlan === 'standard_uten_binding';
    const realEmail = previousMembership ? 'old@example.invalid' : `Test.${initialPlan}@example.invalid`;
    const purchasedPlan = previousMembership ? 'standard_12mnd_binding' : 'standard';
    fs.writeFileSync(path.join(dataDir, 'members.json'), JSON.stringify([{
      id: memberId,
      email: previousMembership ? 'old@example.invalid' : 'temp-4712345678@lalmtreningssenter.no',
      phone: storedPhone,
      name: 'Oppdiktet Medlem',
      active: true,
      plan: initialPlan,
      ...(!previousMembership ? { validUntil: '2099-01-01T23:59:59.000Z' } : {}),
      ...(previousMembership ? {
        membershipStartDate: '2026-01-10', bindingEndDate: null,
        bindingMonthsAtStart: 0, membershipStartOrderId: 'previous-order',
      } : {}),
    }]));
    fs.writeFileSync(path.join(dataDir, 'orders.json'), JSON.stringify([...(previousMembership ? [{
      orderId: 'previous-order', status: 'SALE', paidAt: '2026-01-10T12:00:00Z',
      membershipKey: initialPlan, bindingMonths: 0, memberId,
    }] : []), {
      orderId,
      status: 'PENDING',
      amount: 100,
      membershipKey: purchasedPlan,
      ...(bindingMonths == null ? {} : { bindingMonths }),
      phone: '+4712345678',
      phoneFull: '+4712345678',
      email: realEmail,
      name: 'Oppdiktet Medlem',
      isShortOrDropin: false,
      welcomeSmsSent: true,
      tripletexSynced: true,
    }]));

    let output = '';
    const child = spawn(process.execPath, [
      '--require', path.join(__dirname, 'blockExternal.cjs'),
      '--require', path.join(__dirname, 'mockVippsDetails.cjs'), path.join(root, 'server.js'),
    ], {
      cwd: root,
      env: {
        PATH: process.env.PATH,
        NODE_PATH: path.resolve(root, '../legal-test-server/node_modules'),
        DATA_DIR: dataDir,
        PORT: String(port),
        TRIPLETEX_RETRY_INTERVAL_MINUTES: '0',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { output += chunk; });

    try {
      await waitForServer(port, child, () => output);
      const response = await fetch(`http://localhost:${port}/vipps/callback/v2/payments/${orderId}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ transactionInfo: { status: 'SALE', transactionId: 'synthetic-only', timeStamp: '2026-10-28T12:00:00Z' } }),
      });
      assert.equal(response.status, 200, output);
      assert.equal(await response.text(), 'OK');

      for (let attempt = 0; attempt < 60; attempt += 1) {
        const currentOrders = JSON.parse(fs.readFileSync(path.join(dataDir, 'orders.json')));
        if (currentOrders.find(order => order.orderId === orderId)?.paidAtVerifiedAt) break;
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      const members = JSON.parse(fs.readFileSync(path.join(dataDir, 'members.json')));
      const orders = JSON.parse(fs.readFileSync(path.join(dataDir, 'orders.json')));
      const purchasedOrder = orders.find(order => order.orderId === orderId);
      assert.equal(members.length, 1);
      assert.equal(members[0].id, memberId);
      assert.equal(members[0].email, realEmail.toLowerCase());
      assert.equal(members[0].plan, purchasedPlan);
      assert.equal(members[0].active, true);
      if (bindingMonths != null) {
        assert.equal(members[0].membershipStartDate, '2026-10-29');
        assert.equal(members[0].bindingEndDate, bindingMonths ? '2027-10-29' : null);
        assert.equal(members[0].membershipStartOrderId, orderId);
        assert.equal(members[0].bindingMonthsAtStart, bindingMonths);
        assert.equal(purchasedOrder.paidAt, '2026-10-29T12:00:00Z');
        assert.ok(purchasedOrder.paidAtVerifiedAt);
      } else {
        assert.equal(Object.hasOwn(members[0], 'membershipStartDate'), false);
      }
      assert.equal(Object.hasOwn(members[0], 'validUntil'), false);
      assert.equal(purchasedOrder.status, 'SALE');
      assert.equal(purchasedOrder.memberId, memberId);
      assert.equal(purchasedOrder.welcomeSmsSent, true);
      assert.equal(purchasedOrder.tripletexSynced, true);
      assert.equal(output.includes('TEST BLOCKED AN OUTBOUND CONNECTION'), false, output);
    } finally {
      child.kill('SIGTERM');
      await new Promise(resolve => child.once('exit', resolve));
      fs.rmSync(dataDir, { recursive: true, force: true });
    }
  });
}

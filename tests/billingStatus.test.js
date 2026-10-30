const test = require('node:test');
const assert = require('node:assert/strict');
const { memberBillingStatuses } = require('../billingStatus');

const members = [{ id: 'member-1' }, { id: 'member-2' }];
const orders = [{ memberId: 'member-1', tripletexOrderId: 411 }, { memberId: 'member-2', tripletexOrderId: 422 }];
const invoice = (orderId, dueDate, outstanding, extra = {}) => ({
  id: 1, invoiceNumber: 123, orders: [{ id: orderId }], invoiceDueDate: dueDate,
  amount: 449, amountOutstanding: outstanding, isCreditNote: false,
  isCredited: false, isCharged: true, ...extra,
});
const status = (invoices, today = '2026-10-30', sourceOrders = orders) =>
  memberBillingStatuses(members, sourceOrders, invoices, today);

test('shows invoiced, overdue and paid separately from the 14-day future lock threshold', () => {
  assert.equal(status([invoice(411, '2026-11-01', 449)])[0].code, 'invoiced');
  assert.equal(status([invoice(411, '2026-10-29', 449)])[0].code, 'overdue');
  assert.equal(status([invoice(411, '2026-10-16', 449)])[0].beyondGrace, true);
  assert.equal(status([invoice(411, '2026-10-17', 449)])[0].beyondGrace, false);
  assert.equal(status([invoice(411, '2026-10-01', 0)])[0].code, 'paid');
});

test('does not call credited, incomplete or unrelated invoices paid', () => {
  assert.equal(status([invoice(411, '2026-10-01', 0, { isCredited: true })])[0].code, 'unknown');
  assert.equal(status([invoice(411, '2026-10-01', null)])[0].code, 'unknown');
  assert.equal(status([invoice(999, '2026-10-01', 0)])[0].code, 'unknown');
  assert.equal(status([invoice(411, '2026-10-01', 449)], '2026-10-30', [
    ...orders, { memberId: 'member-2', tripletexOrderId: 411 },
  ])[0].code, 'unknown');
});

test('an older overdue invoice remains visible despite a newer paid invoice', () => {
  const result = status([
    invoice(411, '2026-09-01', 449, { id: 1, invoiceNumber: 100 }),
    invoice(411, '2026-10-01', 0, { id: 2, invoiceNumber: 101 }),
  ]);
  assert.equal(result[0].code, 'overdue');
  assert.equal(result[0].invoiceNumber, 100);
  assert.equal(result[1].code, 'unknown');
});

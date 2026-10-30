const test = require('node:test');
const assert = require('node:assert/strict');
const { confirmedRefund } = require('../refundReview');

const order = { orderId: 'synthetic-order', amount: 100 };
const refund = amount => ({
  orderId: order.orderId,
  transactionSummary: { capturedAmount: 100, refundedAmount: amount },
  transactionLogHistory: [{ operation: 'REFUND', operationSuccess: true, amount, timeStamp: '2026-10-30T12:00:00Z' }],
});

test('detects partial and full refunds', () => {
  assert.deepEqual(confirmedRefund(refund(40), order), {
    capturedAmount: 100, refundedAmount: 40, kind: 'partial', lastRefundAt: '2026-10-30T12:00:00Z',
  });
  assert.equal(confirmedRefund(refund(100), order).kind, 'full');
  assert.equal(confirmedRefund({ ...refund(0), transactionLogHistory: [] }, order), null);
});

test('does not flag an unverified or unrelated refund', () => {
  assert.throws(() => confirmedRefund({ ...refund(40), orderId: 'other-order' }, order));
  assert.throws(() => confirmedRefund({ ...refund(40), transactionLogHistory: [{ ...refund(40).transactionLogHistory[0], operationSuccess: false }] }, order));
  assert.throws(() => confirmedRefund({ ...refund(40), transactionSummary: { capturedAmount: 100, refundedAmount: 60 } }, order));
});

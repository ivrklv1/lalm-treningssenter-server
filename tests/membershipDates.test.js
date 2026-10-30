const assert = require('node:assert/strict');
const test = require('node:test');
const { datesForPaidMembership, shouldReplaceMembershipDates, verifiedPaymentTime, verifiedVippsStatus } = require('../membershipDates');

test('starts on the Oslo payment day and leaves subscription state alone', () => {
  assert.deepEqual(datesForPaidMembership('2026-10-29T23:30:00Z', 12), {
    membershipStartDate: '2026-10-30',
    bindingEndDate: '2027-10-30',
    bindingMonthsAtStart: 12,
  });
  assert.deepEqual(datesForPaidMembership('2026-10-29T10:00:00Z', 0), {
    membershipStartDate: '2026-10-29',
    bindingEndDate: null,
    bindingMonthsAtStart: 0,
  });
});

test('clamps month-end dates and refuses unverified inputs', () => {
  assert.equal(datesForPaidMembership('2024-02-29T12:00:00Z', 12).bindingEndDate, '2025-02-28');
  assert.equal(datesForPaidMembership(null, 12), null);
  assert.equal(datesForPaidMembership('2026-10-29T10:00:00Z', undefined), null);
});

test('a later paid agreement replaces dates, while an old or repeated order cannot', () => {
  const member = { membershipStartDate: '2026-01-10', membershipStartOrderId: 'first' };
  const previousPaymentTime = '2026-01-10T12:00:00Z';
  assert.equal(shouldReplaceMembershipDates(member, 'second', '2026-10-29T12:00:00Z', '2026-10-29', previousPaymentTime), true);
  assert.equal(shouldReplaceMembershipDates(member, 'first', previousPaymentTime, '2026-01-10', previousPaymentTime), false);
  assert.equal(shouldReplaceMembershipDates(member, 'older', '2025-12-01T12:00:00Z', '2025-12-01', previousPaymentTime), false);
  assert.equal(shouldReplaceMembershipDates(member, 'later-today', '2026-01-10T13:00:00Z', '2026-01-10', previousPaymentTime), true);
  assert.equal(shouldReplaceMembershipDates(member, 'earlier-today', '2026-01-10T11:00:00Z', '2026-01-10', previousPaymentTime), false);
});

test('accepts only a matching, successful and unrefunded Vipps capture', () => {
  const order = { orderId: 'order-1', amount: 100 };
  const details = {
    orderId: 'order-1', transactionSummary: { capturedAmount: 100, refundedAmount: 0 },
    transactionLogHistory: [
      { operation: 'RESERVE', operationSuccess: true, amount: 100, timeStamp: '2026-10-29T11:00:00Z' },
      { operation: 'CAPTURE', operationSuccess: true, amount: 100, timeStamp: '2026-10-29T12:00:00Z' },
    ],
  };
  assert.equal(verifiedPaymentTime(details, order), '2026-10-29T12:00:00Z');
  assert.equal(verifiedVippsStatus(details, order), 'CAPTURED');
  assert.equal(verifiedPaymentTime({ ...details, orderId: 'another-order' }, order), null);
  assert.equal(verifiedPaymentTime({ ...details, transactionSummary: { capturedAmount: 100, refundedAmount: 100 } }, order), null);
  assert.equal(verifiedPaymentTime({ ...details, transactionLogHistory: [{ operation: 'CAPTURE', operationSuccess: false, amount: 100, timeStamp: '2026-10-29T12:00:00Z' }] }, order), null);
  assert.equal(verifiedPaymentTime({ ...details, transactionSummary: { capturedAmount: 99, refundedAmount: 0 } }, order), null);
  assert.equal(verifiedVippsStatus({ ...details, transactionSummary: { capturedAmount: 99, refundedAmount: 0 } }, order), null);
  assert.equal(verifiedVippsStatus({ ...details, transactionLogHistory: [
    { operation: 'INITIATE', operationSuccess: true, amount: 100, timeStamp: '2026-10-29T11:00:00Z' },
  ] }, order), 'PENDING');
  assert.equal(verifiedVippsStatus({ ...details, transactionSummary: { capturedAmount: 0, refundedAmount: 0 }, transactionLogHistory: [
    { operation: 'RESERVE', operationSuccess: true, amount: 100, timeStamp: '2026-10-29T11:00:00Z' },
  ] }, order), 'RESERVED');
  assert.equal(verifiedVippsStatus({ ...details, transactionSummary: { capturedAmount: 0, refundedAmount: 0 }, transactionLogHistory: [
    { operation: 'RESERVE', operationSuccess: true, amount: 99, timeStamp: '2026-10-29T11:00:00Z' },
  ] }, order), null);
});

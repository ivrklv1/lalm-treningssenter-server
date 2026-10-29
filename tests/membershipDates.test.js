const assert = require('node:assert/strict');
const test = require('node:test');
const { datesForPaidMembership } = require('../membershipDates');

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

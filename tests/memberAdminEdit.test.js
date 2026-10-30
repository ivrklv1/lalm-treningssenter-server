const test = require('node:test');
const assert = require('node:assert/strict');
const { prepareAdminMemberEdit } = require('../memberAdminEdit');

const now = '2026-10-30T12:00:00Z';
const member = { id: 'synthetic-1', name: 'Gammelt Navn', email: 'old@example.invalid', phone: '+4712345678', plan: 'standard', active: true };
const other = { id: 'synthetic-2', email: 'taken@example.invalid', phone: '87654321' };
const plans = [{ id: 'standard' }, { id: 'standard_binding' }];
const edit = (changes, source = member) => prepareAdminMemberEdit(source, changes, [source, other], plans, 'test-admin', now);

test('validates profile edits, duplicates and protected fields', () => {
  const result = edit({ name: 'Nytt Navn', email: 'NEW@example.invalid', phone: '12345678', plan: 'standard_binding' });
  assert.equal(result.member.name, 'Nytt Navn');
  assert.equal(result.member.email, 'new@example.invalid');
  assert.equal(result.member.phoneFull, '+4712345678');
  assert.equal(result.member.active, true);
  assert.deepEqual(result.member.adminEditHistory[0].fields.sort(), ['name', 'email', 'phone', 'plan'].sort());
  assert.throws(() => edit({ email: 'taken@example.invalid' }), /duplicate_email/);
  assert.throws(() => edit({ phone: '+4787654321' }), /duplicate_phone/);
  assert.throws(() => edit({ id: 'new-id' }), /invalid_fields/);
  assert.throws(() => edit({ active: false }), /invalid_fields/);
  assert.throws(() => edit({ bindingEndDate: '2027-10-30' }), /invalid_fields/);
});

test('a short-term plan with a capitalized key stays selected without a false plan change', () => {
  const shortTerm = { ...member, plan: 'korttid_7dager' };
  const shortPlans = [{ id: 'Korttid_7dager' }, { id: 'Korttid_3dager' }];
  const same = prepareAdminMemberEdit(shortTerm, { plan: 'Korttid_7dager' }, [shortTerm], shortPlans, 'test-admin', now);
  assert.deepEqual(same.changedFields, []);
  assert.equal(same.member.plan, 'korttid_7dager');
  assert.equal(same.member.tripletexFollowUp, undefined);

  const changed = prepareAdminMemberEdit(shortTerm, { plan: 'Korttid_3dager' }, [shortTerm], shortPlans, 'test-admin', now);
  assert.equal(changed.member.plan, 'korttid_3dager');
  assert.equal(changed.member.tripletexFollowUp.status, 'pending');
});

test('manual dates require reason, compute end and preserve active status', () => {
  const changes = { membershipStartDate: '2026-01-31', bindingMonthsAtStart: 12, reason: 'Vipps-ordre og avtale kontrollert' };
  const result = edit(changes);
  assert.equal(result.member.membershipStartDate, '2026-01-31');
  assert.equal(result.member.bindingEndDate, '2027-01-31');
  assert.equal(result.member.bindingMonthsAtStart, 12);
  assert.equal(result.member.active, true);
  assert.equal(result.member.membershipDatesManualReview.editedBy, 'test-admin');
  assert.throws(() => edit({ ...changes, reason: '' }), /date_reason_required/);
  assert.throws(() => edit({ ...changes, membershipStartDate: '2026-02-30' }), /invalid_membership_start/);
  assert.throws(() => edit({ ...changes, membershipStartDate: '2026-11-01' }), /future_membership_start/);
  assert.throws(() => edit(changes, { ...member, membershipStartOrderId: 'vipps-order' }), /vipps_verified_dates_locked/);
  assert.equal(edit({ ...changes, bindingMonthsAtStart: 0 }).member.bindingEndDate, null);
});

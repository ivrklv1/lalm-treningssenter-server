const assert = require('node:assert/strict');
const test = require('node:test');
const { canUpgradeTemporaryMember, findCheckoutConflict, upgradeTemporaryEmail } = require('../memberEmail');

test('checkout allows the short-term-to-membership transition but blocks duplicate memberships', () => {
  const shortTerm = {
    id: 'short', email: 'temp-4712345678@lalmtreningssenter.no',
    phone: '+4712345678', active: true, plan: 'dropin', validUntil: '2099-01-01',
  };
  const active = member => Boolean(member.validUntil ? new Date(member.validUntil) > new Date() : true);
  assert.equal(findCheckoutConflict([shortTerm], '12345678', 'person@example.no', true, active), null);
  assert.equal(findCheckoutConflict([shortTerm], '12345678', 'person@example.no', false, active), shortTerm);
  assert.equal(findCheckoutConflict([shortTerm], '12345678', 'invalid', true, active), shortTerm);
  const ordinary = { ...shortTerm, email: 'person@example.no', validUntil: null, plan: 'standard' };
  assert.equal(findCheckoutConflict([ordinary], '12345678', 'person@example.no', true, active), ordinary);
});

test('checkout refuses ambiguous phone and email ownership', () => {
  const shortTerm = {
    id: 'short', email: 'temp-4712345678@lalmtreningssenter.no',
    phone: '+4712345678', active: true, validUntil: '2099-01-01',
  };
  const other = { id: 'other', email: 'taken@example.no', phone: '+4799999999', active: true };
  const active = () => true;
  assert.equal(findCheckoutConflict([shortTerm, other], '12345678', 'taken@example.no', true, active), shortTerm);
  assert.equal(findCheckoutConflict([shortTerm, { ...shortTerm, id: 'duplicate' }], '12345678', 'new@example.no', true, active), shortTerm);
});

test('active drop-in with a temporary email can upgrade using the same phone', () => {
  const member = {
    email: 'temp-4712345678@lalmtreningssenter.no',
    phone: '+4712345678', active: true, plan: 'dropin',
    validUntil: '2026-10-30T23:59:59.000Z',
  };
  assert.equal(canUpgradeTemporaryMember(member, [member], 'person@example.no', '12345678', true), true);
  assert.equal(member.email, 'temp-4712345678@lalmtreningssenter.no');
  assert.equal(upgradeTemporaryEmail(member, 'person@example.no', [member], true), true);
  assert.equal(member.email, 'person@example.no');
});

test('upgrade requires matching phone, ordinary plan and a unique valid email', () => {
  const member = {
    email: 'temp-4712345678@lalmtreningssenter.no',
    phone: '+4712345678', active: true, plan: 'short_term',
    validUntil: '2026-10-30T23:59:59.000Z',
  };
  const other = { email: 'taken@example.no', phone: '+4799999999' };
  assert.equal(canUpgradeTemporaryMember(member, [member], 'person@example.no', '99999999', true), false);
  assert.equal(canUpgradeTemporaryMember(member, [member], 'person@example.no', '12345678', false), false);
  assert.equal(canUpgradeTemporaryMember(member, [member], 'invalid', '12345678', true), false);
  assert.equal(canUpgradeTemporaryMember(member, [member, other], 'taken@example.no', '12345678', true), false);
  assert.equal(canUpgradeTemporaryMember({ ...member, validUntil: null }, [other], 'person@example.no', '12345678', true), false);
  assert.equal(canUpgradeTemporaryMember({ ...member, active: false }, [other], 'person@example.no', '12345678', true), false);
  assert.equal(member.email, 'temp-4712345678@lalmtreningssenter.no');
});

test('ordinary membership replaces a temporary email from drop-in', () => {
  const member = { email: 'temp-4712345678@lalmtreningssenter.no' };
  assert.equal(upgradeTemporaryEmail(member, 'Person@Example.no', [member], true), true);
  assert.equal(member.email, 'person@example.no');
});

test('drop-in and short-term purchases leave the email alone', () => {
  const member = { email: 'temp-4712345678@lalmtreningssenter.no' };
  assert.equal(upgradeTemporaryEmail(member, 'person@example.no', [member], false), false);
  assert.equal(member.email, 'temp-4712345678@lalmtreningssenter.no');
});

test('a real email is not overwritten by a later checkout', () => {
  const member = { email: 'original@example.no' };
  assert.equal(upgradeTemporaryEmail(member, 'other@example.no', [member], true), false);
  assert.equal(member.email, 'original@example.no');
});

test('invalid and duplicate emails are not accepted', () => {
  const member = { email: 'temp-4712345678@lalmtreningssenter.no' };
  const other = { email: 'taken@example.no' };
  assert.equal(upgradeTemporaryEmail(member, 'not-an-email', [member], true), false);
  assert.equal(upgradeTemporaryEmail(member, 'taken@example.no', [member, other], true), false);
  assert.equal(member.email, 'temp-4712345678@lalmtreningssenter.no');
});

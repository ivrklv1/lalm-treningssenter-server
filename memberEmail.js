const TEMPORARY_EMAIL = /^temp-\d+@lalmtreningssenter\.no$/i;
const VALID_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeMemberPhone(value) {
  const raw = String(value || '').trim();
  if (/[a-z]/i.test(raw)) return null;
  const digits = raw.replace(/\D/g, '');
  const local = digits.length === 8 ? digits
    : digits.length === 10 && digits.startsWith('47') ? digits.slice(2)
    : digits.length === 12 && digits.startsWith('0047') ? digits.slice(4)
    : null;
  return local ? `+47${local}` : null;
}

function canUpgradeTemporaryEmail(member, orderEmail, members, isOrdinaryMembership) {
  if (!isOrdinaryMembership) return false;

  const current = String(member.email || '').trim().toLowerCase();
  const requested = String(orderEmail || '').trim().toLowerCase();
  if ((current && !TEMPORARY_EMAIL.test(current)) ||
      !VALID_EMAIL.test(requested) || TEMPORARY_EMAIL.test(requested) ||
      current === requested ||
      members.some(other => other !== member &&
        String(other.email || '').trim().toLowerCase() === requested)) {
    return false;
  }

  return true;
}

function canUpgradeTemporaryMember(member, members, orderEmail, orderPhone, isOrdinaryMembership) {
  const memberPhone = normalizeMemberPhone(member.phone || member.phoneFull || member.mobile);
  const orderPhoneNormalized = normalizeMemberPhone(orderPhone);
  const expiry = new Date(member.validUntil).getTime();
  return Boolean(member.active && member.validUntil && Number.isFinite(expiry) &&
    memberPhone && memberPhone === orderPhoneNormalized &&
    canUpgradeTemporaryEmail(member, orderEmail, members, isOrdinaryMembership));
}

function findCheckoutConflict(members, orderPhone, orderEmail, isOrdinaryMembership, isValidUntilOk) {
  const requestedPhone = normalizeMemberPhone(orderPhone);
  const requestedEmail = String(orderEmail || '').trim().toLowerCase();
  const phoneOwners = members.filter(m =>
    normalizeMemberPhone(m.phone || m.phoneFull || m.mobile) === requestedPhone);
  const emailOwners = requestedEmail ? members.filter(m =>
    String(m.email || '').trim().toLowerCase() === requestedEmail) : [];
  const activeExisting = members.find(m =>
    (phoneOwners.includes(m) || emailOwners.includes(m)) && m.active && isValidUntilOk(m));

  const phoneOwner = phoneOwners.length === 1 ? phoneOwners[0] : null;
  const upgradingShortTerm = phoneOwner &&
    emailOwners.every(m => m === phoneOwner) &&
    canUpgradeTemporaryMember(phoneOwner, members, orderEmail, orderPhone, isOrdinaryMembership);
  return activeExisting && !upgradingShortTerm ? activeExisting : null;
}

function upgradeTemporaryEmail(member, orderEmail, members, isOrdinaryMembership) {
  if (!canUpgradeTemporaryEmail(member, orderEmail, members, isOrdinaryMembership)) return false;

  member.email = String(orderEmail).trim().toLowerCase();
  return true;
}

module.exports = { canUpgradeTemporaryMember, findCheckoutConflict, upgradeTemporaryEmail };

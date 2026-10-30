const { datesForPaidMembership } = require('./membershipDates');

const EDITABLE = new Set([
  'name', 'email', 'phone', 'address', 'zip', 'city', 'plan', 'clubMember', 'notes',
  'membershipStartDate', 'bindingMonthsAtStart', 'reason',
]);

function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T12:00:00Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

function normalizedPhone(value) {
  let phone = String(value || '').replace(/[\s\-()]/g, '');
  if (/^\d{8}$/.test(phone)) phone = `+47${phone}`;
  else if (/^47\d{8}$/.test(phone)) phone = `+${phone}`;
  return phone;
}

function prepareAdminMemberEdit(member, changes, members, plans, adminUser, now) {
  if (!changes || typeof changes !== 'object' || Array.isArray(changes) ||
      Object.keys(changes).some(key => !EDITABLE.has(key))) throw new Error('invalid_fields');
  const next = { ...member };
  const changedFields = [];
  const set = (field, value) => {
    if (next[field] !== value) {
      next[field] = value;
      changedFields.push(field);
    }
  };
  const stringFields = { name: 120, address: 200, zip: 12, city: 100, notes: 1000 };
  for (const [field, maxLength] of Object.entries(stringFields)) {
    if (!Object.hasOwn(changes, field)) continue;
    if (typeof changes[field] !== 'string') throw new Error(`invalid_${field}`);
    const value = changes[field].trim();
    if (value.length > maxLength || (field === 'name' && !value)) throw new Error(`invalid_${field}`);
    if (field === 'zip' && value && !/^\d{4}$/.test(value)) throw new Error('invalid_zip');
    set(field, value);
  }
  if (Object.hasOwn(changes, 'email')) {
    if (typeof changes.email !== 'string') throw new Error('invalid_email');
    const email = changes.email.trim().toLowerCase();
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('invalid_email');
    if (members.some(other => other.id !== member.id && String(other.email || '').trim().toLowerCase() === email)) {
      throw new Error('duplicate_email');
    }
    set('email', email);
  }
  if (Object.hasOwn(changes, 'phone')) {
    if (typeof changes.phone !== 'string') throw new Error('invalid_phone');
    const phone = normalizedPhone(changes.phone);
    if (!/^\+47\d{8}$/.test(phone)) throw new Error('invalid_phone');
    if (members.some(other => other.id !== member.id &&
      [other.phone, other.phoneFull, other.mobile].some(value => normalizedPhone(value) === phone))) {
      throw new Error('duplicate_phone');
    }
    if (member.phone !== phone || member.phoneFull !== phone || member.mobile !== phone) {
      next.phone = phone;
      next.phoneFull = phone;
      next.mobile = phone;
      changedFields.push('phone');
    }
  }
  if (Object.hasOwn(changes, 'plan')) {
    if (typeof changes.plan !== 'string' || !changes.plan.trim()) throw new Error('invalid_plan');
    const plan = changes.plan.trim();
    if (plan !== member.plan && !plans.some(item => (item.id || item.key) === plan)) throw new Error('invalid_plan');
    set('plan', plan);
    if (plan !== member.plan) {
      next.tripletexFollowUp = {
        reason: 'plan_change', fromPlan: member.plan || null, toPlan: plan,
        createdAt: now, createdBy: adminUser, status: 'pending',
      };
    }
  }
  if (Object.hasOwn(changes, 'clubMember')) {
    if (typeof changes.clubMember !== 'boolean') throw new Error('invalid_clubMember');
    set('clubMember', changes.clubMember);
  }

  const dateFieldsPresent = Object.hasOwn(changes, 'membershipStartDate') || Object.hasOwn(changes, 'bindingMonthsAtStart');
  if (dateFieldsPresent) {
    if (!Object.hasOwn(changes, 'membershipStartDate') || !Object.hasOwn(changes, 'bindingMonthsAtStart')) {
      throw new Error('incomplete_membership_dates');
    }
    const start = changes.membershipStartDate;
    const months = changes.bindingMonthsAtStart;
    if (start !== '' && !validDate(start)) throw new Error('invalid_membership_start');
    if (start > now.slice(0, 10)) throw new Error('future_membership_start');
    if (start !== '' && ![0, 12].includes(months)) throw new Error('invalid_binding_months');
    if (start === '' && months !== null) throw new Error('incomplete_membership_dates');
    const dates = start ? datesForPaidMembership(`${start}T12:00:00+01:00`, months) : {
      membershipStartDate: null, bindingEndDate: null, bindingMonthsAtStart: null,
    };
    const dateChanged = Object.entries(dates).some(([field, value]) => (member[field] ?? null) !== value);
    if (dateChanged) {
      if (member.membershipStartOrderId) throw new Error('vipps_verified_dates_locked');
      const reason = typeof changes.reason === 'string' ? changes.reason.trim() : '';
      if (reason.length < 10 || reason.length > 500) throw new Error('date_reason_required');
      for (const [field, value] of Object.entries(dates)) set(field, value);
      next.membershipDatesManualReview = { reason, editedAt: now, editedBy: adminUser };
    }
  }
  if (changedFields.length) {
    next.updatedAt = now;
    next.adminEditHistory = [...(Array.isArray(member.adminEditHistory) ? member.adminEditHistory : []), {
      editedAt: now, editedBy: adminUser, fields: changedFields,
    }].slice(-30);
  }
  return { member: next, changedFields };
}

module.exports = { prepareAdminMemberEdit };

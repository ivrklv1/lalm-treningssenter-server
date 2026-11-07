const crypto = require('node:crypto');
const fs = require('node:fs');
const { prepareAdminMemberEdit } = require('./memberAdminEdit');

function bindingBackfillRevision(members, orders, plans) {
  return crypto.createHash('sha256').update(JSON.stringify([members, orders, plans])).digest('hex');
}

function prepareBindingBackfill(entries, members, orders, plans, adminUser, now) {
  if (!Array.isArray(entries) || !entries.length || entries.length > 100 ||
      entries.some(entry => !entry || typeof entry.memberId !== 'string' ||
        typeof entry.orderId !== 'string' || typeof entry.startDate !== 'string' || !entry.startDate) ||
      new Set(entries.map(entry => entry.memberId)).size !== entries.length ||
      new Set(entries.map(entry => entry.orderId)).size !== entries.length) {
    throw new Error('invalid_backfill_entries');
  }
  const next = [...members];
  for (const { memberId, orderId, startDate } of entries) {
    const matches = members.filter(member => member.id === memberId);
    const matchingOrders = orders.filter(order => order.orderId === orderId);
    if (matches.length !== 1 || matchingOrders.length !== 1) throw new Error('backfill_link_not_unique');
    const [member] = matches;
    const [order] = matchingOrders;
    const dateFields = [member.membershipStartDate, member.bindingEndDate, member.bindingMonthsAtStart, member.membershipStartOrderId];
    if (dateFields.some(value => value != null && value !== '')) throw new Error('backfill_dates_already_set');
    if (order.memberId !== memberId || !order.tripletexOrderId || !['SALE', 'CAPTURED'].includes(order.status) ||
        Number(order.refundReview?.refundedAmount) > 0 ||
        (order.bindingMonths != null && Number(order.bindingMonths) !== 12)) {
      throw new Error('backfill_order_changed');
    }
    next[members.indexOf(member)] = prepareAdminMemberEdit(member, {
      membershipStartDate: startDate,
      bindingMonthsAtStart: 12,
      reason: `Kontrollert mot Vipps-ordre ${orderId} og historisk avtale.`,
    }, members, plans, adminUser, now).member;
  }
  return next;
}

function saveBindingBackfill(file, members) {
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  try {
    const descriptor = fs.openSync(temporary, 'wx', fs.statSync(file).mode & 0o777);
    try {
      fs.writeFileSync(descriptor, JSON.stringify(members, null, 2), 'utf8');
      fs.fsyncSync(descriptor);
    } finally { fs.closeSync(descriptor); }
    fs.renameSync(temporary, file);
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}

module.exports = { bindingBackfillRevision, prepareBindingBackfill, saveBindingBackfill };

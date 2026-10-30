function osloToday(now = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Oslo', year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(now);
  const get = key => parts.find(part => part.type === key)?.value;
  return `${get('year')}-${get('month')}-${get('day')}`;
}

function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T12:00:00Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function daysAfter(date, today) {
  return Math.floor((Date.parse(`${today}T12:00:00Z`) - Date.parse(`${date}T12:00:00Z`)) / 86400000);
}

function memberBillingStatuses(members, orders, invoices, today = osloToday()) {
  if (!validDate(today) || !Array.isArray(members) || !Array.isArray(orders) || !Array.isArray(invoices)) {
    throw new Error('invalid_billing_input');
  }
  const orderOwners = new Map();
  for (const order of orders) {
    if (!order.memberId || !order.tripletexOrderId) continue;
    const key = String(order.tripletexOrderId);
    const owners = orderOwners.get(key) || new Set();
    owners.add(String(order.memberId));
    orderOwners.set(key, owners);
  }
  const byMember = new Map();
  const ambiguousMembers = new Set();
  for (const invoice of invoices) {
    if (!Array.isArray(invoice.orders) || invoice.orders.length !== 1 || invoice.orders[0]?.id == null) continue;
    const owners = orderOwners.get(String(invoice.orders[0].id));
    if (!owners) continue;
    if (owners.size !== 1) {
      for (const memberId of owners) ambiguousMembers.add(memberId);
      continue;
    }
    const memberId = [...owners][0];
    const list = byMember.get(memberId) || [];
    list.push(invoice);
    byMember.set(memberId, list);
  }
  return members.map(member => {
    const memberId = String(member.id || '');
    const relatedOrderIds = orders.filter(order => String(order.memberId || '') === memberId && order.tripletexOrderId).length;
    const base = { memberId, code: 'unknown', invoiceNumber: null, dueDate: null,
      outstanding: null, daysPastDue: null, beyondGrace: false };
    if (!memberId || ambiguousMembers.has(memberId) || !relatedOrderIds) return base;
    const related = byMember.get(memberId) || [];
    if (!related.length) return base;
    const candidates = related.map(invoice => {
      const amount = invoice.amount;
      const outstanding = invoice.amountOutstanding;
      const dueDate = invoice.invoiceDueDate;
      const valid = Number.isFinite(amount) && amount > 0 &&
        Number.isFinite(outstanding) && outstanding >= 0 && validDate(dueDate) &&
        invoice.isCreditNote === false && invoice.isCredited === false &&
        invoice.isCharged === true;
      if (!valid) return { invoice, code: 'unknown', dueDate: validDate(dueDate) ? dueDate : null, outstanding: null };
      const lateDays = daysAfter(dueDate, today);
      return { invoice, code: outstanding === 0 ? 'paid' : lateDays > 0 ? 'overdue' : 'invoiced',
        dueDate, outstanding, lateDays };
    });
    const priority = { overdue: 3, invoiced: 2, unknown: 1, paid: 0 };
    candidates.sort((a, b) => priority[b.code] - priority[a.code] ||
      (a.code === 'overdue' ? a.dueDate.localeCompare(b.dueDate) : b.dueDate?.localeCompare(a.dueDate || '') || 0));
    const selected = candidates[0];
    return { memberId, code: selected.code, invoiceNumber: selected.invoice.invoiceNumber ?? null,
      dueDate: selected.dueDate, outstanding: selected.outstanding,
      daysPastDue: selected.code === 'overdue' ? selected.lateDays : null,
      beyondGrace: selected.code === 'overdue' && selected.lateDays >= 14 };
  });
}

module.exports = { memberBillingStatuses, osloToday };

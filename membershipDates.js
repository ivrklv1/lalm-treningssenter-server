const OSLO_TIME_ZONE = 'Europe/Oslo';

function osloDate(instant) {
  if (typeof instant !== 'string' || !/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(instant)) return null;
  const date = new Date(instant);
  if (!Number.isFinite(date.getTime())) return null;
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: OSLO_TIME_ZONE, year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(date);
  const value = type => parts.find(part => part.type === type)?.value;
  return `${value('year')}-${value('month')}-${value('day')}`;
}

function addCalendarMonths(startDate, months) {
  const [year, month, day] = startDate.split('-').map(Number);
  const target = new Date(Date.UTC(year, month - 1 + months, 1));
  const lastDay = new Date(Date.UTC(target.getUTCFullYear(), target.getUTCMonth() + 1, 0)).getUTCDate();
  target.setUTCDate(Math.min(day, lastDay));
  return target.toISOString().slice(0, 10);
}

function datesForPaidMembership(paymentTime, bindingMonths) {
  const membershipStartDate = osloDate(paymentTime);
  if (!membershipStartDate) return null;
  const months = Number(bindingMonths);
  if (!Number.isSafeInteger(months) || months < 0 || months > 120) return null;
  return {
    membershipStartDate,
    bindingEndDate: months > 0 ? addCalendarMonths(membershipStartDate, months) : null,
    bindingMonthsAtStart: months,
  };
}

function shouldReplaceMembershipDates(member, orderId, paymentTime, nextStartDate, previousPaymentTime) {
  if (!member.membershipStartDate) return true;
  if (member.membershipStartOrderId === orderId) return false;
  if (nextStartDate < member.membershipStartDate) return false;
  if (nextStartDate > member.membershipStartDate) return true;
  if (!member.membershipStartOrderId) return true;
  const previous = Date.parse(previousPaymentTime);
  const next = Date.parse(paymentTime);
  return Number.isFinite(previous) && Number.isFinite(next) && next > previous;
}

function verifiedPaymentTime(details, order) {
  if (!details || details.orderId !== order.orderId) return null;
  const amount = Number(order.amount);
  const captured = Number(details.transactionSummary?.capturedAmount);
  const refunded = Number(details.transactionSummary?.refundedAmount || 0);
  if (!Number.isSafeInteger(amount) || amount <= 0 ||
      !Number.isSafeInteger(captured) || captured < amount ||
      !Number.isSafeInteger(refunded) || refunded !== 0) return null;
  if (!Array.isArray(details.transactionLogHistory)) return null;
  const captures = details.transactionLogHistory.filter(entry =>
    entry?.operationSuccess === true &&
    ['SALE', 'CAPTURE'].includes(String(entry.operation).toUpperCase()) &&
    Number(entry.amount) >= amount &&
    osloDate(entry.timeStamp)
  );
  if (!captures.length) return null;
  captures.sort((a, b) => Date.parse(a.timeStamp) - Date.parse(b.timeStamp));
  return captures[0].timeStamp;
}

module.exports = { datesForPaidMembership, shouldReplaceMembershipDates, verifiedPaymentTime };

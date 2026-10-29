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

module.exports = { datesForPaidMembership };

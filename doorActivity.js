const fs = require('node:fs');
const readline = require('node:readline');

const WEEKS = 4;
const FIRST_HOUR = 5;
const HOURS = 18;

function dateAtNoon(date) {
  return new Date(`${date}T12:00:00Z`);
}

function addDays(date, days) {
  const value = dateAtNoon(date);
  value.setUTCDate(value.getUTCDate() + days);
  return value.toISOString().slice(0, 10);
}

function mondayOf(date) {
  return addDays(date, -(dateAtNoon(date).getUTCDay() + 6) % 7);
}

function osloDate(now) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Oslo', year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(now);
  const value = type => parts.find(part => part.type === type)?.value;
  return `${value('year')}-${value('month')}-${value('day')}`;
}

async function doorActivitySummary({ filename, now = new Date() }) {
  const firstMonday = addDays(mondayOf(osloDate(now)), -7 * WEEKS);
  const endExclusive = addDays(firstMonday, 7 * WEEKS);
  const counts = Array.from({ length: 7 }, () => Array(HOURS).fill(0));
  let totalOpenings = 0;

  if (fs.existsSync(filename)) {
    const input = fs.createReadStream(filename, { encoding: 'utf8' });
    const lines = readline.createInterface({ input, crlfDelay: Infinity });
    try {
      for await (const line of lines) {
        if (!/\baction=OPEN_(?:MEMBER|DROPIN|LEGACY)\b/.test(line)) continue;
        const match = /^(\d{1,2})\.(\d{1,2})\.(\d{4}),?\s+(\d{1,2}):/.exec(line);
        if (!match) continue;
        const [, day, month, year, hour] = match.map(Number);
        const date = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
        if (date < firstMonday || date >= endExclusive || hour < FIRST_HOUR || hour >= FIRST_HOUR + HOURS) continue;
        const weekday = (dateAtNoon(date).getUTCDay() + 6) % 7;
        counts[weekday][hour - FIRST_HOUR]++;
        totalOpenings++;
      }
    } finally {
      lines.close();
      input.destroy();
    }
  }

  return {
    available: totalOpenings > 0,
    source: 'door-openings',
    from: firstMonday,
    through: addDays(endExclusive, -1),
    weeks: WEEKS,
    firstHour: FIRST_HOUR,
    totalOpenings,
    days: counts.map(day => day.map(count => count / WEEKS)),
  };
}

module.exports = { doorActivitySummary };

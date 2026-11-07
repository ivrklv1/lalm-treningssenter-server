const fs = require('node:fs');
const readline = require('node:readline');

const FROM = '2026-10-05';
const CUTOVER = '2026-10-30';
const EXPECTED_VISITS = 298;
const VISIT_WINDOW_MS = 30 * 60 * 1000;

async function readVisitHistory(filename) {
  if (!fs.existsSync(filename)) return null;

  const rows = [];
  const input = fs.createReadStream(filename, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      const action = line.match(/\baction=OPEN_(MEMBER|DROPIN|LEGACY)\s*$/);
      const stamp = line.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4}),?\s+(\d{1,2}):(\d{2}):(\d{2})\s/);
      if (!action || !stamp) continue;

      const [, day, month, year, hour, minute, second] = stamp.map(Number);
      const date = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
      if (date < FROM || date >= CUTOVER || hour < 5 || hour >= 23) continue;

      const value = (line.slice(stamp[0].length).match(/^(?:name|email)=(.*?)\s+door=/)?.[1] || '')
        .normalize('NFC').trim().toLowerCase().replace(/\s+/g, ' ');
      const email = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      const phone = /^(?:(?:\+47|0047)\s*)?(?:\d\s*){8}$/.test(value);
      const name = /^\p{L}.*\s.*\p{L}$/u.test(value) && !/^(ukjent|drop[ -]?in)\b/.test(value);
      const group = action[1] === 'DROPIN' ? 'dropin' : 'member';
      let key = null;
      if (email) key = `${group}:contact:${value}`;
      else if (phone) key = `${group}:contact:${value.replace(/\s/g, '').slice(-8)}`;
      else if (name) key = `${group}:name:${value}`;

      rows.push({ key, time: Date.UTC(year, month - 1, day, hour, minute, second),
        bucket: `${date}T${String(hour).padStart(2, '0')}` });
    }
  } finally {
    lines.close();
    input.destroy();
  }

  rows.sort((a, b) => a.time - b.time);
  const hours = {};
  const lastVisit = new Map();
  let visits = 0;
  for (const { key, time, bucket } of rows) {
    const previous = key ? lastVisit.get(key) : undefined;
    if (previous !== undefined && time - previous < VISIT_WINDOW_MS) continue;
    if (key) lastVisit.set(key, time);
    hours[bucket] = (hours[bucket] || 0) + 1;
    visits++;
  }
  if (visits !== EXPECTED_VISITS) return null;
  return { from: FROM, cutover: CUTOVER, hours };
}

module.exports = { readVisitHistory };

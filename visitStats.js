const fs = require('node:fs');
const path = require('node:path');

const DEDUP_MS = 30 * 60 * 1000;
const WEEKS = 8;
const FIRST_HOUR = 5;
const LAST_HOUR = 22;

function osloParts(instant) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Oslo', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(instant);
  const value = type => parts.find(part => part.type === type)?.value;
  return { date: `${value('year')}-${value('month')}-${value('day')}`, hour: Number(value('hour')) };
}

function dateAtUtcNoon(value) {
  return new Date(`${value}T12:00:00Z`);
}

function addDays(value, days) {
  const date = dateAtUtcNoon(value);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function mondayOf(value) {
  const weekday = dateAtUtcNoon(value).getUTCDay();
  return addDays(value, -(weekday === 0 ? 6 : weekday - 1));
}

function completeWeeksSince(firstEventDate, nowDate) {
  const firstFullMonday = addDays(mondayOf(firstEventDate), 7);
  const currentMonday = mondayOf(nowDate);
  return Math.max(0, Math.floor((dateAtUtcNoon(currentMonday) - dateAtUtcNoon(firstFullMonday)) / (7 * 86400000)));
}

function createVisitStats({ dataDir }) {
  const filename = path.join(dataDir, 'visit-hours.json');
  const lastSeen = new Map();

  function read() {
    if (!fs.existsSync(filename)) return { version: 1, firstEventDate: null, hours: {} };
    const data = JSON.parse(fs.readFileSync(filename, 'utf8'));
    if (data.version !== 1 || !data.hours || typeof data.hours !== 'object') {
      throw new Error('Invalid visit-hours.json');
    }
    return data;
  }

  function write(data) {
    const temporary = `${filename}.${process.pid}.tmp`;
    try {
      fs.writeFileSync(temporary, JSON.stringify(data), { mode: 0o600 });
      fs.renameSync(temporary, filename);
    } finally {
      if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    }
  }

  function record({ visitorKey, at = new Date() }) {
    if (!visitorKey) return false;
    const instant = new Date(at);
    if (!Number.isFinite(instant.getTime())) return false;
    const { date, hour } = osloParts(instant);
    if (hour < FIRST_HOUR || hour > LAST_HOUR) return false;

    for (const [key, seenAt] of lastSeen) {
      if (instant.getTime() - seenAt >= DEDUP_MS) lastSeen.delete(key);
    }
    const previous = lastSeen.get(visitorKey);
    if (previous != null && instant.getTime() - previous < DEDUP_MS) return false;

    const data = read();
    if (!data.firstEventDate) data.firstEventDate = date;
    const oldestDate = addDays(date, -12 * 7);
    for (const key of Object.keys(data.hours)) {
      if (key.slice(0, 10) < oldestDate) delete data.hours[key];
    }
    const bucket = `${date}T${String(hour).padStart(2, '0')}`;
    data.hours[bucket] = (data.hours[bucket] || 0) + 1;
    write(data);
    lastSeen.set(visitorKey, instant.getTime());
    const expiry = setTimeout(() => {
      if (lastSeen.get(visitorKey) === instant.getTime()) lastSeen.delete(visitorKey);
    }, DEDUP_MS);
    expiry.unref?.();
    return true;
  }

  function summary(now = new Date()) {
    const data = read();
    const { date: nowDate } = osloParts(new Date(now));
    const completeWeeks = data.firstEventDate ? completeWeeksSince(data.firstEventDate, nowDate) : 0;
    if (completeWeeks < WEEKS) {
      return { available: false, weeksCollected: completeWeeks, weeksRequired: WEEKS };
    }

    const firstMonday = addDays(mondayOf(nowDate), -7 * WEEKS);
    const days = Array.from({ length: 7 }, (_, weekday) =>
      Array.from({ length: LAST_HOUR - FIRST_HOUR + 1 }, (_, offset) => {
        const hour = String(FIRST_HOUR + offset).padStart(2, '0');
        let total = 0;
        for (let week = 0; week < WEEKS; week++) {
          const date = addDays(firstMonday, week * 7 + weekday);
          total += data.hours[`${date}T${hour}`] || 0;
        }
        return Math.round(total / WEEKS * 10) / 10;
      })
    );
    return {
      available: true,
      label: 'Gjennomsnittlige registrerte døråpninger per time',
      from: firstMonday,
      through: addDays(mondayOf(nowDate), -1),
      weeks: WEEKS,
      firstHour: FIRST_HOUR,
      days,
    };
  }

  return { record, summary };
}

module.exports = { createVisitStats };

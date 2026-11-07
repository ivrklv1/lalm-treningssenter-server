const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createVisitStats } = require('../visitStats');
const { readVisitHistory } = require('../visitHistory');

test('combines verified log history with live counts exactly at the cutover', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-visits-'));
  try {
    const log = path.join(dataDir, 'access.log');
    const line = (date, time, name) => `${date}, ${time} name=${name} door=styrkerom action=OPEN_MEMBER\n`;
    const historical = Array.from({ length: 298 }, (_, index) => line('05.10.2026', '08:00:00', `Test Person${String.fromCharCode(0x4e00 + index)}`));
    fs.writeFileSync(log, historical.slice(1).join(''));
    assert.equal(await readVisitHistory(log), null);
    fs.writeFileSync(log, historical.join('') + line('05.10.2026', '08:20:00', 'Test Person一') +
      line('30.10.2026', '08:00:00', 'Test Person一'));
    const history = await readVisitHistory(log);
    assert.deepEqual(history.hours, { '2026-10-05T08': 298 });
    fs.writeFileSync(path.join(dataDir, 'visit-hours.json'), JSON.stringify({
      version: 1, firstEventDate: '2026-10-30', hours: { '2026-10-30T08': 13, '2026-11-01T08': 8 },
    }));
    const stats = createVisitStats({ dataDir });
    const now = '2026-11-07T12:00:00Z';
    assert.equal(stats.summary(now).available, false);
    const result = stats.summary(now, history);
    assert.equal(result.available, true);
    assert.equal(result.historicalThrough, '2026-10-29');
    assert.equal(result.days[0][3], 298 / 4);
    assert.equal(result.days[4][3], 13 / 4);
    assert.equal(result.days[6][3], 8 / 4);
    assert.equal(stats.summary('2026-11-30T12:00:00Z').historicalThrough, undefined);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('stores only hourly totals and ignores repeated opens within 30 minutes', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-visits-'));
  try {
    const stats = createVisitStats({ dataDir });
    assert.equal(stats.record({ visitorKey: 'member-1', at: '2026-10-26T16:10:00Z' }), true);
    assert.equal(stats.record({ visitorKey: 'member-1', at: '2026-10-26T16:25:00Z' }), false);
    assert.equal(stats.record({ visitorKey: 'member-2', at: '2026-10-26T16:25:00Z' }), true);
    assert.equal(stats.record({ visitorKey: 'member-1', at: '2026-10-26T16:41:00Z' }), true);
    const saved = fs.readFileSync(path.join(dataDir, 'visit-hours.json'), 'utf8');
    assert.deepEqual(JSON.parse(saved).hours, { '2026-10-26T17': 3 });
    assert.equal(saved.includes('member-1'), false);
    assert.equal(stats.summary('2026-10-29T12:00:00Z').available, false);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('averages each weekday and hour over four completed weeks, including zero days', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-visits-'));
  try {
    const stats = createVisitStats({ dataDir });
    stats.record({ visitorKey: 'start', at: '2026-01-01T10:00:00Z' });
    for (let week = 0; week < 4; week++) {
      const date = new Date(Date.UTC(2026, 0, 5 + week * 7, 9, 0));
      stats.record({ visitorKey: `visitor-${week}`, at: date });
    }
    assert.deepEqual(stats.summary('2026-02-01T12:00:00Z'), {
      available: false, weeksCollected: 3, weeksRequired: 4,
    });
    const result = stats.summary('2026-02-02T12:00:00Z');
    assert.equal(result.available, true);
    assert.equal(result.from, '2026-01-05');
    assert.equal(result.through, '2026-02-01');
    assert.equal(result.weeks, 4);
    assert.equal(result.days[0][5], 1); // Monday 10:00–11:00 Oslo
    assert.equal(result.days[1][5], 0);
    assert.equal(result.days.length, 7);
    assert.equal(result.days[0].length, 18);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('removes hourly totals older than twelve weeks', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-visits-'));
  try {
    const stats = createVisitStats({ dataDir });
    stats.record({ visitorKey: 'old', at: '2026-01-01T10:00:00Z' });
    stats.record({ visitorKey: 'new', at: '2026-04-10T10:00:00Z' });
    const saved = JSON.parse(fs.readFileSync(path.join(dataDir, 'visit-hours.json'), 'utf8'));
    assert.equal(Object.keys(saved.hours).length, 1);
    assert.equal(saved.hours['2026-04-10T12'], 1);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

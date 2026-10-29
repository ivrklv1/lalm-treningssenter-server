const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createVisitStats } = require('../visitStats');

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

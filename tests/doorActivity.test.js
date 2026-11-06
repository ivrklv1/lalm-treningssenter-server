const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { doorActivitySummary } = require('../doorActivity');

test('counts only successful openings in the last four complete weeks, without exposing log details', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-door-activity-'));
  try {
    const filename = path.join(directory, 'access.log');
    fs.writeFileSync(filename, [
      '04.10.2026, 08:00:00 name=Outside door=styrkerom action=OPEN_MEMBER',
      '05.10.2026, 08:10:00 name=Test door=styrkerom action=OPEN_MEMBER',
      '05.10.2026, 08:25:00 name=Test door=styrkerom action=OPEN_MEMBER',
      '09.10.2026, 18:00:00 email=synthetic@example.invalid door=styrkerom action=OPEN_LEGACY',
      '10.10.2026, 12:00:00 name=Guest door=styrkerom action=OPEN_DROPIN',
      '12.10.2026, 08:00:00 name=Test door=styrkerom action=DENY',
      '01.11.2026, 22:00:00 name=Test door=styrkerom action=OPEN_MEMBER',
      '02.11.2026, 08:00:00 name=Outside door=styrkerom action=OPEN_MEMBER',
      '[2026-10-05T08:00:00Z] VIPPS_CHECKOUT_OK orderId=ignored',
    ].join('\n'));
    const result = await doorActivitySummary({ filename, now: new Date('2026-11-06T12:00:00Z') });
    assert.equal(result.totalOpenings, 5);
    assert.equal(result.from, '2026-10-05');
    assert.equal(result.through, '2026-11-01');
    assert.equal(result.days[0][3], 0.5);
    assert.equal(result.days[4][13], 0.25);
    assert.equal(result.days[5][7], 0.25);
    assert.equal(result.days[6][17], 0.25);
    assert.equal(JSON.stringify(result).includes('synthetic@example.invalid'), false);
    assert.equal(JSON.stringify(result).includes('name='), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('reports unavailable if the log has no openings in the period', async () => {
  const result = await doorActivitySummary({ filename: '/nonexistent/access.log', now: new Date('2026-11-06T12:00:00Z') });
  assert.equal(result.available, false);
  assert.equal(result.totalOpenings, 0);
});

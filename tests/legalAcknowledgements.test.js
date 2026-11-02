const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createLegalDocuments } = require('../legalDocuments');
const { createLegalAcknowledgements } = require('../legalAcknowledgements');
const { createLegalMemberSession } = require('../legalMemberSession');

test('required versions are tracked per member and separately for terms and privacy', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-legal-ack-'));
  try {
    const legal = createLegalDocuments({ dataDir, now: () => '2026-11-02T00:00:00.000Z' });
    const acknowledgements = createLegalAcknowledgements({ dataDir, legalDocuments: legal, now: () => '2026-11-03T00:00:00.000Z' });
    assert.deepEqual(acknowledgements.required('member-a'), []);
    legal.saveDraft('terms', { expectedRevision: 0, version: 'v1', title: 'Vilkår', content: 'Innhold', requiresAcknowledgement: true }, 'admin');
    legal.publish('terms', 1, 'admin');
    legal.saveDraft('privacy', { expectedRevision: 0, version: 'p1', title: 'Personvern', content: 'Innhold', requiresAcknowledgement: false }, 'admin');
    legal.publish('privacy', 1, 'admin');
    assert.deepEqual(acknowledgements.required('member-a').map(item => item.version), ['v1']);
    assert.throws(() => acknowledgements.acknowledge('member-a', [{ kind: 'terms', version: 'old' }]), { code: 'document_changed_reload' });
    acknowledgements.acknowledge('member-a', [{ kind: 'terms', version: 'v1' }]);
    assert.deepEqual(acknowledgements.required('member-a'), []);
    assert.equal(acknowledgements.required('member-b').length, 1);
    legal.saveDraft('terms', { expectedRevision: 2, version: 'v2', title: 'Nye vilkår', content: 'Ny tekst', requiresAcknowledgement: true }, 'admin');
    legal.publish('terms', 3, 'admin');
    assert.deepEqual(acknowledgements.required('member-a').map(item => item.version), ['v2']);
    const saved = JSON.parse(fs.readFileSync(path.join(dataDir, 'legal-acknowledgements.json'), 'utf8'));
    assert.equal(saved.members['member-a'].terms.acknowledgedAt, '2026-11-03T00:00:00.000Z');
  } finally { fs.rmSync(dataDir, { recursive: true, force: true }); }
});

test('member session cannot be forged, expires, and survives a server restart', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-legal-session-'));
  try {
    let clock = Date.UTC(2026, 10, 2);
    const first = createLegalMemberSession({ dataDir, now: () => clock });
    const token = first.issue('member-a');
    assert.equal(first.verify(token), 'member-a');
    assert.equal(createLegalMemberSession({ dataDir, now: () => clock }).verify(token), 'member-a');
    const parts = token.split('.');
    parts[1] = Buffer.from(JSON.stringify({ id: 'member-b', exp: clock + 86400000 })).toString('base64url');
    assert.equal(first.verify(parts.join('.')), null);
    assert.equal(first.verify(token.slice(0, -1) + (token.endsWith('x') ? 'y' : 'x')), null);
    clock += 91 * 86400000;
    assert.equal(first.verify(token), null);
  } finally { fs.rmSync(dataDir, { recursive: true, force: true }); }
});

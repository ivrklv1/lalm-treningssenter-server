const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { createLegalDocuments } = require('../legalDocuments');

test('a damaged document store is never replaced with empty legal text', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-legal-damaged-'));
  try {
    const file = path.join(dataDir, 'legal-documents.json');
    fs.writeFileSync(file, '{damaged');
    const store = createLegalDocuments({ dataDir });
    assert.throws(() => store.saveDraft('terms', {
      expectedRevision: 0, version: 'v1', title: 'Title', content: 'Text',
    }, 'editor'));
    assert.equal(fs.readFileSync(file, 'utf8'), '{damaged');
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('legal drafts stay private until publication, preserve history, and reject stale edits', async () => {
  const root = path.resolve(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lalm-legal-admin-'));
  const socket = net.createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  let output = '';
  const child = spawn(process.execPath,
    ['--require', path.join(__dirname, 'blockExternal.cjs'), path.join(root, 'server.js')], {
      cwd: root,
      env: {
        PATH: process.env.PATH,
        NODE_PATH: path.resolve(root, '../legal-test-server/node_modules'),
        DATA_DIR: dataDir, PORT: String(port),
        ADMIN_USER: 'editor', ADMIN_PASS: 'synthetic-password',
        TRIPLETEX_RETRY_INTERVAL_MINUTES: '0',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  child.stdout.on('data', data => { output += data; });
  child.stderr.on('data', data => { output += data; });
  const base = `http://127.0.0.1:${port}`;
  const auth = `Basic ${Buffer.from('editor:synthetic-password').toString('base64')}`;
  const change = (route, method, body) => fetch(base + route, {
    method, headers: { Authorization: auth, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  try {
    for (let i = 0; i < 80 && !output.includes(`Server kjører på http://localhost:${port}`); i++) {
      if (child.exitCode !== null) throw new Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.match(output, /Server kjører på/);
    assert.equal((await fetch(base + '/admin/legal')).status, 401);
    assert.equal((await fetch(base + '/admin/legal/terms/draft', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: '{}',
    })).status, 401);
    assert.equal((await fetch(base + '/api/legal/terms')).status, 404);
    const initial = await fetch(base + '/api/legal/acknowledgements/required');
    assert.equal(initial.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await initial.json(), { ok: true, required: [] });

    const draftResponse = await change('/admin/legal/terms/draft', 'PUT', {
      expectedRevision: 0, version: 'v1', title: 'Testvilkår', content: 'Første tekst',
    });
    assert.equal(draftResponse.status, 200);
    const draft = await draftResponse.json();
    assert.equal(draft.revision, 1);
    assert.equal(draft.published, null);
    assert.equal((await fetch(base + '/api/legal/terms')).status, 404);
    assert.equal((await fetch(base + '/api/legal/privacy')).status, 404);

    const publishedResponse = await change('/admin/legal/terms/publish', 'POST', { expectedRevision: 1 });
    assert.equal(publishedResponse.status, 200);
    const published = await publishedResponse.json();
    assert.equal(published.history.length, 1);
    assert.equal(published.published.version, 'v1');
    assert.equal((await (await fetch(base + '/api/legal/terms')).json()).content, 'Første tekst');

    assert.equal((await change('/admin/legal/terms/draft', 'PUT', {
      expectedRevision: 1, version: 'v2', title: 'Nye vilkår', content: 'Andre tekst',
    })).status, 409);
    assert.equal((await change('/admin/legal/terms/draft', 'PUT', {
      expectedRevision: 2, version: 'v2', title: 'Nye vilkår', content: 'Andre tekst',
    })).status, 200);
    assert.equal((await (await fetch(base + '/api/legal/terms')).json()).content, 'Første tekst');
    assert.equal((await change('/admin/legal/terms/publish', 'POST', { expectedRevision: 3 })).status, 200);
    const adminResponse = await fetch(base + '/admin/legal', { headers: { Authorization: auth } });
    assert.equal(adminResponse.headers.get('cache-control'), 'private, no-store');
    const admin = await adminResponse.json();
    assert.equal(admin.acknowledgementsReady, false);
    assert.deepEqual(admin.terms.history.map(item => item.version), ['v1', 'v2']);
    assert.equal(admin.terms.history[0].content, 'Første tekst');
    assert.equal(admin.privacy.published, null);
    assert.equal((await (await fetch(base + '/api/legal/terms')).json()).content, 'Andre tekst');
    assert.equal((await change('/admin/legal/terms/draft', 'PUT', {
      expectedRevision: 4, version: 'v2', title: 'Gjenta', content: 'Tredje tekst',
    })).status, 200);
    assert.equal((await change('/admin/legal/terms/publish', 'POST', { expectedRevision: 5 })).status, 409);
    assert.equal((await (await fetch(base + '/api/legal/terms')).json()).content, 'Andre tekst');

    assert.equal((await change('/admin/legal/privacy/draft', 'PUT', {
      expectedRevision: 0, version: 'p1', title: 'Personvern', content: 'Privat tekst',
    })).status, 200);
    assert.equal((await change('/admin/legal/privacy/publish', 'POST', { expectedRevision: 1 })).status, 200);
    assert.equal((await (await fetch(base + '/api/legal/privacy')).json()).version, 'p1');
    const publicDocuments = await (await fetch(base + '/api/legal')).json();
    assert.equal(publicDocuments.terms.version, 'v2');
    assert.equal(publicDocuments.privacy.version, 'p1');
    assert.equal(publicDocuments.terms.publishedBy, undefined);

    assert.equal((await change('/admin/legal/terms/draft', 'PUT', {
      expectedRevision: 5, version: 'v3', title: 'Nye vilkår', content: 'Ny testtekst',
      requiresAcknowledgement: true,
    })).status, 200);
    const premature = await change('/admin/legal/terms/publish', 'POST', { expectedRevision: 6 });
    assert.equal(premature.status, 409);
    assert.equal((await premature.json()).error, 'acknowledgement_app_not_ready');
    assert.equal((await (await fetch(base + '/api/legal/terms')).json()).version, 'v2');

    const onDisk = JSON.parse(fs.readFileSync(path.join(dataDir, 'legal-documents.json')));
    assert.equal(onDisk.terms.published.version, 'v2');
    assert.equal(onDisk.terms.history.length, 2);
    assert.equal(onDisk.privacy.published.version, 'p1');

    // A previously published requirement stays on disk when the feature is paused.
    createLegalDocuments({ dataDir }).publish('terms', 6, 'editor');
    assert.equal((await (await fetch(base + '/api/legal/terms')).json()).version, 'v3');
    assert.deepEqual(await (await fetch(base + '/api/legal/acknowledgements/required')).json(),
      { ok: true, required: [] });
    assert.deepEqual(await (await fetch(base + '/api/legal/acknowledgements/pending')).json(),
      { ok: true, pending: [] });
    assert.equal((await change('/api/legal/acknowledgements', 'POST', { documents: [] })).status, 409);
  } finally {
    child.kill('SIGTERM');
    await new Promise(resolve => child.once('exit', resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

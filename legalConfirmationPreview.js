const fs = require('node:fs');
const path = require('node:path');
const { createLegalDocuments, LegalDocumentError } = require('./legalDocuments');
const { createLegalAcknowledgements } = require('./legalAcknowledgements');

const fixtures = [
  { kind: 'terms', version: 'TEST-VILKÅR-2', title: 'Medlemsvilkår – TEST',
    content: 'Dette er et oppdiktet dokument for testkontoen. Dokumentet oppretter ingen medlemsavtale.',
    requiresAcknowledgement: false },
  { kind: 'privacy', version: 'TEST-PERSONVERN-2', title: 'Personvernerklæring – TEST',
    content: 'Dette er en oppdiktet personvernerklæring for testkontoen. Knappen nederst bekrefter at du har lest denne testteksten.',
    requiresAcknowledgement: true },
];

function createLegalConfirmationPreview({ dataDir, verifySession }) {
  const directory = path.join(dataDir, 'legal-confirmation-preview');
  const documents = createLegalDocuments({ dataDir: directory });
  const acknowledgements = createLegalAcknowledgements({ dataDir: directory, legalDocuments: documents });

  function prepareFixtures() {
    fs.mkdirSync(directory, { recursive: true });
    for (const { kind, ...fixture } of fixtures) {
      const current = documents.read()[kind];
      if (current.history.some(item => item.version === fixture.version)) continue;
      const saved = documents.saveDraft(kind, { ...fixture, expectedRevision: current.revision }, 'preview');
      documents.publish(kind, saved.revision, 'preview');
    }
  }

  return (req, res, next) => {
    const route = req.path;
    const read = req.method === 'GET';
    const pending = read && route === '/api/legal/acknowledgements/pending';
    const submit = req.method === 'POST' && route === '/api/legal/acknowledgements';
    const required = read && route === '/api/legal/acknowledgements/required';
    const document = read && ['/api/legal', '/api/legal/terms', '/api/legal/privacy'].includes(route);
    if (!pending && !submit && !required && !document) return next();

    res.set('Cache-Control', 'private, no-store');
    try {
      if (pending || submit) {
        const token = /^Bearer (.+)$/.exec(req.get('authorization') || '')?.[1];
        const memberId = verifySession(token);
        if (memberId !== 'legal-test-member') return res.status(401).json({ ok: false, error: 'login_required' });
        prepareFixtures();
        if (pending) return res.json({ ok: true, pending: acknowledgements.required(memberId) });
        return res.json({ ok: true, ...acknowledgements.acknowledge(memberId, req.body?.documents) });
      }
      prepareFixtures();
      if (required) {
        const stored = documents.read();
        return res.json({ ok: true, required: fixtures.flatMap(({ kind }) => {
          const published = stored[kind].published;
          return published?.requiresAcknowledgement ? [{ kind, version: published.version }] : [];
        }) });
      }
      if (route === '/api/legal') return res.json({
        terms: documents.publicDocument('terms'), privacy: documents.publicDocument('privacy'),
      });
      return res.json(documents.publicDocument(route.split('/').at(-1)));
    } catch (error) {
      if (error instanceof LegalDocumentError) return res.status(error.status).json({ ok: false, error: error.code });
      console.error('Bekreftelsestest:', error.message);
      return res.status(503).json({ ok: false, error: 'legal_preview_unavailable' });
    }
  };
}

module.exports = { createLegalConfirmationPreview };

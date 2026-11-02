const fs = require('node:fs');
const path = require('node:path');

const KINDS = new Set(['terms', 'privacy']);

class LegalDocumentError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function emptyDocument() {
  return { revision: 0, draft: null, published: null, history: [] };
}

function createLegalDocuments({ dataDir, now = () => new Date().toISOString() }) {
  const file = path.join(dataDir, 'legal-documents.json');

  function read() {
    if (!fs.existsSync(file)) {
      return { schemaVersion: 1, terms: emptyDocument(), privacy: emptyDocument() };
    }
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (data?.schemaVersion !== 1 || !data.terms || !data.privacy ||
        !Array.isArray(data.terms.history) || !Array.isArray(data.privacy.history)) {
      throw new LegalDocumentError('legal_store_invalid', 503);
    }
    return data;
  }

  function write(data) {
    const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
    let fd;
    try {
      fd = fs.openSync(temporary, 'wx', 0o600);
      fs.writeFileSync(fd, JSON.stringify(data, null, 2));
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(temporary, file);
    } catch (error) {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.unlinkSync(temporary); } catch (_) {}
      throw error;
    }
  }

  function documentFor(data, kind) {
    if (!KINDS.has(kind)) throw new LegalDocumentError('invalid_document_type');
    return data[kind];
  }

  function checkRevision(document, expectedRevision) {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision !== document.revision) {
      throw new LegalDocumentError('document_changed_reload', 409);
    }
  }

  function saveDraft(kind, input, actor) {
    const data = read();
    const document = documentFor(data, kind);
    checkRevision(document, input?.expectedRevision);
    const version = typeof input?.version === 'string' ? input.version.trim() : '';
    const title = typeof input?.title === 'string' ? input.title.trim() : '';
    const content = typeof input?.content === 'string' ? input.content.trim() : '';
    if (!version || version.length > 80 || !title || title.length > 200 ||
        !content || content.length > 50000) {
      throw new LegalDocumentError('version_title_content_required');
    }
    if (input?.requiresAcknowledgement !== undefined && typeof input.requiresAcknowledgement !== 'boolean') {
      throw new LegalDocumentError('acknowledgement_choice_required');
    }
    document.draft = { version, title, content,
      requiresAcknowledgement: input.requiresAcknowledgement === true,
      updatedAt: now(), updatedBy: actor || 'admin' };
    document.revision += 1;
    write(data);
    return document;
  }

  function publish(kind, expectedRevision, actor) {
    const data = read();
    const document = documentFor(data, kind);
    checkRevision(document, expectedRevision);
    if (!document.draft) throw new LegalDocumentError('draft_required');
    if (document.history.some(item => item.version === document.draft.version)) {
      throw new LegalDocumentError('version_already_published', 409);
    }
    const published = {
      version: document.draft.version,
      title: document.draft.title,
      content: document.draft.content,
      requiresAcknowledgement: document.draft.requiresAcknowledgement === true,
      updatedAt: now(),
      publishedBy: actor || 'admin',
    };
    document.published = published;
    document.history.push(published);
    document.draft = null;
    document.revision += 1;
    write(data);
    return document;
  }

  function publicDocument(kind) {
    const document = documentFor(read(), kind).published;
    if (!document) throw new LegalDocumentError('document_not_published', 404);
    const { version, title, content, updatedAt } = document;
    return { version, title, content, updatedAt,
      requiresAcknowledgement: document.requiresAcknowledgement === true };
  }

  return { read, saveDraft, publish, publicDocument };
}

module.exports = { createLegalDocuments, LegalDocumentError };

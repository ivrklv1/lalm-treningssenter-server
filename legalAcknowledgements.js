const fs = require('node:fs');
const path = require('node:path');
const { LegalDocumentError } = require('./legalDocuments');

function createLegalAcknowledgements({ dataDir, legalDocuments, now = () => new Date().toISOString() }) {
  const file = path.join(dataDir, 'legal-acknowledgements.json');
  function read() {
    if (!fs.existsSync(file)) return { schemaVersion: 1, members: {} };
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (data?.schemaVersion !== 1 || !data.members || typeof data.members !== 'object' || Array.isArray(data.members)) {
      throw new LegalDocumentError('legal_acknowledgements_invalid', 503);
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
  function required(memberId) {
    const data = read();
    const legal = legalDocuments.read();
    return ['terms', 'privacy'].flatMap(kind => {
      const published = legal[kind].published;
      if (!published || published.requiresAcknowledgement !== true) return [];
      if (data.members[memberId]?.[kind]?.version === published.version) return [];
      return [{ kind, version: published.version, title: published.title }];
    });
  }
  function acknowledge(memberId, entries) {
    if (!Array.isArray(entries) || entries.length < 1 || entries.length > 2 ||
      entries.some(entry => !entry || !['terms', 'privacy'].includes(entry.kind) || typeof entry.version !== 'string') ||
      new Set(entries.map(entry => entry.kind)).size !== entries.length) {
      throw new LegalDocumentError('invalid_acknowledgement');
    }
    const legal = legalDocuments.read();
    for (const entry of entries) {
      const published = legal[entry.kind].published;
      if (!published || published.version !== entry.version || published.requiresAcknowledgement !== true) {
        throw new LegalDocumentError('document_changed_reload', 409);
      }
    }
    const data = read();
    const member = data.members[memberId] || {};
    const at = now();
    let changed = false;
    for (const entry of entries) {
      const previous = member[entry.kind];
      if (previous?.version === entry.version) continue;
      const history = Array.isArray(previous?.history) ? previous.history :
        previous?.version ? [{ version: previous.version, acknowledgedAt: previous.acknowledgedAt }] : [];
      history.push({ version: entry.version, acknowledgedAt: at });
      member[entry.kind] = { version: entry.version, acknowledgedAt: at, history };
      changed = true;
    }
    if (changed) {
      data.members[memberId] = member;
      write(data);
    }
    const acknowledgedAt = changed ? at : entries.map(entry => member[entry.kind].acknowledgedAt).sort().at(-1);
    return { acknowledgedAt, pending: required(memberId) };
  }
  return { required, acknowledge };
}

module.exports = { createLegalAcknowledgements };

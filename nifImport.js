const crypto = require('node:crypto');

const headers = ['fornavn', 'etternavn', 'e-post', 'tlf. mobil', 'kontingent'];

function parseRow(line, separator) {
  const quoted = /^"((?:[^"]|"")*)"$/;
  const fields = line.split(new RegExp(`${separator}(?=(?:[^"]*"[^"]*")*[^"]*$)`));
  return fields.map((value) => {
    const field = value.trim();
    const match = quoted.exec(field);
    if (match) return match[1].replace(/""/g, '"').trim();
    if (field.includes('"')) throw new Error('invalid_nif_csv');
    return field;
  });
}

function analyzeNifImport(csv, members, { normalizePhone, normalizeName, discountPlans, now }) {
  if (typeof csv !== 'string' || !csv.trim()) throw new Error('csv_required');

  const lines = csv.split(/\r?\n/);
  const separator = lines[0].includes('\t') ? '\t' : ';';
  const columns = parseRow(lines[0], separator).map((field) => field.toLowerCase());
  if (columns.length !== headers.length || !headers.every((field, index) => field === columns[index])) {
    throw new Error('invalid_nif_csv');
  }

  const updatedMembers = members.map((member) => ({ ...member }));
  const indexes = { email: new Map(), phone: new Map(), name: new Map() };
  const addIndex = (index, key, member) => {
    if (!key) return;
    const matches = index.get(key) || [];
    matches.push(member);
    index.set(key, matches);
  };
  const emailOf = (member) => String(member.email || '').trim().toLowerCase();
  const phoneOf = (member) => normalizePhone(member.phone || member.mobile || member.phoneFull || '');

  for (const member of updatedMembers) {
    addIndex(indexes.email, emailOf(member), member);
    addIndex(indexes.phone, phoneOf(member), member);
    addIndex(indexes.name, normalizeName(member.name || ''), member);
  }

  let totalRows = 0;
  const matchedMembers = new Set();
  const review = [];

  for (const [index, line] of lines.slice(1).entries()) {
    if (!line.trim()) continue;
    totalRows++;
    const fields = parseRow(line, separator);
    if (fields.length !== headers.length) {
      review.push({ row: index + 2, name: '', status: '', reason: 'invalid_row' });
      continue;
    }
    const [firstName, lastName, emailField, phoneField, status] = fields;
    const name = `${firstName} ${lastName}`.trim();
    const item = { row: index + 2, name, status };
    if (status.toLowerCase() !== 'betalt') {
      review.push({ ...item, reason: 'payment_unconfirmed' });
      continue;
    }

    const email = emailField.toLowerCase();
    const phone = normalizePhone(phoneField);
    const emailMatches = indexes.email.get(email) || [];
    const phoneMatches = indexes.phone.get(phone) || [];
    const nameMatches = indexes.name.get(normalizeName(name)) || [];
    const contactMatches = [...new Set([...emailMatches, ...phoneMatches])];
    const candidates = contactMatches.length ? contactMatches : nameMatches;
    const member = candidates[0];
    const conflictingName = contactMatches.length && nameMatches.length && !nameMatches.includes(member);
    const conflictingContacts = !contactMatches.length && member &&
      ((email && emailOf(member) && email !== emailOf(member)) ||
        (phoneField && phoneOf(member) && phone !== phoneOf(member)));

    if (candidates.length > 1 || conflictingName || conflictingContacts) {
      review.push({ ...item, reason: 'ambiguous' });
    } else if (!member) {
      review.push({ ...item, reason: 'no_match' });
    } else if (!discountPlans.includes(String(member.plan || '').trim().toLowerCase())) {
      review.push({ ...item, reason: 'other_plan' });
    } else {
      matchedMembers.add(member);
    }
  }

  if (!totalRows) throw new Error('invalid_nif_csv');

  let added = 0;
  for (const member of matchedMembers) {
    if (member.clubMember === true) continue;
    added++;
    member.clubMember = true;
    member.clubMemberSource = 'nif';
    member.clubMemberSyncedAt = now;
  }

  return {
    members: updatedMembers,
    summary: { totalRows, matched: matchedMembers.size, added, review },
    previewToken: crypto.createHash('sha256').update(JSON.stringify({ csv, members })).digest('hex'),
  };
}

module.exports = { analyzeNifImport };

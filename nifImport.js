const crypto = require('node:crypto');

function fingerprint(csv, members) {
  return crypto.createHash('sha256').update(JSON.stringify({ csv, members })).digest('hex');
}

function analyzeNifImport(csv, members, { normalizePhone, normalizeName, discountPlans, now }) {
  if (typeof csv !== 'string' || !csv.trim()) {
    throw new Error('csv_required');
  }

  const updatedMembers = members.map((member) => ({ ...member }));
  const indexes = { email: new Map(), phone: new Map(), name: new Map() };
  const addIndex = (index, key, member) => {
    if (!key) return;
    const matches = index.get(key) || [];
    matches.push(member);
    index.set(key, matches);
  };

  for (const member of updatedMembers) {
    addIndex(indexes.email, String(member.email || '').trim().toLowerCase(), member);
    addIndex(indexes.phone, normalizePhone(member.phone || member.mobile || member.phoneFull || ''), member);
    addIndex(indexes.name, normalizeName(member.name || ''), member);
  }

  let totalRows = 0;
  let activeRows = 0;
  let matched = 0;
  let unmatched = 0;
  let ambiguous = 0;
  const matchedMembers = new Set();

  for (const line of csv.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const fields = line.split(';').map((field) => field.trim());
    if (fields[0]?.toLowerCase() === 'fornavn' && line.toLowerCase().includes('medlemsstatus')) continue;
    if (fields.length < 6) continue;
    totalRows++;
    if (fields[5].toLowerCase() !== 'aktiv') continue;
    activeRows++;

    const email = fields[2].toLowerCase();
    const phone = normalizePhone(fields[3]);
    const name = normalizeName(`${fields[0]} ${fields[1]}`);
    const emailMatches = email ? indexes.email.get(email) || [] : [];
    const phoneMatches = phone ? indexes.phone.get(phone) || [] : [];
    const nameMatches = name ? indexes.name.get(name) || [] : [];
    const candidates = emailMatches.length ? emailMatches : phoneMatches.length ? phoneMatches : nameMatches;

    if (candidates.length > 1 ||
        (emailMatches.length === 1 && phoneMatches.length === 1 && emailMatches[0] !== phoneMatches[0])) {
      ambiguous++;
      continue;
    }
    const member = candidates[0];
    if (!member || !discountPlans.includes(member.plan)) {
      unmatched++;
      continue;
    }
    matchedMembers.add(member);
    matched++;
  }

  // An empty or wrong-format export must never clear the existing NIF flags.
  if (totalRows === 0 || activeRows === 0) {
    throw new Error('invalid_nif_csv');
  }
  if (matchedMembers.size === 0) {
    throw new Error('no_nif_matches');
  }

  let added = 0;
  let removed = 0;
  for (const member of updatedMembers) {
    if (matchedMembers.has(member)) {
      if (!member.clubMember || member.clubMemberSource !== 'nif') added++;
      member.clubMember = true;
      member.clubMemberSource = 'nif';
      member.clubMemberSyncedAt = now;
    } else if (member.clubMemberSource === 'nif') {
      removed++;
      member.clubMember = false;
      delete member.clubMemberSource;
      delete member.clubMemberSyncedAt;
    }
  }

  return {
    members: updatedMembers,
    summary: { totalRows, activeRows, matched, unmatched, ambiguous, added, removed },
    previewToken: fingerprint(csv, members),
  };
}

module.exports = { analyzeNifImport };

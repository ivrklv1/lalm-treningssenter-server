const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function createLegalMemberSession({ dataDir, now = () => Date.now() }) {
  const secretFile = path.join(dataDir, 'legal-member-session.key');
  let cachedSecret;
  function secret() {
    if (cachedSecret) return cachedSecret;
    if (process.env.LEGAL_MEMBER_SESSION_SECRET) {
      const value = process.env.LEGAL_MEMBER_SESSION_SECRET;
      if (Buffer.byteLength(value) < 32) throw new Error('legal_session_secret_too_short');
      cachedSecret = Buffer.from(value);
      return cachedSecret;
    }
    try {
      fs.writeFileSync(secretFile, crypto.randomBytes(32), { flag: 'wx', mode: 0o600 });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    const value = fs.readFileSync(secretFile);
    if (value.length !== 32) throw new Error('legal_session_secret_invalid');
    cachedSecret = value;
    return cachedSecret;
  }
  function signature(payload) {
    return crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
  }
  function issue(memberId) {
    if (typeof memberId !== 'string' || !memberId) throw new Error('member_id_required');
    const payload = Buffer.from(JSON.stringify({ id: memberId, exp: now() + 90 * 86400000 })).toString('base64url');
    return `legal1.${payload}.${signature(payload)}`;
  }
  function verify(token) {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0] !== 'legal1' || !/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
    const expected = Buffer.from(signature(parts[1]));
    const received = Buffer.from(parts[2]);
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) return null;
    try {
      const value = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      if (typeof value.id !== 'string' || !value.id || !Number.isSafeInteger(value.exp) || value.exp <= now()) return null;
      return value.id;
    } catch (_) {
      return null;
    }
  }
  return { issue, verify };
}

module.exports = { createLegalMemberSession };

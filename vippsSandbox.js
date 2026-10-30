const path = require('node:path');
const crypto = require('node:crypto');

const SANDBOX_PLAN = 'TEST_BINDING_12M';

function validateVippsSandbox(env) {
  if (env.VIPPS_SANDBOX_ONLY !== '1') return;

  const required = [
    'VIPPS_CLIENT_ID', 'VIPPS_CLIENT_SECRET', 'VIPPS_SUBSCRIPTION_KEY',
    'VIPPS_SANDBOX_ACCESS_TOKEN', 'SERVER_URL', 'VIPPS_CALLBACK_URL', 'DATA_DIR',
  ];
  const missing = required.filter(name => !env[name]);
  if (missing.length) throw new Error(`Vipps sandbox mangler: ${missing.join(', ')}`);
  if (env.VIPPS_ENV !== 'test' || env.VIPPS_MSN !== '411837') {
    throw new Error('Vipps sandbox krever VIPPS_ENV=test og VIPPS_MSN=411837');
  }
  if (env.VIPPS_SANDBOX_ACCESS_TOKEN.length < 32) {
    throw new Error('VIPPS_SANDBOX_ACCESS_TOKEN må ha minst 32 tegn');
  }

  const dataDir = path.resolve(env.DATA_DIR);
  if (!path.isAbsolute(env.DATA_DIR) ||
      !dataDir.startsWith('/tmp/lalm-vipps-sandbox')) {
    throw new Error('Vipps sandbox krever egen lagring under /tmp/lalm-vipps-sandbox');
  }

  const blocked = Object.keys(env).filter(name =>
    /^(EUROBATE_|TELL_|TRIPLETEX_|BACKUP_|AWS_|S3_)/.test(name) && env[name]
  );
  if (blocked.length) {
    throw new Error(`Vipps sandbox kan ikke starte med andre tjenestenøkler/oppsett: ${blocked.join(', ')}`);
  }

  const serverUrl = env.SERVER_URL.replace(/\/$/, '');
  if (!/^https:\/\/[a-z0-9.-]+$/i.test(serverUrl) ||
      /lalm-treningssenter-server(?:-legal-test|-1)?\.onrender\.com/i.test(serverUrl)) {
    throw new Error('Vipps sandbox krever egen HTTPS-adresse');
  }
  if (env.VIPPS_CALLBACK_URL !== `${serverUrl}/vipps/callback`) {
    throw new Error('Vipps sandbox callback må peke til egen tjeneste');
  }
}

function sandboxTokenMatches(candidate, expected) {
  const left = Buffer.from(String(candidate || ''));
  const right = Buffer.from(String(expected || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function vippsSandboxGate(env) {
  return (req, res, next) => {
    if (req.method === 'GET' && req.path === '/vipps/sandbox-return') return next();
    if (req.method === 'POST' && /^\/vipps\/callback\/v2\/payments\/[^/]+$/.test(req.path)) return next();
    if ((req.method === 'GET' && req.path === '/vipps/sandbox-auth-check') ||
        (req.method === 'POST' && req.path === '/vipps/checkout') ||
        (req.method === 'GET' && /^\/vipps\/order-status\/[^/]+$/.test(req.path))) {
      if (sandboxTokenMatches(req.get('x-sandbox-token'), env.VIPPS_SANDBOX_ACCESS_TOKEN)) return next();
      return res.status(403).json({ ok: false, error: 'sandbox_token_required' });
    }
    return res.status(404).json({ ok: false, error: 'sandbox_route_unavailable' });
  };
}

module.exports = { SANDBOX_PLAN, validateVippsSandbox, vippsSandboxGate };

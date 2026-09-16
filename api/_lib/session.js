import crypto from 'node:crypto';

export const SESSION_COOKIE = 'task8_session';
export const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

export function createSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}

export function hashSessionToken(token) {
  return crypto.createHash('sha256').update(String(token || ''), 'utf8').digest('hex');
}

export function readCookie(req, name) {
  const raw = String(req.headers.cookie || '');
  if (!raw) return null;

  for (const part of raw.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

function isHttps(req) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  if (forwardedProto) return forwardedProto === 'https';
  return !String(req.headers.host || '').startsWith('localhost');
}

export function setSessionCookie(req, res, token, maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000)) {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (isHttps(req)) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

export function clearSessionCookie(req, res) {
  const parts = [
    `${SESSION_COOKIE}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (isHttps(req)) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

import crypto from 'node:crypto';

export const REMOTE_LOGIN_TTL_MS = 2 * 60 * 1000;

export function createOpaqueSecret(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function hashOpaqueSecret(value) {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

export function safeSecretMatches(rawValue, expectedHash) {
  const actual = hashOpaqueSecret(rawValue);
  const a = Buffer.from(actual, 'utf8');
  const b = Buffer.from(String(expectedHash || ''), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function preview(value, head = 12, tail = 6) {
  const text = String(value || '');
  if (text.length <= head + tail + 1) return text;
  return `${text.slice(0, head)}…${text.slice(-tail)}`;
}

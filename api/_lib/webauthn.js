export const OWNER_ID = 'portfolio-owner';
export const RP_NAME = 'Network Security Profile';
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export function getWebAuthnConfig(req) {
  const forwardedHost = req.headers['x-forwarded-host'];
  const host = forwardedHost || req.headers.host;
  if (!host) throw new Error('요청 Host를 확인할 수 없습니다.');

  const forwardedProto = req.headers['x-forwarded-proto'];
  const local = host.startsWith('localhost') || host.startsWith('127.0.0.1');
  const protocol = forwardedProto || (local ? 'http' : 'https');

  const rpID = process.env.WEBAUTHN_RP_ID || host.split(':')[0];
  const origin = process.env.WEBAUTHN_ORIGIN || `${protocol}://${host}`;

  return { rpID, origin };
}

export function noStore(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
}

export function jsonError(res, status, error, message) {
  return res.status(status).json({ ok: false, error, message });
}

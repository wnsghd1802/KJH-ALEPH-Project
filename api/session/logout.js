import { getDB } from '../../lib/db.js';
import { OWNER_ID, noStore, jsonError } from '../../lib/webauthn.js';
import {
  SESSION_COOKIE,
  clearSessionCookie,
  hashSessionToken,
  readCookie,
} from '../../lib/session.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const token = readCookie(req, SESSION_COOKIE);
    if (token) {
      const db = getDB();
      await db
        .from('auth_sessions')
        .update({ revoked_at: new Date().toISOString() })
        .eq('owner_id', OWNER_ID)
        .eq('token_hash', hashSessionToken(token))
        .is('revoked_at', null);
    }

    clearSessionCookie(req, res);
    return res.status(200).json({ ok: true, loggedOut: true });
  } catch (error) {
    console.error('session/logout', error);
    return jsonError(res, 500, 'LOGOUT_FAILED', error.message || '로그아웃 처리에 실패했습니다.');
  }
}

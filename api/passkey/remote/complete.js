import { getDB } from '../../_lib/db.js';
import { OWNER_ID, noStore, jsonError } from '../../_lib/webauthn.js';
import { createSessionToken, hashSessionToken, setSessionCookie, SESSION_TTL_MS } from '../../_lib/session.js';
import { safeSecretMatches } from '../../_lib/remote-login.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const requestId = String(req.body?.requestId || '');
    const browserSecret = String(req.body?.browserSecret || '');
    const db = getDB();

    const { data: row, error } = await db
      .from('remote_login_requests')
      .select('id, browser_secret_hash, status, expires_at')
      .eq('id', requestId)
      .eq('owner_id', OWNER_ID)
      .maybeSingle();
    if (error) throw error;
    if (!row || !safeSecretMatches(browserSecret, row.browser_secret_hash)) {
      return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 요청을 찾을 수 없습니다.');
    }
    if (row.status !== 'approved') {
      return jsonError(res, 409, 'NOT_APPROVED', `휴대폰 승인이 완료되지 않았습니다. (${row.status})`);
    }
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      return jsonError(res, 410, 'REQUEST_EXPIRED', '로그인 요청이 만료되었습니다.');
    }

    const completedAt = new Date().toISOString();
    const { data: claimed, error: claimError } = await db
      .from('remote_login_requests')
      .update({ status: 'completed', completed_at: completedAt })
      .eq('id', row.id)
      .eq('status', 'approved')
      .select('id');
    if (claimError) throw claimError;
    if (!claimed || claimed.length !== 1) {
      return jsonError(res, 409, 'ALREADY_COMPLETED', '이미 완료된 로그인 요청입니다.');
    }

    const rawToken = createSessionToken();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    const { error: sessionError } = await db.from('auth_sessions').insert({
      owner_id: OWNER_ID,
      token_hash: hashSessionToken(rawToken),
      expires_at: expiresAt,
    });
    if (sessionError) throw sessionError;

    setSessionCookie(req, res, rawToken);
    return res.status(200).json({
      ok: true,
      verified: true,
      session: {
        type: 'HttpOnly cookie',
        display: 'task8_session=••••••••',
        expiresAt,
      },
      message: '휴대폰 승인을 확인해 PC 세션을 발급했습니다.',
    });
  } catch (error) {
    console.error('remote/complete', error);
    return jsonError(res, 500, 'REMOTE_COMPLETE_FAILED', error.message || 'PC 로그인 완료 처리에 실패했습니다.');
  }
}

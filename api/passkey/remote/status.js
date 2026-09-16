import { getDB } from '../../_lib/db.js';
import { OWNER_ID, noStore, jsonError } from '../../_lib/webauthn.js';
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
      .select('id, browser_secret_hash, status, expires_at, approved_at, completed_at')
      .eq('id', requestId)
      .eq('owner_id', OWNER_ID)
      .maybeSingle();
    if (error) throw error;
    if (!row || !safeSecretMatches(browserSecret, row.browser_secret_hash)) {
      return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 요청을 찾을 수 없습니다.');
    }

    if (row.status === 'pending' && new Date(row.expires_at).getTime() <= Date.now()) {
      await db.from('remote_login_requests').update({ status: 'expired' }).eq('id', row.id).eq('status', 'pending');
      row.status = 'expired';
    }

    return res.status(200).json({
      ok: true,
      status: row.status,
      approvedAt: row.approved_at,
      completedAt: row.completed_at,
      expiresAt: row.expires_at,
    });
  } catch (error) {
    console.error('remote/status', error);
    return jsonError(res, 500, 'REMOTE_STATUS_FAILED', error.message || '로그인 승인 상태 확인에 실패했습니다.');
  }
}

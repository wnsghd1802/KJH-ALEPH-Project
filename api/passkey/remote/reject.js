import { getDB } from '../../_lib/db.js';
import { OWNER_ID, noStore, jsonError } from '../../_lib/webauthn.js';
import { safeSecretMatches } from '../../_lib/remote-login.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const requestId = String(req.body?.requestId || '');
    const phoneToken = String(req.body?.phoneToken || '');
    const db = getDB();
    const { data: row, error } = await db
      .from('remote_login_requests')
      .select('id, phone_secret_hash, status')
      .eq('id', requestId)
      .eq('owner_id', OWNER_ID)
      .maybeSingle();
    if (error) throw error;
    if (!row || !safeSecretMatches(phoneToken, row.phone_secret_hash)) {
      return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 승인 요청을 찾을 수 없습니다.');
    }
    if (row.status !== 'pending') {
      return jsonError(res, 409, 'REQUEST_NOT_PENDING', '이미 처리된 로그인 요청입니다.');
    }

    await db.from('remote_login_requests').update({ status: 'rejected' }).eq('id', requestId).eq('status', 'pending');
    return res.status(200).json({ ok: true, rejected: true });
  } catch (error) {
    console.error('remote/reject', error);
    return jsonError(res, 500, 'REMOTE_REJECT_FAILED', error.message || '로그인 요청 거절 처리에 실패했습니다.');
  }
}

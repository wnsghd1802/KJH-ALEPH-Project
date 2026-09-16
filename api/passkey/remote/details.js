import { getDB } from '../../_lib/db.js';
import { OWNER_ID, noStore, jsonError } from '../../_lib/webauthn.js';
import { safeSecretMatches } from '../../_lib/remote-login.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const requestId = String(req.body?.requestId || '');
    const phoneToken = String(req.body?.phoneToken || '');
    if (!requestId || !phoneToken) return jsonError(res, 400, 'INVALID_REQUEST', '승인 요청 정보가 없습니다.');

    const db = getDB();
    const { data: row, error } = await db
      .from('remote_login_requests')
      .select('id, phone_secret_hash, options_json, request_device, status, expires_at, created_at')
      .eq('id', requestId)
      .eq('owner_id', OWNER_ID)
      .maybeSingle();
    if (error) throw error;
    if (!row || !safeSecretMatches(phoneToken, row.phone_secret_hash)) {
      return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 승인 요청을 찾을 수 없습니다.');
    }

    if (new Date(row.expires_at).getTime() <= Date.now() && row.status === 'pending') {
      await db.from('remote_login_requests').update({ status: 'expired' }).eq('id', row.id).eq('status', 'pending');
      row.status = 'expired';
    }

    return res.status(200).json({
      ok: true,
      requestId: row.id,
      requestDevice: row.request_device,
      status: row.status,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
      optionsJSON: row.status === 'pending' ? row.options_json : null,
    });
  } catch (error) {
    console.error('remote/details', error);
    return jsonError(res, 500, 'REMOTE_LOGIN_DETAILS_FAILED', error.message || '로그인 요청을 불러오지 못했습니다.');
  }
}

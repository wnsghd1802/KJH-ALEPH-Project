import { getDB } from '../../_lib/db.js';
import { OWNER_ID, noStore, jsonError } from '../../_lib/webauthn.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const registrationId = String(req.body?.registrationId || '');
    if (!registrationId) return jsonError(res, 400, 'INVALID_REQUEST', 'registrationId가 필요합니다.');

    const db = getDB();
    const { error } = await db
      .from('webauthn_challenges')
      .delete()
      .eq('id', registrationId)
      .eq('owner_id', OWNER_ID)
      .eq('purpose', 'registration')
      .is('used_at', null);

    if (error) throw error;
    return res.status(200).json({ ok: true, cancelled: true });
  } catch (error) {
    console.error('register/cancel', error);
    return jsonError(res, 500, 'CANCEL_FAILED', error.message || '등록 취소 처리에 실패했습니다.');
  }
}

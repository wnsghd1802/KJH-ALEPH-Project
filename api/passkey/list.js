import { getDB } from '../../lib/db.js';
import { OWNER_ID, noStore, jsonError } from '../../lib/webauthn.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'GET') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'GET 요청만 허용됩니다.');

  try {
    const db = getDB();
    const { data, error } = await db
      .from('passkeys')
      .select('id, name, created_at, device_type, backed_up')
      .eq('owner_id', OWNER_ID)
      .order('created_at', { ascending: true });

    if (error) throw error;

    return res.status(200).json({
      ok: true,
      passkeys: (data || []).map((item) => ({
        id: item.id,
        name: item.name,
        createdAt: item.created_at,
        deviceType: item.device_type,
        backedUp: item.backed_up,
      })),
    });
  } catch (error) {
    console.error('passkey/list', error);
    return jsonError(res, 500, 'PASSKEY_LIST_FAILED', error.message || '패스키 목록을 불러오지 못했습니다.');
  }
}

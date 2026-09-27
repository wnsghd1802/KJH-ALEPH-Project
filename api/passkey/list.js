import {
  getDB, getActiveSession, clearSessionCookie, noStore, jsonError, normalizeOwnerId,
} from '../_lib/common.js';

async function listPasskeys(db, ownerId) {
  const { data, error } = await db.from('passkeys')
    .select('id, name, created_at, device_type, backed_up')
    .eq('owner_id', ownerId)
    .order('created_at', { ascending: true });
  if (error) throw error;
  return (data || []).map((item) => ({
    id: item.id,
    name: item.name,
    createdAt: item.created_at,
    deviceType: item.device_type,
    backedUp: item.backed_up,
  }));
}

export default async function handler(req, res) {
  noStore(res);
  try {
    const db = getDB();

    if (req.method === 'GET') {
      const ownerId = normalizeOwnerId(req.query?.accountId);
      if (!ownerId) return jsonError(res, 400, 'INVALID_ACCOUNT', '조회할 계정을 선택해 주세요.');
      const passkeys = await listPasskeys(db, ownerId);
      return res.status(200).json({ ok: true, ownerId, count: passkeys.length, passkeys });
    }

    if (req.method === 'DELETE') {
      const session = await getActiveSession(req, db);
      if (!session) return jsonError(res, 401, 'AUTH_REQUIRED_TO_DELETE_PASSKEY', '패스키를 삭제하려면 먼저 해당 계정으로 로그인해 주세요.');

      const passkeyId = String(req.body?.id || '').trim();
      if (!passkeyId) return jsonError(res, 400, 'PASSKEY_ID_REQUIRED', '삭제할 패스키 ID가 필요합니다.');

      const ownerId = session.owner_id;
      const { data: target, error: targetError } = await db.from('passkeys')
        .select('id, name, credential_id')
        .eq('id', passkeyId)
        .eq('owner_id', ownerId)
        .maybeSingle();
      if (targetError) throw targetError;
      if (!target) return jsonError(res, 404, 'PASSKEY_NOT_FOUND', '현재 로그인한 계정에 등록된 패스키가 아닙니다.');

      const { error: deleteError } = await db.from('passkeys').delete().eq('id', target.id).eq('owner_id', ownerId);
      if (deleteError) throw deleteError;

      const remaining = await listPasskeys(db, ownerId);
      const noPasskeysLeft = remaining.length === 0;
      if (noPasskeysLeft) {
        const now = new Date().toISOString();
        const { error: revokeError } = await db.from('auth_sessions')
          .update({ revoked_at: now }).eq('owner_id', ownerId).is('revoked_at', null);
        if (revokeError) throw revokeError;
        clearSessionCookie(req, res);
      }

      return res.status(200).json({
        ok: true,
        ownerId,
        deleted: { id: target.id, name: target.name },
        remainingCount: remaining.length,
        noPasskeysLeft,
        message: noPasskeysLeft
          ? '마지막 패스키가 삭제되어 로그인 세션도 종료되었습니다. 새 패스키를 등록하기 전까지 로그인할 수 없습니다.'
          : `${target.name} 패스키를 서버 등록 목록에서 삭제했습니다.`,
      });
    }

    res.setHeader('Allow', 'GET, DELETE');
    return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'GET 또는 DELETE 요청만 허용됩니다.');
  } catch (error) {
    console.error('passkey/list', error);
    return jsonError(res, 500, 'PASSKEY_MANAGEMENT_FAILED', error.message || '패스키 정보를 처리하지 못했습니다.');
  }
}

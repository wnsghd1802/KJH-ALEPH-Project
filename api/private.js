import { getDB, getActiveSession, noStore, jsonError, normalizeOwnerId, getOtherOwnerId } from './_lib/common.js';

async function countItems(db, ownerId) {
  const { count, error } = await db.from('private_items').select('id', { count: 'exact', head: true }).eq('owner_id', ownerId);
  if (error) throw error;
  return count || 0;
}

async function readItems(db, ownerId) {
  const { data, error } = await db.from('private_items')
    .select('id, title, value, sort_order')
    .eq('owner_id', ownerId)
    .order('sort_order', { ascending: true });
  if (error) throw error;
  return data || [];
}

async function logAccess(db, values) {
  try { await db.from('card5_access_events').insert(values); }
  catch (error) { console.warn('card5 access log skipped', error?.message || error); }
}

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'GET 요청만 허용됩니다.');
  }

  try {
    const db = getDB();
    const session = await getActiveSession(req, db);
    if (!session) return jsonError(res, 401, 'AUTH_REQUIRED', '패스키 로그인이 필요합니다.');

    const sessionOwnerId = session.owner_id;
    const mode = String(req.query?.mode || 'self');
    const requestedOwnerId = normalizeOwnerId(req.query?.owner_id) || null;

    // C37/C38: 실제로 반대 계정 자료를 읽으려는 명시적 요청은 403으로 거절합니다.
    if (mode === 'cross') {
      const targetOwnerId = requestedOwnerId || getOtherOwnerId(sessionOwnerId);
      if (targetOwnerId === sessionOwnerId) {
        return jsonError(res, 400, 'TARGET_MUST_BE_OTHER_ACCOUNT', '반대 계정을 대상으로 테스트해 주세요.');
      }

      const before = await countItems(db, targetOwnerId);
      await logAccess(db, {
        session_owner_id: sessionOwnerId,
        requested_owner_id: targetOwnerId,
        action: 'cross_account_read',
        result: 'DENIED',
        status_code: 403,
      });
      const after = await countItems(db, targetOwnerId);

      return jsonError(res, 403, 'CROSS_ACCOUNT_ACCESS_DENIED', '현재 로그인한 계정의 자료가 아니므로 접근이 거절되었습니다.', {
        sessionOwnerId,
        requestedOwnerId: targetOwnerId,
        targetCountBefore: before,
        targetCountAfter: after,
        targetDataReturned: 0,
      });
    }

    // C40: URL/body에 다른 owner_id를 적더라도 실제 조회 기준은 세션 owner_id입니다.
    // 즉 조작된 owner_id는 권한 판단에 사용하지 않고 내 자료만 반환합니다.
    const items = await readItems(db, sessionOwnerId);
    const tampered = Boolean(requestedOwnerId && requestedOwnerId !== sessionOwnerId);
    if (tampered) {
      await logAccess(db, {
        session_owner_id: sessionOwnerId,
        requested_owner_id: requestedOwnerId,
        action: 'tampered_owner_id',
        result: 'IGNORED_RETURNED_SELF',
        status_code: 200,
      });
    }

    await db.from('auth_sessions').update({ last_seen_at: new Date().toISOString() }).eq('id', session.id);

    return res.status(200).json({
      ok: true,
      session: 'task8_session=••••••••',
      ownerId: sessionOwnerId,
      requestedOwnerId,
      ignoredRequestedOwnerId: tampered ? requestedOwnerId : null,
      accessRule: 'session_owner_only',
      count: items.length,
      items: items.map(({ title, value }) => ({ title, value })),
    });
  } catch (error) {
    console.error('private', error);
    return jsonError(res, 500, 'PRIVATE_READ_FAILED', error.message || '비공개 자료를 불러오지 못했습니다.');
  }
}

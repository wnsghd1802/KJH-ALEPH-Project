import { getDB, OWNER_ID, noStore, jsonError, SESSION_COOKIE, hashSessionToken, readCookie } from './_lib/common.js';

async function requireSession(req, db) {
  const rawToken = readCookie(req, SESSION_COOKIE);
  if (!rawToken) return null;
  const now = new Date().toISOString();
  const { data, error } = await db
    .from('auth_sessions')
    .select('id')
    .eq('owner_id', OWNER_ID)
    .eq('token_hash', hashSessionToken(rawToken))
    .is('revoked_at', null)
    .gt('expires_at', now)
    .maybeSingle();
  if (error) throw error;
  return data || null;
}

export default async function handler(req, res) {
  noStore(res);

  if (req.method === 'GET') {
    const publicKey = process.env.VAPID_PUBLIC_KEY;
    if (!publicKey) return jsonError(res, 503, 'VAPID_NOT_CONFIGURED', '휴대폰 알림용 VAPID_PUBLIC_KEY가 설정되지 않았습니다.');
    return res.status(200).json({ ok: true, publicKey });
  }

  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'GET 또는 POST 요청만 허용됩니다.');

  try {
    const subscription = req.body?.subscription;
    const endpoint = String(subscription?.endpoint || '');
    const p256dh = String(subscription?.keys?.p256dh || '');
    const auth = String(subscription?.keys?.auth || '');
    if (!endpoint || !p256dh || !auth) {
      return jsonError(res, 400, 'INVALID_SUBSCRIPTION', '브라우저 알림 구독 정보가 올바르지 않습니다.');
    }

    const db = getDB();
    const session = await requireSession(req, db);
    if (!session) return jsonError(res, 401, 'AUTH_REQUIRED', '휴대폰에서 먼저 패스키 로그인을 완료한 뒤 알림을 연결해 주세요.');

    const now = new Date().toISOString();
    const { error } = await db.from('push_subscriptions').upsert({
      owner_id: OWNER_ID,
      endpoint,
      p256dh,
      auth,
      user_agent: String(req.headers['user-agent'] || '').slice(0, 500),
      active: true,
      updated_at: now,
    }, { onConflict: 'endpoint' });
    if (error) throw error;

    return res.status(200).json({ ok: true, message: '이 휴대폰이 로그인 승인 알림 기기로 연결되었습니다.' });
  } catch (error) {
    console.error('push', error);
    return jsonError(res, 500, 'PUSH_REGISTER_FAILED', error.message || '휴대폰 알림 연결에 실패했습니다.');
  }
}

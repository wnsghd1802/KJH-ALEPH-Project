import { getDB } from './_lib/db.js';
import { OWNER_ID, noStore, jsonError } from './_lib/webauthn.js';
import {
  SESSION_COOKIE,
  hashSessionToken,
  readCookie,
} from './_lib/session.js';

const PRIVATE_ITEMS = [
  { title: '준비 중인 프로젝트', value: '보안 자동 점검 도구 개선' },
  { title: '개인 메모', value: '네트워크 및 리눅스 실습 복습하기' },
  { title: '다음 목표', value: '패스키 인증 흐름 직접 구현해 보기' },
];

export default async function handler(req, res) {
  noStore(res);

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'GET 요청만 허용됩니다.');
  }

  try {
    const token = readCookie(req, SESSION_COOKIE);
    if (!token) {
      return jsonError(res, 401, 'AUTH_REQUIRED', '패스키 로그인이 필요합니다.');
    }

    const db = getDB();
    const now = new Date().toISOString();
    const { data: session, error } = await db
      .from('auth_sessions')
      .select('id, expires_at, revoked_at')
      .eq('owner_id', OWNER_ID)
      .eq('token_hash', hashSessionToken(token))
      .is('revoked_at', null)
      .gt('expires_at', now)
      .maybeSingle();

    if (error) throw error;
    if (!session) {
      return jsonError(res, 401, 'SESSION_INVALID', '로그인 세션이 없거나 만료되었습니다.');
    }

    await db
      .from('auth_sessions')
      .update({ last_seen_at: now })
      .eq('id', session.id);

    return res.status(200).json({
      ok: true,
      session: 'task8_session=••••••••',
      items: PRIVATE_ITEMS,
    });
  } catch (error) {
    console.error('private', error);
    return jsonError(res, 500, 'PRIVATE_READ_FAILED', error.message || '비공개 자료를 불러오지 못했습니다.');
  }
}

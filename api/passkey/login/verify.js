import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { getDB, getWebAuthnConfig, noStore, jsonError, SESSION_TTL_MS, createSessionToken, hashSessionToken, setSessionCookie, normalizeOwnerId } from '../../_lib/common.js';

function credentialHint(value) {
  const text = String(value || '');
  if (!text) return null;
  return text.length > 18 ? `${text.slice(0, 10)}…${text.slice(-6)}` : text;
}

async function logEvent(db, values) {
  try { await db.from('webauthn_auth_events').insert(values); }
  catch (error) { console.warn('auth event log skipped', error?.message || error); }
}

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const loginId = String(req.body?.loginId || '');
    const credential = req.body?.credential;
    if (!loginId || !credential) return jsonError(res, 400, 'INVALID_REQUEST', 'loginId와 credential이 필요합니다.');

    const db = getDB();
    const { rpID, origin } = getWebAuthnConfig(req);
    const { data: challengeRow, error: challengeError } = await db.from('webauthn_challenges')
      .select('*').eq('id', loginId).eq('purpose', 'authentication').maybeSingle();
    if (challengeError) throw challengeError;

    const ownerId = normalizeOwnerId(challengeRow?.owner_id);
    if (!challengeRow || !ownerId) {
      return jsonError(res, 400, 'CHALLENGE_NOT_FOUND', '로그인 질문이 없거나 정리되었습니다.');
    }

    if (challengeRow.used_at) {
      await logEvent(db, { owner_id: ownerId, event_type: 'replay_rejected', challenge_id: loginId, credential_hint: credentialHint(credential?.id), result: 'REJECTED', detail: '이미 사용한 challenge 재사용 거절' });
      return jsonError(res, 409, 'CHALLENGE_ALREADY_USED', '이미 사용한 로그인 질문입니다. 재사용할 수 없습니다.');
    }

    if (new Date(challengeRow.expires_at).getTime() <= Date.now()) {
      await db.from('webauthn_challenges').update({ used_at: new Date().toISOString() }).eq('id', loginId);
      return jsonError(res, 400, 'CHALLENGE_EXPIRED', '로그인 질문이 만료되었습니다. 다시 로그인해 주세요.');
    }

    const { data: claimed, error: claimError } = await db.from('webauthn_challenges')
      .update({ used_at: new Date().toISOString() }).eq('id', loginId).is('used_at', null).select('id');
    if (claimError) throw claimError;
    if (!claimed?.length) return jsonError(res, 409, 'CHALLENGE_ALREADY_USED', '이미 사용한 로그인 질문입니다.');

    const { data: passkey, error: passkeyError } = await db.from('passkeys')
      .select('id, credential_id, public_key, counter, transports')
      .eq('owner_id', ownerId)
      .eq('credential_id', String(credential.id || ''))
      .maybeSingle();
    if (passkeyError) throw passkeyError;
    if (!passkey) {
      await logEvent(db, { owner_id: ownerId, event_type: 'verify_failed', challenge_id: loginId, credential_hint: credentialHint(credential?.id), result: 'REJECTED', detail: '서버에 등록되지 않은 credential 또는 다른 계정의 credential' });
      return jsonError(res, 401, 'PASSKEY_NOT_REGISTERED', '선택한 계정에 등록된 패스키가 아닙니다.');
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: challengeRow.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: passkey.credential_id,
          publicKey: new Uint8Array(Buffer.from(passkey.public_key, 'base64url')),
          counter: Number(passkey.counter || 0),
          transports: passkey.transports || [],
        },
        requireUserVerification: true,
      });
    } catch (verifyError) {
      await logEvent(db, { owner_id: ownerId, event_type: 'verify_failed', challenge_id: loginId, credential_hint: credentialHint(credential?.id), result: 'REJECTED', detail: verifyError.message || '서명 검증 실패' });
      return jsonError(res, 401, 'AUTHENTICATION_VERIFY_FAILED', verifyError.message || '패스키 서명 검증에 실패했습니다.');
    }

    if (!verification.verified || !verification.authenticationInfo) {
      return jsonError(res, 401, 'NOT_VERIFIED', '패스키 서명이 검증되지 않았습니다.');
    }

    await db.from('passkeys').update({ counter: verification.authenticationInfo.newCounter }).eq('id', passkey.id);

    const rawToken = createSessionToken();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    const { error: sessionError } = await db.from('auth_sessions').insert({
      owner_id: ownerId,
      token_hash: hashSessionToken(rawToken),
      expires_at: expiresAt,
    });
    if (sessionError) throw sessionError;

    setSessionCookie(req, res, rawToken);
    await logEvent(db, { owner_id: ownerId, event_type: 'verify_success', challenge_id: loginId, credential_hint: credentialHint(credential?.id), result: 'VERIFIED', detail: '저장된 공개키로 서명 검증 성공 후 세션 발급' });

    return res.status(200).json({
      ok: true,
      verified: true,
      ownerId,
      session: { type: 'HttpOnly cookie', display: 'task8_session=••••••••', expiresAt },
    });
  } catch (error) {
    console.error('login/verify', error);
    return jsonError(res, 500, 'AUTHENTICATION_FAILED', error.message || '패스키 로그인 처리에 실패했습니다.');
  }
}

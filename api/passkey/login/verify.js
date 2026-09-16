import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { getDB } from '../../_lib/db.js';
import {
  OWNER_ID,
  getWebAuthnConfig,
  noStore,
  jsonError,
} from '../../_lib/webauthn.js';
import {
  SESSION_TTL_MS,
  createSessionToken,
  hashSessionToken,
  setSessionCookie,
} from '../../_lib/session.js';

function credentialHint(value) {
  const text = String(value || '');
  if (!text) return null;
  return text.length > 18 ? `${text.slice(0, 10)}…${text.slice(-6)}` : text;
}

async function logEvent(db, values) {
  try {
    await db.from('webauthn_auth_events').insert(values);
  } catch (error) {
    console.warn('auth event log skipped', error?.message || error);
  }
}

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const loginId = String(req.body?.loginId || '');
    const credential = req.body?.credential;
    if (!loginId || !credential) {
      return jsonError(res, 400, 'INVALID_REQUEST', 'loginId와 credential이 필요합니다.');
    }

    const db = getDB();
    const { rpID, origin } = getWebAuthnConfig(req);

    const { data: challengeRow, error: challengeError } = await db
      .from('webauthn_challenges')
      .select('*')
      .eq('id', loginId)
      .eq('owner_id', OWNER_ID)
      .eq('purpose', 'authentication')
      .maybeSingle();

    if (challengeError) throw challengeError;
    if (!challengeRow) {
      await logEvent(db, {
        owner_id: OWNER_ID,
        event_type: 'replay_rejected',
        challenge_id: loginId || null,
        credential_hint: credentialHint(credential?.id),
        result: 'REJECTED',
        detail: '로그인 challenge를 찾을 수 없음',
      });
      return jsonError(res, 400, 'CHALLENGE_NOT_FOUND', '로그인 질문이 없거나 정리되었습니다.');
    }

    if (challengeRow.used_at) {
      await logEvent(db, {
        owner_id: OWNER_ID,
        event_type: 'replay_rejected',
        challenge_id: loginId,
        credential_hint: credentialHint(credential?.id),
        result: 'REJECTED',
        detail: '이미 사용한 challenge 재사용 거절',
      });
      return jsonError(res, 409, 'CHALLENGE_ALREADY_USED', '이미 사용한 로그인 질문입니다. 재사용할 수 없습니다.');
    }

    if (new Date(challengeRow.expires_at).getTime() <= Date.now()) {
      await db.from('webauthn_challenges').update({ used_at: new Date().toISOString() }).eq('id', loginId);
      await logEvent(db, {
        owner_id: OWNER_ID,
        event_type: 'verify_failed',
        challenge_id: loginId,
        credential_hint: credentialHint(credential?.id),
        result: 'REJECTED',
        detail: 'challenge 만료',
      });
      return jsonError(res, 400, 'CHALLENGE_EXPIRED', '로그인 질문이 만료되었습니다. 다시 로그인해 주세요.');
    }

    // 검증 성공/실패 여부와 관계없이 challenge를 한 번만 사용할 수 있도록 먼저 소비합니다.
    const { data: claimed, error: claimError } = await db
      .from('webauthn_challenges')
      .update({ used_at: new Date().toISOString() })
      .eq('id', loginId)
      .is('used_at', null)
      .select('id');

    if (claimError) throw claimError;
    if (!claimed || claimed.length !== 1) {
      await logEvent(db, {
        owner_id: OWNER_ID,
        event_type: 'replay_rejected',
        challenge_id: loginId,
        credential_hint: credentialHint(credential?.id),
        result: 'REJECTED',
        detail: '동시 요청 또는 재사용 감지',
      });
      return jsonError(res, 409, 'CHALLENGE_ALREADY_USED', '이미 사용한 로그인 질문입니다.');
    }

    const { data: passkey, error: passkeyError } = await db
      .from('passkeys')
      .select('id, credential_id, public_key, counter, transports')
      .eq('owner_id', OWNER_ID)
      .eq('credential_id', String(credential.id || ''))
      .maybeSingle();

    if (passkeyError) throw passkeyError;
    if (!passkey) {
      await logEvent(db, {
        owner_id: OWNER_ID,
        event_type: 'verify_failed',
        challenge_id: loginId,
        credential_hint: credentialHint(credential?.id),
        result: 'REJECTED',
        detail: '서버에 등록되지 않은 credential',
      });
      return jsonError(res, 401, 'PASSKEY_NOT_REGISTERED', '서버에 등록된 패스키가 아닙니다.');
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
      await logEvent(db, {
        owner_id: OWNER_ID,
        event_type: 'verify_failed',
        challenge_id: loginId,
        credential_hint: credentialHint(credential?.id),
        result: 'REJECTED',
        detail: verifyError.message || '서명 검증 실패',
      });
      return jsonError(res, 401, 'AUTHENTICATION_VERIFY_FAILED', verifyError.message || '패스키 서명 검증에 실패했습니다.');
    }

    if (!verification.verified || !verification.authenticationInfo) {
      await logEvent(db, {
        owner_id: OWNER_ID,
        event_type: 'verify_failed',
        challenge_id: loginId,
        credential_hint: credentialHint(credential?.id),
        result: 'REJECTED',
        detail: '서명 검증 결과 verified=false',
      });
      return jsonError(res, 401, 'NOT_VERIFIED', '패스키 서명이 검증되지 않았습니다.');
    }

    const { newCounter } = verification.authenticationInfo;
    const { error: counterError } = await db
      .from('passkeys')
      .update({ counter: newCounter })
      .eq('id', passkey.id);
    if (counterError) throw counterError;

    const rawToken = createSessionToken();
    const tokenHash = hashSessionToken(rawToken);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

    const { error: sessionError } = await db
      .from('auth_sessions')
      .insert({
        owner_id: OWNER_ID,
        token_hash: tokenHash,
        expires_at: expiresAt,
      });
    if (sessionError) throw sessionError;

    setSessionCookie(req, res, rawToken);

    await logEvent(db, {
      owner_id: OWNER_ID,
      event_type: 'verify_success',
      challenge_id: loginId,
      credential_hint: credentialHint(credential?.id),
      result: 'VERIFIED',
      detail: '저장된 공개키로 서명 검증 성공 후 세션 발급',
    });

    return res.status(200).json({
      ok: true,
      verified: true,
      session: {
        type: 'HttpOnly cookie',
        display: 'task8_session=••••••••',
        expiresAt,
      },
    });
  } catch (error) {
    console.error('login/verify', error);
    return jsonError(res, 500, 'AUTHENTICATION_FAILED', error.message || '패스키 로그인 처리에 실패했습니다.');
  }
}

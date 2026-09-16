import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { getDB } from '../../_lib/db.js';
import { OWNER_ID, getWebAuthnConfig, noStore, jsonError } from '../../_lib/webauthn.js';
import { safeSecretMatches, preview } from '../../_lib/remote-login.js';

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
    const requestId = String(req.body?.requestId || '');
    const phoneToken = String(req.body?.phoneToken || '');
    const credential = req.body?.credential;
    if (!requestId || !phoneToken || !credential) {
      return jsonError(res, 400, 'INVALID_REQUEST', '로그인 승인 정보가 부족합니다.');
    }

    const db = getDB();
    const { rpID, origin } = getWebAuthnConfig(req);

    const { data: remoteRow, error: remoteError } = await db
      .from('remote_login_requests')
      .select('*')
      .eq('id', requestId)
      .eq('owner_id', OWNER_ID)
      .maybeSingle();
    if (remoteError) throw remoteError;
    if (!remoteRow || !safeSecretMatches(phoneToken, remoteRow.phone_secret_hash)) {
      return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 승인 요청을 찾을 수 없습니다.');
    }
    if (remoteRow.status !== 'pending') {
      return jsonError(res, 409, 'REQUEST_NOT_PENDING', `이미 처리된 로그인 요청입니다. (${remoteRow.status})`);
    }
    if (new Date(remoteRow.expires_at).getTime() <= Date.now()) {
      await db.from('remote_login_requests').update({ status: 'expired' }).eq('id', requestId).eq('status', 'pending');
      return jsonError(res, 410, 'REQUEST_EXPIRED', '로그인 승인 요청이 만료되었습니다. PC에서 다시 요청해 주세요.');
    }

    const { data: challengeRow, error: challengeError } = await db
      .from('webauthn_challenges')
      .select('*')
      .eq('id', remoteRow.challenge_id)
      .eq('owner_id', OWNER_ID)
      .eq('purpose', 'authentication')
      .maybeSingle();
    if (challengeError) throw challengeError;
    if (!challengeRow) return jsonError(res, 400, 'CHALLENGE_NOT_FOUND', '로그인 challenge가 없습니다.');
    if (challengeRow.used_at) return jsonError(res, 409, 'CHALLENGE_ALREADY_USED', '이미 사용된 로그인 challenge입니다.');

    const { data: claimed, error: claimError } = await db
      .from('webauthn_challenges')
      .update({ used_at: new Date().toISOString() })
      .eq('id', challengeRow.id)
      .is('used_at', null)
      .select('id');
    if (claimError) throw claimError;
    if (!claimed || claimed.length !== 1) {
      return jsonError(res, 409, 'CHALLENGE_ALREADY_USED', '이미 사용된 로그인 challenge입니다.');
    }

    const { data: passkey, error: passkeyError } = await db
      .from('passkeys')
      .select('id, credential_id, public_key, counter, transports')
      .eq('owner_id', OWNER_ID)
      .eq('credential_id', String(credential.id || ''))
      .maybeSingle();
    if (passkeyError) throw passkeyError;
    if (!passkey) return jsonError(res, 401, 'PASSKEY_NOT_REGISTERED', '서버에 등록된 패스키가 아닙니다.');

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
      await db.from('remote_login_requests').update({ status: 'rejected' }).eq('id', requestId).eq('status', 'pending');
      await logEvent(db, {
        owner_id: OWNER_ID,
        event_type: 'verify_failed',
        challenge_id: challengeRow.id,
        credential_hint: preview(credential?.id, 10, 6),
        result: 'REJECTED',
        detail: `remote approval failed: ${verifyError.message || '서명 검증 실패'}`,
      });
      return jsonError(res, 401, 'AUTHENTICATION_VERIFY_FAILED', verifyError.message || '패스키 서명 검증에 실패했습니다.');
    }

    if (!verification.verified || !verification.authenticationInfo) {
      await db.from('remote_login_requests').update({ status: 'rejected' }).eq('id', requestId).eq('status', 'pending');
      return jsonError(res, 401, 'NOT_VERIFIED', '패스키 서명이 검증되지 않았습니다.');
    }

    const { newCounter } = verification.authenticationInfo;
    await db.from('passkeys').update({ counter: newCounter }).eq('id', passkey.id);

    const approvedAt = new Date().toISOString();
    const { data: updated, error: approveError } = await db
      .from('remote_login_requests')
      .update({
        status: 'approved',
        approved_at: approvedAt,
        credential_hint: preview(credential.id, 10, 6),
      })
      .eq('id', requestId)
      .eq('status', 'pending')
      .select('id');
    if (approveError) throw approveError;
    if (!updated || updated.length !== 1) {
      return jsonError(res, 409, 'REQUEST_ALREADY_HANDLED', '이미 처리된 로그인 요청입니다.');
    }

    await logEvent(db, {
      owner_id: OWNER_ID,
      event_type: 'verify_success',
      challenge_id: challengeRow.id,
      credential_hint: preview(credential?.id, 10, 6),
      result: 'VERIFIED',
      detail: '휴대폰 패스키 공개키 검증 성공 · PC 승인 대기 완료',
    });

    return res.status(200).json({
      ok: true,
      approved: true,
      message: '본인 인증이 완료되었습니다. PC 로그인이 승인되었습니다.',
    });
  } catch (error) {
    console.error('remote/approve', error);
    return jsonError(res, 500, 'REMOTE_APPROVAL_FAILED', error.message || '휴대폰 로그인 승인에 실패했습니다.');
  }
}

import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { getDB, getWebAuthnConfig, noStore, jsonError, normalizeOwnerId } from '../../_lib/common.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const registrationId = String(req.body?.registrationId || '');
    const credential = req.body?.credential;
    if (!registrationId || !credential) return jsonError(res, 400, 'INVALID_REQUEST', 'registrationId와 credential이 필요합니다.');

    const db = getDB();
    const { rpID, origin } = getWebAuthnConfig(req);
    const { data: challengeRow, error: challengeError } = await db.from('webauthn_challenges')
      .select('*').eq('id', registrationId).eq('purpose', 'registration').is('used_at', null).maybeSingle();
    if (challengeError) throw challengeError;
    const ownerId = normalizeOwnerId(challengeRow?.owner_id);
    if (!challengeRow || !ownerId) return jsonError(res, 400, 'CHALLENGE_NOT_FOUND', '등록 질문이 없거나 이미 사용되었습니다.');

    if (new Date(challengeRow.expires_at).getTime() <= Date.now()) {
      await db.from('webauthn_challenges').delete().eq('id', registrationId);
      return jsonError(res, 400, 'CHALLENGE_EXPIRED', '등록 질문이 만료되었습니다. 다시 등록해 주세요.');
    }

    const { data: claimed, error: claimError } = await db.from('webauthn_challenges')
      .update({ used_at: new Date().toISOString() }).eq('id', registrationId).is('used_at', null).select('id');
    if (claimError) throw claimError;
    if (!claimed?.length) return jsonError(res, 409, 'CHALLENGE_ALREADY_USED', '이미 사용된 등록 질문입니다.');

    let verification;
    try {
      verification = await verifyRegistrationResponse({ response: credential, expectedChallenge: challengeRow.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true });
    } catch (verifyError) {
      return jsonError(res, 400, 'REGISTRATION_VERIFY_FAILED', verifyError.message || '패스키 응답 검증에 실패했습니다.');
    }
    if (!verification.verified || !verification.registrationInfo) return jsonError(res, 400, 'NOT_VERIFIED', '패스키 등록 응답이 검증되지 않았습니다.');

    const { credential: verifiedCredential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    const publicKey = Buffer.from(verifiedCredential.publicKey).toString('base64url');
    const { data: saved, error: saveError } = await db.from('passkeys').insert({
      owner_id: ownerId,
      name: challengeRow.passkey_name,
      credential_id: verifiedCredential.id,
      webauthn_user_id: challengeRow.webauthn_user_id,
      public_key: publicKey,
      counter: verifiedCredential.counter,
      transports: verifiedCredential.transports || credential.response?.transports || [],
      device_type: credentialDeviceType,
      backed_up: credentialBackedUp,
    }).select('id, name, created_at, device_type, backed_up').single();

    if (saveError) {
      if (saveError.code === '23505') return jsonError(res, 409, 'PASSKEY_ALREADY_REGISTERED', '이미 등록된 패스키입니다.');
      throw saveError;
    }

    const { count, error: countError } = await db.from('passkeys').select('id', { count: 'exact', head: true }).eq('owner_id', ownerId);
    if (countError) throw countError;

    return res.status(200).json({
      ok: true,
      verified: true,
      ownerId,
      passkeyCount: count || 0,
      passkey: { id: saved.id, name: saved.name, createdAt: saved.created_at, deviceType: saved.device_type, backedUp: saved.backed_up },
    });
  } catch (error) {
    console.error('register/verify', error);
    return jsonError(res, 500, 'REGISTRATION_SAVE_FAILED', error.message || '패스키 등록을 저장하지 못했습니다.');
  }
}

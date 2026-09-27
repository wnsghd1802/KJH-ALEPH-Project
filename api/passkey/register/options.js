import { generateRegistrationOptions } from '@simplewebauthn/server';
import { getDB, RP_NAME, CHALLENGE_TTL_MS, getWebAuthnConfig, getActiveSession, noStore, jsonError, normalizeOwnerId, getAccount } from '../../_lib/common.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const ownerId = normalizeOwnerId(req.body?.accountId);
    if (!ownerId) return jsonError(res, 400, 'INVALID_ACCOUNT', '패스키를 등록할 계정을 선택해 주세요.');

    const name = String(req.body?.name || '').trim();
    const authenticatorType = String(req.body?.authenticatorType || 'localDevice');
    const testMode = req.body?.testMode === true;
    const allowedAuthenticatorTypes = new Set(['remoteDevice', 'securityKey', 'localDevice']);
    if (!name || name.length > 40) return jsonError(res, 400, 'INVALID_NAME', '패스키 이름은 1~40자로 입력해 주세요.');
    if (!allowedAuthenticatorTypes.has(authenticatorType)) return jsonError(res, 400, 'INVALID_AUTHENTICATOR_TYPE', '지원하지 않는 인증 수단입니다.');

    const db = getDB();
    const { rpID } = getWebAuthnConfig(req);
    const { data: existing, error: existingError } = await db.from('passkeys')
      .select('id, credential_id, transports').eq('owner_id', ownerId).order('created_at', { ascending: true });
    if (existingError) throw existingError;

    if (!testMode && existing?.length) {
      const session = await getActiveSession(req, db);
      if (!session) return jsonError(res, 401, 'AUTH_REQUIRED_TO_ADD_PASSKEY', '새 패스키를 추가하려면 먼저 해당 계정으로 로그인해 주세요.');
      if (session.owner_id !== ownerId) return jsonError(res, 403, 'CROSS_ACCOUNT_MANAGEMENT_DENIED', '다른 계정의 패스키를 추가할 수 없습니다.');
    }

    const account = getAccount(ownerId);
    const optionsJSON = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID,
      userID: new TextEncoder().encode(ownerId),
      userName: ownerId,
      userDisplayName: account.displayName,
      attestationType: 'none',
      excludeCredentials: testMode ? [] : (existing || []).map((item) => ({ id: item.credential_id, transports: item.transports || [] })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      preferredAuthenticatorType: authenticatorType,
      supportedAlgorithmIDs: [-7, -257],
      timeout: 60_000,
    });

    await db.from('webauthn_challenges').delete()
      .eq('owner_id', ownerId).eq('purpose', 'registration').is('used_at', null);

    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();
    const { data: challengeRow, error: challengeError } = await db.from('webauthn_challenges').insert({
      owner_id: ownerId,
      purpose: 'registration',
      challenge: optionsJSON.challenge,
      webauthn_user_id: optionsJSON.user.id,
      passkey_name: name,
      expires_at: expiresAt,
    }).select('id').single();
    if (challengeError) throw challengeError;

    return res.status(200).json({ ok: true, ownerId, testMode, mode: existing?.length ? 'additional' : 'first', existingCount: existing?.length || 0, registrationId: challengeRow.id, optionsJSON });
  } catch (error) {
    console.error('register/options', error);
    return jsonError(res, 500, 'REGISTRATION_OPTIONS_FAILED', error.message || '등록용 질문을 만들지 못했습니다.');
  }
}

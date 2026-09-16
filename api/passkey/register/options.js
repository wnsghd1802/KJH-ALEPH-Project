import { generateRegistrationOptions } from '@simplewebauthn/server';
import { getDB } from '../../_lib/db.js';
import {
  OWNER_ID,
  RP_NAME,
  CHALLENGE_TTL_MS,
  getWebAuthnConfig,
  noStore,
  jsonError,
} from '../../_lib/webauthn.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const name = String(req.body?.name || '').trim();
    const authenticatorType = String(req.body?.authenticatorType || 'remoteDevice');
    const allowedAuthenticatorTypes = new Set(['remoteDevice', 'securityKey', 'localDevice']);
    if (!name || name.length > 40) {
      return jsonError(res, 400, 'INVALID_NAME', '패스키 이름은 1~40자로 입력해 주세요.');
    }
    if (!allowedAuthenticatorTypes.has(authenticatorType)) {
      return jsonError(res, 400, 'INVALID_AUTHENTICATOR_TYPE', '지원하지 않는 인증 수단입니다.');
    }

    const db = getDB();
    const { rpID } = getWebAuthnConfig(req);

    const { data: existing, error: existingError } = await db
      .from('passkeys')
      .select('credential_id, transports')
      .eq('owner_id', OWNER_ID);

    if (existingError) throw existingError;

    // Card 2는 최초 등록만 엽니다. Card 4에서 로그인된 세션으로 추가 등록을 허용합니다.
    if ((existing || []).length > 0) {
      return jsonError(res, 409, 'FIRST_PASSKEY_ALREADY_REGISTERED', '첫 패스키가 이미 등록되어 있습니다. 추가 등록은 Card 4에서 진행합니다.');
    }

    const optionsJSON = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID,
      userID: new TextEncoder().encode(OWNER_ID),
      userName: OWNER_ID,
      userDisplayName: 'Portfolio Owner',
      attestationType: 'none',
      excludeCredentials: (existing || []).map((item) => ({
        id: item.credential_id,
        transports: item.transports || [],
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      // SimpleWebAuthn이 WebAuthn hints + 하위 호환용 authenticatorAttachment를 함께 구성합니다.
      // remoteDevice: 휴대폰/태블릿(hybrid), securityKey: USB/FIDO2 키, localDevice: Windows Hello 등
      preferredAuthenticatorType: authenticatorType,
      supportedAlgorithmIDs: [-7, -257],
      timeout: 60_000,
    });

    // 이전에 끝나지 않은 최초 등록 challenge는 정리합니다.
    await db
      .from('webauthn_challenges')
      .delete()
      .eq('owner_id', OWNER_ID)
      .eq('purpose', 'registration')
      .is('used_at', null);

    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();
    const { data: challengeRow, error: challengeError } = await db
      .from('webauthn_challenges')
      .insert({
        owner_id: OWNER_ID,
        purpose: 'registration',
        challenge: optionsJSON.challenge,
        webauthn_user_id: optionsJSON.user.id,
        passkey_name: name,
        expires_at: expiresAt,
      })
      .select('id')
      .single();

    if (challengeError) throw challengeError;

    return res.status(200).json({
      ok: true,
      registrationId: challengeRow.id,
      optionsJSON,
    });
  } catch (error) {
    console.error('register/options', error);
    return jsonError(res, 500, 'REGISTRATION_OPTIONS_FAILED', error.message || '등록용 질문을 만들지 못했습니다.');
  }
}

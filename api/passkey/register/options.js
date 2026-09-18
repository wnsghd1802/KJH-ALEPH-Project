import { generateRegistrationOptions } from '@simplewebauthn/server';
import { getDB, OWNER_ID, RP_NAME, CHALLENGE_TTL_MS, getWebAuthnConfig, getActiveSession, noStore, jsonError } from '../../_lib/common.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const name = String(req.body?.name || '').trim();
    const authenticatorType = String(req.body?.authenticatorType || 'localDevice');
    const testMode = req.body?.testMode === true;
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
      .select('id, credential_id, transports')
      .eq('owner_id', OWNER_ID)
      .order('created_at', { ascending: true });

    if (existingError) throw existingError;

    // 첫 패스키는 Card 2 초기 설정으로 등록할 수 있습니다.
    // 이미 패스키가 하나 이상 있으면 Card 4의 추가 등록이므로 기존 패스키 로그인 세션을 요구합니다.
    // 취소 테스트는 실제 저장을 하지 않으므로 기존 Card 2 증빙을 위해 세션 요구에서 제외합니다.
    if (!testMode && (existing || []).length > 0) {
      const session = await getActiveSession(req, db);
      if (!session) {
        return jsonError(
          res,
          401,
          'AUTH_REQUIRED_TO_ADD_PASSKEY',
          '새 패스키를 추가하려면 먼저 위의 패스키 로그인으로 본인 확인을 해 주세요.'
        );
      }
    }

    const optionsJSON = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID,
      userID: new TextEncoder().encode(OWNER_ID),
      userName: OWNER_ID,
      userDisplayName: 'Portfolio Owner',
      attestationType: 'none',
      // Card 4: 이미 서버에 등록된 credential을 모두 제외해 같은 credential의 중복 등록을 막습니다.
      // Samsung Pass 등 다른 credential provider에는 기존 credential이 없으므로 새 패스키를 만들 수 있습니다.
      excludeCredentials: testMode
        ? []
        : (existing || []).map((item) => ({
            id: item.credential_id,
            transports: item.transports || [],
          })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      preferredAuthenticatorType: authenticatorType,
      supportedAlgorithmIDs: [-7, -257],
      timeout: 60_000,
    });

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
      testMode,
      mode: (existing || []).length > 0 ? 'additional' : 'first',
      existingCount: (existing || []).length,
      registrationId: challengeRow.id,
      optionsJSON,
    });
  } catch (error) {
    console.error('register/options', error);
    return jsonError(res, 500, 'REGISTRATION_OPTIONS_FAILED', error.message || '등록용 질문을 만들지 못했습니다.');
  }
}

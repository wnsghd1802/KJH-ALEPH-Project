import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getDB } from '../../_lib/db.js';
import {
  OWNER_ID,
  CHALLENGE_TTL_MS,
  getWebAuthnConfig,
  noStore,
  jsonError,
} from '../../_lib/webauthn.js';

function previewChallenge(value) {
  const text = String(value || '');
  return text.length > 30 ? `${text.slice(0, 18)}…${text.slice(-8)}` : text;
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
    const db = getDB();
    const { rpID } = getWebAuthnConfig(req);

    const { data: passkeys, error: passkeyError } = await db
      .from('passkeys')
      .select('credential_id, transports')
      .eq('owner_id', OWNER_ID);

    if (passkeyError) throw passkeyError;
    if (!passkeys || passkeys.length === 0) {
      return jsonError(res, 404, 'NO_PASSKEY', '등록된 패스키가 없습니다. 먼저 Card 2에서 패스키를 등록해 주세요.');
    }

    const optionsJSON = await generateAuthenticationOptions({
      rpID,
      allowCredentials: passkeys.map((item) => ({
        id: item.credential_id,
        transports: item.transports || [],
      })),
      userVerification: 'required',
      timeout: 60_000,
    });

    // 만료된 로그인 challenge만 정리합니다. 아직 살아 있는 challenge는 그대로 두어
    // C28에서 서로 다른 로그인 challenge가 실제로 발급되었음을 비교할 수 있게 합니다.
    await db
      .from('webauthn_challenges')
      .delete()
      .eq('owner_id', OWNER_ID)
      .eq('purpose', 'authentication')
      .lt('expires_at', new Date().toISOString());

    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();
    const { data: challengeRow, error: challengeError } = await db
      .from('webauthn_challenges')
      .insert({
        owner_id: OWNER_ID,
        purpose: 'authentication',
        challenge: optionsJSON.challenge,
        expires_at: expiresAt,
      })
      .select('id')
      .single();

    if (challengeError) throw challengeError;

    await logEvent(db, {
      owner_id: OWNER_ID,
      event_type: 'challenge_issued',
      challenge_id: challengeRow.id,
      result: 'ISSUED',
      detail: `challenge ${previewChallenge(optionsJSON.challenge)}`,
    });

    return res.status(200).json({
      ok: true,
      loginId: challengeRow.id,
      optionsJSON,
    });
  } catch (error) {
    console.error('login/options', error);
    return jsonError(res, 500, 'AUTHENTICATION_OPTIONS_FAILED', error.message || '로그인용 질문을 만들지 못했습니다.');
  }
}

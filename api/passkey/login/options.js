import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getDB, CHALLENGE_TTL_MS, getWebAuthnConfig, noStore, jsonError, normalizeOwnerId } from '../../_lib/common.js';

function previewChallenge(value) {
  const text = String(value || '');
  return text.length > 30 ? `${text.slice(0, 18)}…${text.slice(-8)}` : text;
}

async function logEvent(db, values) {
  try { await db.from('webauthn_auth_events').insert(values); }
  catch (error) { console.warn('auth event log skipped', error?.message || error); }
}

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');

  try {
    const ownerId = normalizeOwnerId(req.body?.accountId);
    if (!ownerId) return jsonError(res, 400, 'INVALID_ACCOUNT', '로그인할 계정을 선택해 주세요.');

    const authMode = String(req.body?.authMode || 'local');
    if (!['local', 'phone'].includes(authMode)) {
      return jsonError(res, 400, 'INVALID_AUTH_MODE', '지원하지 않는 로그인 방식입니다.');
    }

    const db = getDB();
    const { rpID } = getWebAuthnConfig(req);
    const { data: passkeys, error: passkeyError } = await db
      .from('passkeys')
      .select('credential_id')
      .eq('owner_id', ownerId);

    if (passkeyError) throw passkeyError;
    if (!passkeys?.length) return jsonError(res, 404, 'NO_PASSKEY', '선택한 계정에 등록된 패스키가 없습니다.');

    const optionsJSON = await generateAuthenticationOptions({
      rpID,
      userVerification: 'required',
      timeout: 60_000,
    });
    optionsJSON.hints = authMode === 'phone' ? ['hybrid'] : ['client-device', 'hybrid'];

    await db.from('webauthn_challenges').delete()
      .eq('owner_id', ownerId)
      .eq('purpose', 'authentication')
      .lt('expires_at', new Date().toISOString());

    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();
    const { data: challengeRow, error: challengeError } = await db.from('webauthn_challenges').insert({
      owner_id: ownerId,
      purpose: 'authentication',
      challenge: optionsJSON.challenge,
      expires_at: expiresAt,
    }).select('id').single();
    if (challengeError) throw challengeError;

    await logEvent(db, {
      owner_id: ownerId,
      event_type: 'challenge_issued',
      challenge_id: challengeRow.id,
      result: 'ISSUED',
      detail: `challenge ${previewChallenge(optionsJSON.challenge)}`,
    });

    return res.status(200).json({ ok: true, ownerId, loginId: challengeRow.id, authMode, optionsJSON });
  } catch (error) {
    console.error('login/options', error);
    return jsonError(res, 500, 'AUTHENTICATION_OPTIONS_FAILED', error.message || '로그인용 질문을 만들지 못했습니다.');
  }
}

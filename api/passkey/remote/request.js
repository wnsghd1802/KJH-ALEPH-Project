import webpush from 'web-push';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getDB } from '../../_lib/db.js';
import {
  OWNER_ID,
  getWebAuthnConfig,
  noStore,
  jsonError,
} from '../../_lib/webauthn.js';
import {
  REMOTE_LOGIN_TTL_MS,
  createOpaqueSecret,
  hashOpaqueSecret,
  preview,
} from '../../_lib/remote-login.js';

function configureWebPush() {
  const publicKey = process.env.VAPID_PUBLIC_KEY;
  const privateKey = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT || 'https://kjhnet.vercel.app';
  if (!publicKey || !privateKey) {
    throw new Error('VAPID_PUBLIC_KEY 또는 VAPID_PRIVATE_KEY가 설정되지 않았습니다.');
  }
  webpush.setVapidDetails(subject, publicKey, privateKey);
}

function clientLabel(req) {
  const ua = String(req.headers['user-agent'] || 'PC 브라우저');
  if (/Windows/i.test(ua)) return 'Windows PC';
  if (/Macintosh|Mac OS X/i.test(ua)) return 'Mac';
  if (/Linux/i.test(ua)) return 'Linux PC';
  return 'PC 브라우저';
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
    configureWebPush();
    const db = getDB();
    const { rpID } = getWebAuthnConfig(req);

    const { data: subscriptions, error: subscriptionError } = await db
      .from('push_subscriptions')
      .select('id, endpoint, p256dh, auth')
      .eq('owner_id', OWNER_ID)
      .eq('active', true);
    if (subscriptionError) throw subscriptionError;
    if (!subscriptions || subscriptions.length === 0) {
      return jsonError(res, 409, 'PHONE_NOT_LINKED', '로그인 알림을 받을 휴대폰이 연결되어 있지 않습니다. 휴대폰에서 먼저 “이 휴대폰 알림 연결”을 실행해 주세요.');
    }

    const { data: passkeys, error: passkeyError } = await db
      .from('passkeys')
      .select('credential_id')
      .eq('owner_id', OWNER_ID);
    if (passkeyError) throw passkeyError;
    if (!passkeys || passkeys.length === 0) {
      return jsonError(res, 404, 'NO_PASSKEY', '등록된 패스키가 없습니다.');
    }

    const optionsJSON = await generateAuthenticationOptions({
      rpID,
      allowCredentials: passkeys.map((item) => ({ id: item.credential_id })),
      userVerification: 'required',
      timeout: REMOTE_LOGIN_TTL_MS,
    });

    const now = new Date();
    const expiresAt = new Date(now.getTime() + REMOTE_LOGIN_TTL_MS).toISOString();

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

    const browserSecret = createOpaqueSecret();
    const phoneSecret = createOpaqueSecret();
    const label = clientLabel(req);

    const { data: remoteRow, error: remoteError } = await db
      .from('remote_login_requests')
      .insert({
        owner_id: OWNER_ID,
        challenge_id: challengeRow.id,
        browser_secret_hash: hashOpaqueSecret(browserSecret),
        phone_secret_hash: hashOpaqueSecret(phoneSecret),
        options_json: optionsJSON,
        request_device: label,
        status: 'pending',
        expires_at: expiresAt,
      })
      .select('id')
      .single();
    if (remoteError) throw remoteError;

    const notificationPayload = JSON.stringify({
      title: 'PC 로그인 승인 요청',
      body: `${label}에서 패스키 로그인을 요청했습니다. 눌러서 본인 인증 후 승인하세요.`,
      tag: `remote-login-${remoteRow.id}`,
      url: `/phone-auth.html?requestId=${encodeURIComponent(remoteRow.id)}&token=${encodeURIComponent(phoneSecret)}`,
    });

    let delivered = 0;
    for (const sub of subscriptions) {
      try {
        await webpush.sendNotification({
          endpoint: sub.endpoint,
          keys: { p256dh: sub.p256dh, auth: sub.auth },
        }, notificationPayload, { TTL: 120, urgency: 'high' });
        delivered += 1;
      } catch (pushError) {
        const statusCode = Number(pushError?.statusCode || 0);
        if (statusCode === 404 || statusCode === 410) {
          await db.from('push_subscriptions').update({ active: false, updated_at: new Date().toISOString() }).eq('id', sub.id);
        }
        console.warn('push delivery failed', statusCode, pushError?.message || pushError);
      }
    }

    if (delivered === 0) {
      await db.from('remote_login_requests').update({ status: 'rejected' }).eq('id', remoteRow.id);
      return jsonError(res, 502, 'PUSH_DELIVERY_FAILED', '연결된 휴대폰으로 로그인 알림을 보내지 못했습니다. 휴대폰 알림 연결을 다시 해 주세요.');
    }

    await logEvent(db, {
      owner_id: OWNER_ID,
      event_type: 'challenge_issued',
      challenge_id: challengeRow.id,
      result: 'ISSUED',
      detail: `PASS-style remote login ${preview(optionsJSON.challenge)}`,
    });

    return res.status(200).json({
      ok: true,
      requestId: remoteRow.id,
      browserSecret,
      challenge: optionsJSON.challenge,
      expiresAt,
      delivered,
      message: '휴대폰으로 로그인 승인 알림을 보냈습니다.',
    });
  } catch (error) {
    console.error('remote/request', error);
    return jsonError(res, 500, 'REMOTE_LOGIN_REQUEST_FAILED', error.message || '휴대폰 로그인 요청을 만들지 못했습니다.');
  }
}

import webpush from 'web-push';
import { generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import {
  getDB, OWNER_ID, getWebAuthnConfig, noStore, jsonError,
  REMOTE_LOGIN_TTL_MS, createOpaqueSecret, hashOpaqueSecret, safeSecretMatches, preview,
  SESSION_TTL_MS, createSessionToken, hashSessionToken, setSessionCookie,
} from '../_lib/common.js';

function configureWebPush() {
  const publicKey = process.env.VAPID_PUBLIC_KEY;
  const privateKey = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT || 'https://kjhnet.vercel.app';
  if (!publicKey || !privateKey) throw new Error('VAPID_PUBLIC_KEY 또는 VAPID_PRIVATE_KEY가 설정되지 않았습니다.');
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
  try { await db.from('webauthn_auth_events').insert(values); }
  catch (error) { console.warn('auth event log skipped', error?.message || error); }
}

async function requestAction(req, res) {
  configureWebPush();
  const db = getDB();
  const { rpID } = getWebAuthnConfig(req);

  const { data: subscriptions, error: subscriptionError } = await db
    .from('push_subscriptions').select('id, endpoint, p256dh, auth')
    .eq('owner_id', OWNER_ID).eq('active', true);
  if (subscriptionError) throw subscriptionError;
  if (!subscriptions?.length) return jsonError(res, 409, 'PHONE_NOT_LINKED', '로그인 알림을 받을 휴대폰이 연결되어 있지 않습니다. 휴대폰에서 먼저 로그인 후 알림 기기로 연결해 주세요.');

  const { data: passkeys, error: passkeyError } = await db.from('passkeys').select('credential_id').eq('owner_id', OWNER_ID);
  if (passkeyError) throw passkeyError;
  if (!passkeys?.length) return jsonError(res, 404, 'NO_PASSKEY', '등록된 패스키가 없습니다.');

  // 휴대폰 승인 페이지에서는 특정 credential_id를 강제로 제한하지 않습니다.
  // 등록 시 residentKey: 'required'로 만든 discoverable passkey를
  // Android/Google 비밀번호 관리자가 직접 찾아 선택하도록 합니다.
  const optionsJSON = await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
    timeout: REMOTE_LOGIN_TTL_MS,
  });

  const expiresAt = new Date(Date.now() + REMOTE_LOGIN_TTL_MS).toISOString();
  const { data: challengeRow, error: challengeError } = await db.from('webauthn_challenges').insert({
    owner_id: OWNER_ID, purpose: 'authentication', challenge: optionsJSON.challenge, expires_at: expiresAt,
  }).select('id').single();
  if (challengeError) throw challengeError;

  const browserSecret = createOpaqueSecret();
  const phoneSecret = createOpaqueSecret();
  const label = clientLabel(req);
  const { data: remoteRow, error: remoteError } = await db.from('remote_login_requests').insert({
    owner_id: OWNER_ID,
    challenge_id: challengeRow.id,
    browser_secret_hash: hashOpaqueSecret(browserSecret),
    phone_secret_hash: hashOpaqueSecret(phoneSecret),
    options_json: optionsJSON,
    request_device: label,
    status: 'pending',
    expires_at: expiresAt,
  }).select('id').single();
  if (remoteError) throw remoteError;

  const notificationPayload = JSON.stringify({
    title: 'PC 로그인 승인 요청',
    body: `${label}에서 로그인을 요청했습니다. 눌러서 본인 인증 후 승인하세요.`,
    tag: `remote-login-${remoteRow.id}`,
    url: `/phone-auth.html?requestId=${encodeURIComponent(remoteRow.id)}&token=${encodeURIComponent(phoneSecret)}`,
  });

  let delivered = 0;
  for (const sub of subscriptions) {
    try {
      await webpush.sendNotification({ endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } }, notificationPayload, { TTL: 120, urgency: 'high' });
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

  await logEvent(db, { owner_id: OWNER_ID, event_type: 'challenge_issued', challenge_id: challengeRow.id, result: 'ISSUED', detail: `remote login ${preview(optionsJSON.challenge)}` });
  return res.status(200).json({ ok: true, requestId: remoteRow.id, browserSecret, challenge: optionsJSON.challenge, expiresAt, delivered, message: '휴대폰으로 로그인 승인 알림을 보냈습니다.' });
}

async function statusAction(req, res) {
  const requestId = String(req.body?.requestId || '');
  const browserSecret = String(req.body?.browserSecret || '');
  const db = getDB();
  const { data: row, error } = await db.from('remote_login_requests')
    .select('id, browser_secret_hash, status, expires_at, approved_at, completed_at')
    .eq('id', requestId).eq('owner_id', OWNER_ID).maybeSingle();
  if (error) throw error;
  if (!row || !safeSecretMatches(browserSecret, row.browser_secret_hash)) return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 요청을 찾을 수 없습니다.');
  if (row.status === 'pending' && new Date(row.expires_at).getTime() <= Date.now()) {
    await db.from('remote_login_requests').update({ status: 'expired' }).eq('id', row.id).eq('status', 'pending');
    row.status = 'expired';
  }
  return res.status(200).json({ ok: true, status: row.status, approvedAt: row.approved_at, completedAt: row.completed_at, expiresAt: row.expires_at });
}

async function completeAction(req, res) {
  const requestId = String(req.body?.requestId || '');
  const browserSecret = String(req.body?.browserSecret || '');
  const db = getDB();
  const { data: row, error } = await db.from('remote_login_requests')
    .select('id, browser_secret_hash, status, expires_at')
    .eq('id', requestId).eq('owner_id', OWNER_ID).maybeSingle();
  if (error) throw error;
  if (!row || !safeSecretMatches(browserSecret, row.browser_secret_hash)) return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 요청을 찾을 수 없습니다.');
  if (row.status !== 'approved') return jsonError(res, 409, 'NOT_APPROVED', `휴대폰 승인이 완료되지 않았습니다. (${row.status})`);
  if (new Date(row.expires_at).getTime() <= Date.now()) return jsonError(res, 410, 'REQUEST_EXPIRED', '로그인 요청이 만료되었습니다.');

  const completedAt = new Date().toISOString();
  const { data: claimed, error: claimError } = await db.from('remote_login_requests')
    .update({ status: 'completed', completed_at: completedAt }).eq('id', row.id).eq('status', 'approved').select('id');
  if (claimError) throw claimError;
  if (!claimed?.length) return jsonError(res, 409, 'ALREADY_COMPLETED', '이미 완료된 로그인 요청입니다.');

  const rawToken = createSessionToken();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const { error: sessionError } = await db.from('auth_sessions').insert({ owner_id: OWNER_ID, token_hash: hashSessionToken(rawToken), expires_at: expiresAt });
  if (sessionError) throw sessionError;
  setSessionCookie(req, res, rawToken);
  return res.status(200).json({ ok: true, verified: true, session: { type: 'HttpOnly cookie', display: 'task8_session=••••••••', expiresAt }, message: '휴대폰 승인을 확인해 PC 세션을 발급했습니다.' });
}

async function detailsAction(req, res) {
  const requestId = String(req.body?.requestId || '');
  const phoneToken = String(req.body?.phoneToken || '');
  if (!requestId || !phoneToken) return jsonError(res, 400, 'INVALID_REQUEST', '승인 요청 정보가 없습니다.');
  const db = getDB();
  const { data: row, error } = await db.from('remote_login_requests')
    .select('id, phone_secret_hash, options_json, request_device, status, expires_at, created_at')
    .eq('id', requestId).eq('owner_id', OWNER_ID).maybeSingle();
  if (error) throw error;
  if (!row || !safeSecretMatches(phoneToken, row.phone_secret_hash)) return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 승인 요청을 찾을 수 없습니다.');
  if (new Date(row.expires_at).getTime() <= Date.now() && row.status === 'pending') {
    await db.from('remote_login_requests').update({ status: 'expired' }).eq('id', row.id).eq('status', 'pending');
    row.status = 'expired';
  }
  return res.status(200).json({ ok: true, requestId: row.id, requestDevice: row.request_device, status: row.status, expiresAt: row.expires_at, createdAt: row.created_at, optionsJSON: row.status === 'pending' ? row.options_json : null });
}

async function approveAction(req, res) {
  const requestId = String(req.body?.requestId || '');
  const phoneToken = String(req.body?.phoneToken || '');
  const credential = req.body?.credential;
  if (!requestId || !phoneToken || !credential) return jsonError(res, 400, 'INVALID_REQUEST', '로그인 승인 정보가 부족합니다.');

  const db = getDB();
  const { rpID, origin } = getWebAuthnConfig(req);
  const { data: remoteRow, error: remoteError } = await db.from('remote_login_requests').select('*').eq('id', requestId).eq('owner_id', OWNER_ID).maybeSingle();
  if (remoteError) throw remoteError;
  if (!remoteRow || !safeSecretMatches(phoneToken, remoteRow.phone_secret_hash)) return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 승인 요청을 찾을 수 없습니다.');
  if (remoteRow.status !== 'pending') return jsonError(res, 409, 'REQUEST_NOT_PENDING', `이미 처리된 로그인 요청입니다. (${remoteRow.status})`);
  if (new Date(remoteRow.expires_at).getTime() <= Date.now()) {
    await db.from('remote_login_requests').update({ status: 'expired' }).eq('id', requestId).eq('status', 'pending');
    return jsonError(res, 410, 'REQUEST_EXPIRED', '로그인 승인 요청이 만료되었습니다. PC에서 다시 요청해 주세요.');
  }

  const { data: challengeRow, error: challengeError } = await db.from('webauthn_challenges').select('*')
    .eq('id', remoteRow.challenge_id).eq('owner_id', OWNER_ID).eq('purpose', 'authentication').maybeSingle();
  if (challengeError) throw challengeError;
  if (!challengeRow) return jsonError(res, 400, 'CHALLENGE_NOT_FOUND', '로그인 challenge가 없습니다.');
  if (challengeRow.used_at) return jsonError(res, 409, 'CHALLENGE_ALREADY_USED', '이미 사용된 로그인 challenge입니다.');

  const { data: claimed, error: claimError } = await db.from('webauthn_challenges').update({ used_at: new Date().toISOString() })
    .eq('id', challengeRow.id).is('used_at', null).select('id');
  if (claimError) throw claimError;
  if (!claimed?.length) return jsonError(res, 409, 'CHALLENGE_ALREADY_USED', '이미 사용된 로그인 challenge입니다.');

  const { data: passkey, error: passkeyError } = await db.from('passkeys')
    .select('id, credential_id, public_key, counter, transports').eq('owner_id', OWNER_ID).eq('credential_id', String(credential.id || '')).maybeSingle();
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
    await logEvent(db, { owner_id: OWNER_ID, event_type: 'verify_failed', challenge_id: challengeRow.id, credential_hint: preview(credential?.id, 10, 6), result: 'REJECTED', detail: `remote approval failed: ${verifyError.message || '서명 검증 실패'}` });
    return jsonError(res, 401, 'AUTHENTICATION_VERIFY_FAILED', verifyError.message || '패스키 서명 검증에 실패했습니다.');
  }

  if (!verification.verified || !verification.authenticationInfo) {
    await db.from('remote_login_requests').update({ status: 'rejected' }).eq('id', requestId).eq('status', 'pending');
    return jsonError(res, 401, 'NOT_VERIFIED', '패스키 서명이 검증되지 않았습니다.');
  }

  await db.from('passkeys').update({ counter: verification.authenticationInfo.newCounter }).eq('id', passkey.id);
  const approvedAt = new Date().toISOString();
  const { data: updated, error: approveError } = await db.from('remote_login_requests')
    .update({ status: 'approved', approved_at: approvedAt, credential_hint: preview(credential.id, 10, 6) })
    .eq('id', requestId).eq('status', 'pending').select('id');
  if (approveError) throw approveError;
  if (!updated?.length) return jsonError(res, 409, 'REQUEST_ALREADY_HANDLED', '이미 처리된 로그인 요청입니다.');

  await logEvent(db, { owner_id: OWNER_ID, event_type: 'verify_success', challenge_id: challengeRow.id, credential_hint: preview(credential?.id, 10, 6), result: 'VERIFIED', detail: '휴대폰 패스키 공개키 검증 성공 · PC 승인 대기 완료' });
  return res.status(200).json({ ok: true, approved: true, message: '본인 인증이 완료되었습니다. PC 로그인이 승인되었습니다.' });
}

async function rejectAction(req, res) {
  const requestId = String(req.body?.requestId || '');
  const phoneToken = String(req.body?.phoneToken || '');
  const db = getDB();
  const { data: row, error } = await db.from('remote_login_requests').select('id, phone_secret_hash, status')
    .eq('id', requestId).eq('owner_id', OWNER_ID).maybeSingle();
  if (error) throw error;
  if (!row || !safeSecretMatches(phoneToken, row.phone_secret_hash)) return jsonError(res, 404, 'REQUEST_NOT_FOUND', '로그인 승인 요청을 찾을 수 없습니다.');
  if (row.status !== 'pending') return jsonError(res, 409, 'REQUEST_NOT_PENDING', '이미 처리된 로그인 요청입니다.');
  await db.from('remote_login_requests').update({ status: 'rejected' }).eq('id', requestId).eq('status', 'pending');
  return res.status(200).json({ ok: true, rejected: true });
}

const actions = { request: requestAction, status: statusAction, complete: completeAction, details: detailsAction, approve: approveAction, reject: rejectAction };

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 허용됩니다.');
  const action = String(req.body?.action || '');
  const fn = actions[action];
  if (!fn) return jsonError(res, 400, 'INVALID_ACTION', '알 수 없는 원격 로그인 요청입니다.');
  try { return await fn(req, res); }
  catch (error) {
    console.error(`remote/${action}`, error);
    return jsonError(res, 500, 'REMOTE_LOGIN_FAILED', error?.message || '원격 로그인 처리 중 서버 오류가 발생했습니다.');
  }
}

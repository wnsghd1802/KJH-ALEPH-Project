import { noStore, jsonError } from '../_lib/webauthn.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'GET') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'GET 요청만 허용됩니다.');

  const publicKey = process.env.VAPID_PUBLIC_KEY;
  if (!publicKey) {
    return jsonError(res, 503, 'VAPID_NOT_CONFIGURED', '휴대폰 알림용 VAPID_PUBLIC_KEY가 설정되지 않았습니다.');
  }

  return res.status(200).json({ ok: true, publicKey });
}

# Card 3 PASS-style PC login - GitHub 반영 파일

## 교체
- `index.html`
- `package.json`

## 새로 추가
- `sw.js`
- `phone-auth.html`
- `api/_lib/remote-login.js`
- `api/push/public-key.js`
- `api/push/register.js`
- `api/passkey/remote/request.js`
- `api/passkey/remote/details.js`
- `api/passkey/remote/approve.js`
- `api/passkey/remote/reject.js`
- `api/passkey/remote/status.js`
- `api/passkey/remote/complete.js`
- `sql/04_pass_style_remote_login.sql`
- `CARD3_PASS_STYLE_LOGIN.md`

## Vercel 환경 변수
- `VAPID_PUBLIC_KEY`
- `VAPID_PRIVATE_KEY`
- `VAPID_SUBJECT`

VAPID_PRIVATE_KEY는 GitHub에 저장하지 않습니다.

권장 커밋 메시지:

`Add PASS-style phone approval login for PC`

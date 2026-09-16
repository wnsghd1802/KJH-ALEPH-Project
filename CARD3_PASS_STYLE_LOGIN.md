# Card 3 - PASS 앱처럼 휴대폰 승인으로 PC 로그인

이번 버전은 Windows 보안창의 QR/hybrid 선택에 의존하지 않습니다.

## 동작 흐름

1. 휴대폰에서 포트폴리오를 열고 기존 패스키로 한 번 로그인합니다.
2. `이 휴대폰을 로그인 알림 기기로 연결`을 누르고 알림 권한을 허용합니다.
3. 서버가 Web Push 구독 정보를 저장합니다. 개인키는 저장하지 않습니다.
4. PC에서 `휴대폰에 로그인 요청 보내기 (PASS 방식)`을 누릅니다.
5. 서버가 새 WebAuthn challenge와 원격 로그인 요청을 만들고 휴대폰으로 Push 알림을 보냅니다.
6. 휴대폰에 `PC 로그인 승인 요청` 알림이 뜹니다.
7. 알림을 누르면 승인 페이지가 열리고, 휴대폰 패스키로 본인 인증합니다.
8. 서버가 Card 2에서 저장한 공개키로 서명을 검증합니다.
9. 검증 성공 시 원격 요청 상태를 `approved`로 바꿉니다.
10. PC가 승인 상태를 확인하고 자기 브라우저에 HttpOnly 세션 쿠키를 발급받습니다.
11. PC에서 비공개 자료가 자동으로 열립니다.

즉 휴대폰의 패스키 개인키를 PC로 옮기지 않고, 휴대폰이 서명 검증을 통과했다는 서버 상태를 이용해 PC 로그인을 완료합니다.

## 최초 1회 설정

Supabase SQL Editor에서 `sql/04_pass_style_remote_login.sql`을 실행합니다.

Vercel Environment Variables에 다음 3개를 설정합니다.

- `VAPID_PUBLIC_KEY`
- `VAPID_PRIVATE_KEY`
- `VAPID_SUBJECT=https://kjhnet.vercel.app`

VAPID 개인키는 GitHub에 커밋하지 않습니다.

## 휴대폰 연결 시 주의

`/api/push/register`는 로그인 세션이 있는 휴대폰만 등록할 수 있습니다.
따라서 휴대폰에서 먼저 `이 기기에서 패스키 로그인`을 성공한 뒤 `이 휴대폰을 로그인 알림 기기로 연결`을 누릅니다.

## 주요 파일

- `sw.js`: Push 알림 수신 및 알림 클릭 처리
- `phone-auth.html`: 휴대폰 승인 화면
- `api/push/public-key.js`: Push 공개키 전달
- `api/push/register.js`: 휴대폰 Push 구독 저장
- `api/passkey/remote/request.js`: PC 요청 생성 + Push 발송
- `api/passkey/remote/details.js`: 휴대폰 승인 요청 조회
- `api/passkey/remote/approve.js`: 휴대폰 패스키 서명 검증 및 승인
- `api/passkey/remote/reject.js`: 휴대폰 거절
- `api/passkey/remote/status.js`: PC의 승인 상태 확인
- `api/passkey/remote/complete.js`: 승인 완료 후 PC 세션 발급

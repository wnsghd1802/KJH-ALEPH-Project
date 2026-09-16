# Task 8 / Card 3 - 패스키 로그인

## 먼저 할 일
Supabase SQL Editor에서 `sql/03_passkey_card3.sql`을 한 번 실행합니다.

## 구현 흐름
1. `/api/passkey/login/options`가 로그인할 때마다 새 WebAuthn challenge를 생성합니다.
2. challenge는 `webauthn_challenges`에 `purpose=authentication`으로 5분간 저장됩니다.
3. 브라우저/휴대폰의 패스키가 challenge에 서명합니다.
4. `/api/passkey/login/verify`가 `passkeys.public_key`를 읽어 실제 서명을 검증합니다.
5. 성공한 경우에만 `auth_sessions`에 세션 token의 SHA-256 hash를 저장합니다.
6. 브라우저에는 HttpOnly / SameSite=Lax / Secure 쿠키 `task8_session`이 설정됩니다.
7. `/api/private`는 유효한 세션 쿠키가 없으면 항상 401을 반환합니다.

## PC에서 휴대폰 패스키 사용
Windows 보안창의 QR/hybrid 선택에 의존하지 않습니다.
`sql/04_pass_style_remote_login.sql`과 Web Push 설정을 추가하면 PC의 로그인 요청이 연결된 휴대폰 알림으로 전달됩니다.
휴대폰에서 알림을 누르고 패스키 본인 인증을 승인하면 서버가 저장된 공개키로 서명을 검증하고, PC가 승인 상태를 확인한 뒤 자기 브라우저에 HttpOnly 세션을 발급받습니다.
자세한 설정은 `CARD3_PASS_STYLE_LOGIN.md`를 참고합니다.

## 검증 버튼
페이지의 Card 3 패널에는 다음 검증 도구가 있습니다.
- `Challenge 2회 발급`: C27/C28. 두 요청의 challenge가 서로 다른지 화면에 기록합니다.
- `잘못된 서명 테스트`: C30. 정상 패스키 응답의 signature 한 글자를 바꿔 서버에 보내고 공개키 검증 실패를 확인합니다.
- `같은 질문 재사용 테스트`: C31. 직전 성공 요청의 loginId + credential을 그대로 다시 보내고 `CHALLENGE_ALREADY_USED` 거절을 확인합니다.
- `비공개 요청 확인`: C33. 로그인 전 401 / 로그인 후 200을 비교합니다.

## C32 / C34 제출 문장
로그인 성공 뒤 사용자를 구분하는 방식은 서버 세션입니다. 브라우저에는 `task8_session` HttpOnly 쿠키가 설정되고,
DB에는 쿠키 원문이 아니라 SHA-256 hash만 저장됩니다. 제출 화면에는 세션 값을 `task8_session=••••••••`처럼 가려서 표시합니다.

## C35
비밀번호 입력란은 만들지 않았습니다. 로그인은 패스키(WebAuthn)만 사용합니다.

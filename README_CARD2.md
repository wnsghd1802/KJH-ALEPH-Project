# 과제 8 - Card 2 / 패스키 등록

이 버전은 Card 1 위에 실제 WebAuthn 패스키 **등록** 기능을 추가합니다.
Card 3 로그인 기능은 아직 넣지 않았습니다.

## 먼저 해야 하는 설정

### 1. Supabase SQL 실행
`sql/02_passkey_card2.sql` 전체를 Supabase > SQL Editor에서 실행합니다.

생성되는 테이블:
- `webauthn_challenges`: 서버가 만든 일회용 질문 저장
- `passkeys`: 검증이 끝난 공개키/credential 정보 저장

### 2. Vercel 환경 변수 2개 추가
Project > Settings > Environment Variables

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

주의: `SUPABASE_SERVICE_ROLE_KEY`는 절대 HTML/JavaScript에 넣지 않습니다.
Vercel 서버 환경 변수에만 넣습니다.

환경 변수를 넣은 후 Redeploy 합니다.

## Card 2 동작 순서

1. `나만 보기`에서 패스키 이름 입력 (예: `내 PC`)
2. `새 패스키 등록` 클릭
3. `/api/passkey/register/options`가 새 challenge 생성 + DB 보관
4. 브라우저/Windows Hello/비밀번호 관리자가 개인키-공개키 쌍 생성
5. 브라우저는 등록 응답을 `/api/passkey/register/verify`로 전송
6. 서버가 challenge, Origin, RP ID, 사용자 확인 등을 검증
7. 성공하면 `passkeys` 테이블에 공개키를 저장
8. 개인키는 서버로 전송되지 않음

## 등록 취소 테스트
패스키 창에서 취소하면 프론트가 `/api/passkey/register/cancel`을 호출해 사용하지 않은 challenge를 삭제합니다.
`passkeys` 테이블에도 아무 패스키가 추가되지 않습니다.

## Card 2 증거 남기기

- 등록 전/후 화면
- 브라우저 개발자 도구 Network에서 `register/options` 요청과 `register/verify` 응답
- 화면의 `CHALLENGE` 값
- Supabase `passkeys` 테이블에 `public_key`가 저장된 화면
- 패스키 이름과 등록 날짜가 보이는 목록
- 패스키를 어디에 저장했는지 기록 (예: Windows Hello, Google 비밀번호 관리자, 보안 키 등)

## 중요한 제한
Card 2에서는 **첫 패스키 1개만** 공개 등록할 수 있습니다.
한 개가 생긴 뒤에는 등록 API가 409로 막힙니다.
Card 4에서 패스키로 인증된 세션에 한해 두 번째 패스키 등록을 허용하도록 바꿉니다.

## HTTPS
WebAuthn/패스키는 배포 환경에서 HTTPS가 필요합니다. `localhost`는 개발 예외입니다.

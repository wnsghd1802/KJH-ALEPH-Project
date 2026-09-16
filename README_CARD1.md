# 과제 8 - Card 1

## 이번 단계에서 반영한 내용

- 기존 소개 페이지 유지
- 공개 영역과 구분되는 `나만 보기` 비공개 영역 추가
- 비공개 영역에 잠긴 항목 3개 표시
- 실제 비공개 데이터는 `index.html`에 넣지 않음
- `/api/private` 서버 API 추가
- 인증되지 않은 `/api/private` 요청은 HTTP 401 반환
- 패스키 버튼은 Card 2/3에서 실제 기능 연결 예정

## Vercel 배포 구조

```text
/
├─ index.html
└─ api/
   └─ private.js
```

## Card 1 확인

1. 공개 페이지에서 `나만 보기` 영역이 구분되어 보이는지 확인
2. 페이지 소스에서 실제 비공개 값이 없는지 확인
3. 브라우저에서 `/api/private` 직접 접속
4. HTTP 401 / `AUTH_REQUIRED` 응답 확인

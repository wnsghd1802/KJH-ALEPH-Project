// Task 8 - Card 1
// Vercel Serverless Function: /api/private
// Card 3에서 실제 패스키 로그인 세션 검증을 연결합니다.

const PRIVATE_ITEMS = [
  { title: '준비 중인 프로젝트', value: '보안 자동 점검 도구 개선' },
  { title: '개인 메모', value: '네트워크 및 리눅스 실습 복습하기' },
  { title: '다음 목표', value: '패스키 인증 흐름 직접 구현해 보기' }
];

export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({
      ok: false,
      error: 'METHOD_NOT_ALLOWED'
    });
  }

  // Card 1에서는 인증되지 않은 요청이 서버에서 실제로 거절되는지 먼저 확인합니다.
  // Card 3에서 이 부분을 "서버가 발급한 유효한 세션인지 확인"하는 코드로 교체합니다.
  const authenticated = false;

  if (!authenticated) {
    return res.status(401).json({
      ok: false,
      error: 'AUTH_REQUIRED',
      message: '패스키 인증이 필요합니다.'
    });
  }

  return res.status(200).json({
    ok: true,
    items: PRIVATE_ITEMS
  });
}

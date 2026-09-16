import requestHandler from '../../lib/remote/request.js';
import statusHandler from '../../lib/remote/status.js';
import completeHandler from '../../lib/remote/complete.js';
import detailsHandler from '../../lib/remote/details.js';
import approveHandler from '../../lib/remote/approve.js';
import rejectHandler from '../../lib/remote/reject.js';

const handlers = {
  request: requestHandler,
  status: statusHandler,
  complete: completeHandler,
  details: detailsHandler,
  approve: approveHandler,
  reject: rejectHandler,
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'METHOD_NOT_ALLOWED', message: 'POST 요청만 허용됩니다.' });
  }

  const action = String(req.body?.action || '');
  const actionHandler = handlers[action];
  if (!actionHandler) {
    return res.status(400).json({ ok: false, error: 'INVALID_ACTION', message: '알 수 없는 원격 로그인 요청입니다.' });
  }

  return actionHandler(req, res);
}

const SW_VERSION = 'card3-pass-notification-v2';

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (_) {
    data = { body: event.data ? event.data.text() : '로그인 승인 요청이 도착했습니다.' };
  }

  const targetUrl = new URL(data.url || '/', self.location.origin).href;
  const title = data.title || '로그인 승인 요청';
  const options = {
    body: data.body || 'PC에서 로그인을 요청했습니다.',
    tag: data.tag || 'remote-login',
    renotify: true,
    requireInteraction: true,
    data: { url: targetUrl, version: SW_VERSION },
    actions: [
      { action: 'approve', title: '로그인 승인' },
    ],
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  if (event.action && event.action !== 'approve') return;

  const rawUrl = event.notification?.data?.url || '/';
  const targetUrl = new URL(rawUrl, self.location.origin).href;

  // Android Chrome에서 기존 숨은 탭을 navigate/focus 하면 화면이 나타나지 않는
  // 경우가 있어, 알림 클릭은 승인 페이지를 직접 openWindow() 하도록 합니다.
  event.waitUntil((async () => {
    try {
      const opened = await self.clients.openWindow(targetUrl);
      if (opened && 'focus' in opened) await opened.focus();
      return;
    } catch (openError) {
      // openWindow 실패 시에만 기존 창을 찾아 이동시키는 보조 경로를 사용합니다.
      const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      for (const client of windows) {
        if ('navigate' in client) {
          await client.navigate(targetUrl);
          if ('focus' in client) await client.focus();
          return;
        }
      }
      throw openError;
    }
  })());
});

/* Pasteli: recibe los avisos del servidor y los muestra como notificación. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { body: e.data ? e.data.text() : '' }; }
  const title = d.title || 'Pasteli';
  e.waitUntil(self.registration.showNotification(title, {
    body: d.body || '',
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-192.png',
    tag: d.tag || 'pasteli-avisos',
    renotify: true,
    requireInteraction: true,
    vibrate: [200, 100, 200],
    data: { url: d.url || '/#negocio' },
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/#negocio';
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if ('focus' in c) { try { await c.navigate(url); } catch (_) {} return c.focus(); }
    }
    return self.clients.openWindow(url);
  })());
});

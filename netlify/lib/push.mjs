// Envío de notificaciones push (Web Push) a los aparatos registrados.
import { getStore } from '@netlify/blobs';
import webpush from 'web-push';
import crypto from 'node:crypto';

const sys = () => getStore({ name: 'sys', consistency: 'strong' });
const subs = () => getStore({ name: 'push', consistency: 'strong' });

export async function vapid() {
  let k = await sys().get('vapid', { type: 'json' });
  if (!k) {
    const fresh = webpush.generateVAPIDKeys();
    await sys().setJSON('vapid', fresh, { onlyIfNew: true });
    k = (await sys().get('vapid', { type: 'json' })) || fresh;
  }
  return k;
}
export const subKey = endpoint => crypto.createHash('sha1').update(endpoint).digest('hex');

export async function saveSub(sub, meta = {}) {
  if (!sub || typeof sub.endpoint !== 'string' || !/^https:\/\//.test(sub.endpoint) || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) throw new Error('bad_sub');
  await subs().setJSON(subKey(sub.endpoint), { sub: { endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } }, ua: String(meta.ua || '').slice(0, 160), nombre: String(meta.nombre || '').slice(0, 60), alta: new Date().toISOString() });
}
export async function removeSub(endpoint) { await subs().delete(subKey(endpoint)); }
export async function countSubs() { return (await subs().list()).blobs.length; }

/** Envía a todos los aparatos. Devuelve { sent, failed, removed }. */
export async function sendAll(payload) {
  const k = await vapid();
  const opts = { vapidDetails: { subject: 'https://pasteli-app.netlify.app', publicKey: k.publicKey, privateKey: k.privateKey }, TTL: 6 * 3600, urgency: 'normal' };
  const { blobs } = await subs().list();
  let sent = 0, failed = 0, removed = 0;
  await Promise.all(blobs.map(async b => {
    const rec = await subs().get(b.key, { type: 'json' });
    if (!rec) return;
    try { await webpush.sendNotification(rec.sub, JSON.stringify(payload), opts); sent++; }
    catch (e) {
      if (e && (e.statusCode === 404 || e.statusCode === 410)) { await subs().delete(b.key); removed++; }
      else { failed++; console.warn('push', e && e.statusCode, e && e.body); }
    }
  }));
  return { sent, failed, removed };
}

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
  const opts = { vapidDetails: { subject: 'https://pasteli-app.netlify.app', publicKey: k.publicKey, privateKey: k.privateKey }, TTL: 24 * 3600, urgency: 'high' };
  const { blobs } = await subs().list();
  let sent = 0, failed = 0, removed = 0;
  await Promise.all(blobs.map(async b => {
    const rec = await subs().get(b.key, { type: 'json' });
    if (!rec) return;
    try { await webpush.sendNotification(rec.sub, JSON.stringify(payload), opts); sent++; await subs().setJSON(b.key, { ...rec, ok: new Date().toISOString(), err: null }); }
    catch (e) {
      if (e && (e.statusCode === 404 || e.statusCode === 410)) { await subs().delete(b.key); removed++; }
      else { failed++; console.warn('push', e && e.statusCode, e && e.body); await subs().setJSON(b.key, { ...rec, err: { at: new Date().toISOString(), code: (e && e.statusCode) || 0 } }); }
    }
  }));
  return { sent, failed, removed };
}

/** Estado de los aparatos registrados (para la pantalla de ajustes). */
export async function listSubs() {
  const { blobs } = await subs().list();
  const out = [];
  for (const b of blobs) { const r = await subs().get(b.key, { type: 'json' }); if (r) out.push({ ua: r.ua, nombre: r.nombre, alta: r.alta, ok: r.ok || null, err: r.err || null }); }
  return out;
}
export async function logRun(entry) { await sys().setJSON('lastRun', { at: new Date().toISOString(), ...entry }); }
export async function lastRun() { return sys().get('lastRun', { type: 'json' }); }

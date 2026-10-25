// Servidor de Pasteli en Netlify: acceso con PIN + contraseña, base de datos y archivos del negocio.
// Todo lo privado exige un token firmado; solo el catálogo publicado y las fotos son públicos.
import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
import { vapid, saveSub, removeSub, sendAll, countSubs } from '../lib/push.mjs';
import { localNow, readCfg, compose, toPayload } from '../lib/avisos.mjs';

export const config = { path: ['/api/*', '/_blob/*'] };

const DEFAULT_PIN = '2003';
const TOKEN_HOURS = 12;
const MAX_UPLOAD = 5.5 * 1024 * 1024;
const COLS = ['productos', 'proveedores', 'facturas', 'facturas_cli', 'cxc', 'ventas', 'movs', 'pedidos', 'bitacora', 'config', 'cargas'];
const SAFE_SEG = /^[A-Za-z0-9_\-.~:@+]{1,200}$/;
const PRIVATE_CFG = ['pin', 'passHash', 'passSalt'];

const st = name => getStore({ name, consistency: 'strong' });
const json = (body, status = 200, extra = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra } });
const err = (code, status = 400, extra = {}) => json({ error: code, ...extra }, status);

/* ---------- secretos y credenciales ---------- */
async function secret() {
  const s = st('sys');
  let v = await s.get('secret');
  if (v) return v;
  const fresh = crypto.randomBytes(32).toString('hex');
  await s.set('secret', fresh, { onlyIfNew: true });
  return (await s.get('secret')) || fresh;
}
const hash = (txt, salt) => crypto.scryptSync(String(txt), salt, 32).toString('hex');
const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
async function getAuth() { return (await st('sys').get('auth', { type: 'json' })) || null; }
async function saveAuth(a) { await st('sys').setJSON('auth', a); }

async function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', await secret()).update(body).digest('base64url');
  return body + '.' + mac;
}
async function verify(req) {
  const h = req.headers.get('authorization') || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [body, mac] = tok.split('.');
  if (!body || !mac) return null;
  const good = crypto.createHmac('sha256', await secret()).update(body).digest('base64url');
  if (!same(mac, good)) return null;
  let p; try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
  if (!p || Date.now() > p.exp) return null;
  const a = await getAuth();
  if (!a || a.v !== p.v) return null;
  return p;
}

/* ---------- límite de intentos ---------- */
async function locked() {
  const t = (await st('sys').get('tries', { type: 'json' })) || { n: 0, until: 0 };
  return { t, wait: t.until > Date.now() ? Math.ceil((t.until - Date.now()) / 1000) : 0 };
}
async function fail(t) {
  t.n = (t.n || 0) + 1;
  if (t.n >= 5) { t.until = Date.now() + 60000 * Math.min(30, 2 ** Math.floor(t.n / 5 - 1)); }
  await st('sys').setJSON('tries', t);
}
async function okTries() { await st('sys').setJSON('tries', { n: 0, until: 0 }); }

/* ---------- base de datos (un blob por documento: d/<colección>/<id>) ---------- */
function splitPath(p) {
  const parts = String(p || '').split('/');
  if (parts.length !== 2 || !COLS.includes(parts[0]) || !SAFE_SEG.test(parts[1])) return null;
  return parts;
}
const dkey = (c, id) => `d/${c}/${id}`;
function clean(c, id, data) {
  if (c === 'config' && id === 'app' && data && typeof data === 'object') { const o = { ...data }; PRIVATE_CFG.forEach(k => delete o[k]); return o; }
  return data;
}
async function listCol(c) {
  const { blobs } = await st('db').list({ prefix: `d/${c}/` });
  const etags = {};
  for (const b of blobs) etags[b.key.slice(c.length + 3)] = b.etag;
  return etags;
}
const sig = etags => crypto.createHash('sha1').update(Object.keys(etags).sort().map(k => k + ':' + etags[k]).join('|')).digest('hex');

async function writeDoc(c, id, data, mode) {
  const s = st('db'), key = dkey(c, id);
  if (mode === 'delete') { await s.delete(key); return true; }
  if (JSON.stringify(data).length > 1_000_000) throw new Error('too_big');
  if (mode === 'set') { await s.setJSON(key, clean(c, id, data)); return true; }
  for (let i = 0; i < 6; i++) { // update = mezcla de campos de primer nivel, con control de concurrencia
    const cur = await s.getWithMetadata(key, { type: 'json' });
    if (!cur) { const r = await s.setJSON(key, clean(c, id, data), { onlyIfNew: true }); if (r.modified) return true; continue; }
    const next = { ...(cur.data || {}) };
    for (const [k, v] of Object.entries(data)) { if (v && typeof v === 'object' && v.__delete__ === true) delete next[k]; else next[k] = v; }
    const r = await s.setJSON(key, clean(c, id, next), { onlyIfMatch: cur.etag });
    if (r.modified) return true;
  }
  throw new Error('conflict');
}

/* ---------- archivos ---------- */
const INLINE = /^(image\/(png|jpeg|gif|webp)|application\/pdf|video\/(mp4|webm)|text\/(plain|csv)|audio\/(mpeg|mp4|ogg|wav))$/;
async function serveAsset(id) {
  if (!/^[a-f0-9]{32}$/.test(id)) return new Response('No encontrado', { status: 404 });
  const r = await st('assets').getWithMetadata(id, { type: 'arrayBuffer' });
  if (!r) return new Response('No encontrado', { status: 404 });
  const m = r.metadata || {};
  let type = String(m.type || 'application/octet-stream');
  const inline = INLINE.test(type) || type === 'font/woff2' || type === 'image/svg+xml';
  if (type === 'image/svg+xml') { /* se sirve como imagen con CSP estricta */ }
  else if (!inline) type = 'application/octet-stream';
  const name = String(m.name || 'archivo').replace(/[\r\n"]/g, '');
  return new Response(r.data, { headers: {
    'content-type': type,
    'content-disposition': `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(name)}`,
    'cache-control': 'public, max-age=31536000, immutable',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox",
  } });
}

/* ---------- rutas ---------- */
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;
  try {
    if (path.startsWith('/_blob/')) return serveAsset(path.slice(7));
    const route = path.replace(/^\/api\//, '');
    const body = req.method === 'POST' && route !== 'asset' ? await req.json().catch(() => ({})) : {};

    // Catálogo publicado (público para leer)
    if (route === 'catalog' && req.method === 'GET') {
      const cat = await st('sys').get('catalog', { type: 'json' });
      return json({ cat: cat || null });
    }

    // Estado del acceso: ¿ya hay contraseña creada?
    if (route === 'auth/status') { const a = await getAuth(); return json({ setup: !!a }); }

    // Entrar: PIN + contraseña (o crear la contraseña la primera vez)
    if (route === 'auth/login' && req.method === 'POST') {
      const { t, wait } = await locked();
      if (wait) return err('locked', 429, { wait });
      const pin = String(body.pin || ''), pass = String(body.pass || '');
      let a = await getAuth();
      if (!a) {
        if (!same(pin, DEFAULT_PIN)) { await fail(t); return err('bad_login', 401); }
        if (pass.length < 8) return err('weak', 400);
        const ps = crypto.randomBytes(16).toString('hex'), ws = crypto.randomBytes(16).toString('hex');
        a = { v: 1, pinSalt: ps, pinHash: hash(pin, ps), passSalt: ws, passHash: hash(pass, ws), creado: new Date().toISOString() };
        const r = await st('sys').setJSON('auth', a, { onlyIfNew: true });
        if (!r.modified) return err('race', 409);
      } else {
        const okPin = same(hash(pin, a.pinSalt), a.pinHash), okPass = same(hash(pass, a.passSalt), a.passHash);
        if (!okPin || !okPass) { await fail(t); return err('bad_login', 401); }
      }
      await okTries();
      return json({ token: await sign({ v: a.v, exp: Date.now() + TOKEN_HOURS * 3600e3 }) });
    }

    // A partir de aquí todo exige sesión
    const who = await verify(req);
    if (!who) return err('unauthorized', 401);

    if (route === 'auth/pin' && req.method === 'POST') {
      const pin = String(body.pin || '');
      if (!/^\d{4}$/.test(pin)) return err('bad_format');
      const a = await getAuth(); const ps = crypto.randomBytes(16).toString('hex');
      a.pinSalt = ps; a.pinHash = hash(pin, ps); a.v++; await saveAuth(a);
      return json({ ok: true, token: await sign({ v: a.v, exp: Date.now() + TOKEN_HOURS * 3600e3 }) });
    }
    if (route === 'auth/pass' && req.method === 'POST') {
      const a = await getAuth();
      if (!same(hash(String(body.cur || ''), a.passSalt), a.passHash)) return err('bad_pass', 401);
      const n = String(body.pass || ''); if (n.length < 8) return err('weak');
      const ws = crypto.randomBytes(16).toString('hex');
      a.passSalt = ws; a.passHash = hash(n, ws); a.v++; await saveAuth(a);
      return json({ ok: true, token: await sign({ v: a.v, exp: Date.now() + TOKEN_HOURS * 3600e3 }) });
    }

    // Avisos push (computadora y celular)
    if (route === 'push/key') { const k = await vapid(); return json({ key: k.publicKey, n: await countSubs() }); }
    if (route === 'push/sub' && req.method === 'POST') {
      try { await saveSub(body.sub, { ua: req.headers.get('user-agent'), nombre: body.nombre }); } catch { return err('bad_request'); }
      return json({ ok: true, n: await countSubs() });
    }
    if (route === 'push/unsub' && req.method === 'POST') {
      if (typeof body.endpoint === 'string') await removeSub(body.endpoint);
      return json({ ok: true, n: await countSubs() });
    }
    if (route === 'push/test' && req.method === 'POST') {
      const r = await sendAll({ title: 'Pasteli', body: 'Los avisos funcionan en este aparato ✓', tag: 'pasteli-test', url: '/#negocio' });
      return json({ ok: true, ...r });
    }
    if (route === 'push/preview' && req.method === 'POST') {
      const app = await st('db').get('d/config/app', { type: 'json' });
      const cfg = readCfg(app);
      const lines = await compose(cfg, localNow(), { general: true, pedidos: true });
      return json({ n: lines.length, payload: toPayload(lines) });
    }

    // Publicar catálogo
    if (route === 'catalog' && req.method === 'POST') {
      if (!body.cat || typeof body.cat !== 'object') return err('bad_request');
      if (JSON.stringify(body.cat).length > 4_000_000) return err('too_big');
      await st('sys').setJSON('catalog', body.cat);
      return json({ ok: true });
    }

    // Sincronizar: firma por colección; si cambió, devuelve los etags de cada documento
    if (route === 'db/sync' && req.method === 'POST') {
      const want = Array.isArray(body.cols) ? body.cols.filter(c => COLS.includes(c)) : [];
      const have = body.sig || {};
      const out = {};
      await Promise.all(want.map(async c => { const e = await listCol(c); const s = sig(e); if (have[c] !== s) out[c] = { sig: s, etags: e }; }));
      return json({ changed: out });
    }
    // Leer documentos concretos
    if (route === 'db/get' && req.method === 'POST') {
      const c = body.col; if (!COLS.includes(c)) return err('bad_request');
      const ids = (Array.isArray(body.ids) ? body.ids : []).filter(i => SAFE_SEG.test(i)).slice(0, 2000);
      const s = st('db'); const docs = {};
      await Promise.all(ids.map(async id => { const r = await s.getWithMetadata(dkey(c, id), { type: 'json' }); if (r) docs[id] = { data: clean(c, id, r.data), etag: r.etag }; }));
      return json({ docs });
    }
    // Escribir
    if (route === 'db/write' && req.method === 'POST') {
      const p = splitPath(body.path); if (!p) return err('bad_path');
      const mode = ['set', 'update', 'delete'].includes(body.mode) ? body.mode : 'update';
      if (mode !== 'delete' && (!body.data || typeof body.data !== 'object' || Array.isArray(body.data))) return err('bad_request');
      await writeDoc(p[0], p[1], body.data, mode);
      return json({ ok: true });
    }
    // Importar datos (de la app anterior)
    if (route === 'db/import' && req.method === 'POST') {
      const docs = body.docs && typeof body.docs === 'object' ? body.docs : {};
      let n = 0;
      for (const [k, v] of Object.entries(docs)) { const p = splitPath(k); if (!p || !v || typeof v !== 'object') continue; await writeDoc(p[0], p[1], v, 'set'); n++; }
      return json({ ok: true, n });
    }

    // Subir archivo
    if (route === 'asset' && req.method === 'POST') {
      const buf = await req.arrayBuffer();
      if (!buf.byteLength) return err('empty');
      if (buf.byteLength > MAX_UPLOAD) return err('too_large', 413);
      const id = crypto.randomBytes(16).toString('hex');
      const type = String(req.headers.get('content-type') || 'application/octet-stream').split(';')[0].trim().slice(0, 120);
      let name = 'archivo'; try { name = decodeURIComponent(req.headers.get('x-name') || 'archivo').slice(0, 200); } catch {}
      await st('assets').set(id, buf, { metadata: { type, name, size: buf.byteLength, subido: new Date().toISOString() } });
      return json({ id, url: '/_blob/' + id, sizeBytes: buf.byteLength, contentType: type });
    }

    return err('not_found', 404);
  } catch (e) {
    console.error(e);
    return err(e && e.message === 'conflict' ? 'conflict' : e && e.message === 'too_big' ? 'too_big' : 'server_error', e && e.message === 'conflict' ? 409 : 500);
  }
};

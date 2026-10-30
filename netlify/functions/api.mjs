// Servidor de Pasteli en Netlify: acceso con PIN + contraseña, base de datos y archivos del negocio.
// Todo lo privado exige un token firmado; solo el catálogo publicado y las fotos son públicos.
import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
import { vapid, saveSub, removeSub, sendAll, countSubs, listSubs, lastRun } from '../lib/push.mjs';
import { localNow, readCfg, compose, toPayload } from '../lib/avisos.mjs';

export const config = { path: ['/api/*', '/_blob/*'] };

const DEFAULT_PIN = '2003';
const TOKEN_HOURS = 12;
const MAX_UPLOAD = 5.5 * 1024 * 1024;
const COLS = ['productos', 'proveedores', 'facturas', 'facturas_cli', 'cxc', 'ventas', 'movs', 'pedidos', 'bitacora', 'config', 'cargas', 'ordenes'];
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
/* ---------- panel CP: PIN propio y solo las pestañas que el dueño elija ---------- */
const CP_TABS = { ven: ['ventas'], fin: ['facturas', 'proveedores'], cxp: ['facturas', 'proveedores'], cxc: ['cxc'] };
async function getCp() { return (await st('sys').get('cp', { type: 'json' })) || null; }
const cpCols = cp => { const o = new Set(); ((cp && cp.tabs) || []).forEach(t => (CP_TABS[t] || []).forEach(c => o.add(c))); return o; };

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
  if (p.role === 'cp') { const cp = await getCp(); if (!cp || cp.v !== p.cv) return null; p.cpRec = cp; }
  return p;
}

/* ---------- límite de intentos ---------- */
async function locked(key = 'tries') {
  const t = (await st('sys').get(key, { type: 'json' })) || { n: 0, until: 0 };
  return { t, wait: t.until > Date.now() ? Math.ceil((t.until - Date.now()) / 1000) : 0 };
}
async function fail(t, key = 'tries') {
  t.n = (t.n || 0) + 1;
  if (t.n >= 5) { t.until = Date.now() + 60000 * Math.min(30, 2 ** Math.floor(t.n / 5 - 1)); }
  await st('sys').setJSON(key, t);
}
async function okTries(key = 'tries') { await st('sys').setJSON(key, { n: 0, until: 0 }); }

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
    const body = req.method === 'POST' && route !== 'asset' && route !== 'pub/upload' ? await req.json().catch(() => ({})) : {};

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

    // Subida pública (foto de ticket / constancia desde el formulario de clientes). Solo imagen/PDF, límite de tamaño y de frecuencia.
    if (route === 'pub/upload' && req.method === 'POST') {
      const hour = new Date().toISOString().slice(0, 13);
      const rl = (await st('sys').get('pubrate', { type: 'json' })) || {};
      if (rl.h !== hour) { rl.h = hour; rl.n = 0; }
      if (rl.n >= 60) return err('rate', 429);
      const buf = Buffer.from(await req.arrayBuffer());
      if (!buf.length) return err('empty');
      if (buf.length > 8 * 1024 * 1024) return err('too_large', 413);
      const hd = buf.subarray(0, 12);
      let type = null;
      if (hd[0] === 0xff && hd[1] === 0xd8) type = 'image/jpeg';
      else if (hd.subarray(0, 4).toString('latin1') === '\x89PNG') type = 'image/png';
      else if (hd.subarray(0, 4).toString('latin1') === 'RIFF' && hd.subarray(8, 12).toString('latin1') === 'WEBP') type = 'image/webp';
      else if (hd.subarray(0, 5).toString('latin1') === '%PDF-') type = 'application/pdf';
      if (!type) return err('bad_type', 415);
      rl.n++; await st('sys').setJSON('pubrate', rl);
      const id = crypto.randomBytes(16).toString('hex');
      let name = 'archivo'; try { name = decodeURIComponent(req.headers.get('x-name') || 'archivo').slice(0, 120); } catch {}
      await st('assets').set(id, buf, { metadata: { type, name, size: buf.length, subido: new Date().toISOString(), pub: true } });
      return json({ id, url: '/_blob/' + id });
    }

    // Solicitud de factura desde el formulario de clientes: se guarda en Facturas del panel (además del WhatsApp).
    if (route === 'pub/factura' && req.method === 'POST') {
      const hour = new Date().toISOString().slice(0, 13);
      const rl = (await st('sys').get('pubfac', { type: 'json' })) || {};
      if (rl.h !== hour) { rl.h = hour; rl.n = 0; }
      if (rl.n >= 40) return err('rate', 429);
      const str = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
      const d = {
        nombre: str(body.nombre, 160), rfc: str(body.rfc, 13).toUpperCase(), regimen: str(body.regimen, 6), cp: str(body.cp, 5), uso: str(body.uso, 6),
        correo: str(body.correo, 120), tel: str(body.tel, 30), fechaCompra: str(body.fechaCompra, 10), total: Math.max(0, Math.min(1e7, Number(body.total) || 0)),
        ticket: str(body.ticket, 60), pago: str(body.pago, 6), notas: str(body.notas, 300),
      };
      if (!d.nombre || !/^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/.test(d.rfc) || !/^\d{5}$/.test(d.cp) || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(d.correo)) return err('bad_request', 400);
      const id = /^fc-[a-z0-9]{6,20}$/.test(String(body.id || '')) ? body.id : 'fc-' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
      const file = async (u, label) => {
        const m = /\/_blob\/([a-f0-9]{32})$/.exec(String(u || '')); if (!m) return null;
        const r = await st('assets').getWithMetadata(m[1], { type: 'arrayBuffer' }); const md = r && r.metadata;
        if (!md || !md.pub) return null;
        return { id: m[1], nombre: String(md.name || label).slice(0, 120), tipo: String(md.type || ''), peso: Number(md.size) || 0 };
      };
      const t = await file(body.ticketUrl, 'ticket'), c = await file(body.csfUrl, 'constancia');
      const rec = { ...d, estado: 'pendiente', creado: new Date().toISOString(), origen: 'web', ...(t ? { ticketImg: t } : {}), ...(c ? { constancia: c } : {}) };
      const r = await st('db').setJSON(dkey('facturas_cli', id), rec, { onlyIfNew: true });
      if (r.modified) {
        rl.n++; await st('sys').setJSON('pubfac', rl);
        try { await sendAll({ title: 'Pasteli · Nueva solicitud de factura', body: `${d.nombre} · $${Math.round(d.total)}`, tag: 'pasteli-factura-' + id, url: '/#negocio' }); } catch (e) { console.warn('push factura', e && e.message); }
      }
      return json({ ok: true, id });
    }

    // Entrar al panel CP (solo PIN)
    if (route === 'auth/cp' && req.method === 'POST') {
      const a = await getAuth(), cp = await getCp();
      if (!a || !cp || !cp.hash) return err('no_cp', 404);
      const { t, wait } = await locked('triescp');
      if (wait) return err('locked', 429, { wait });
      if (!same(hash(String(body.pin || ''), cp.salt), cp.hash)) { await fail(t, 'triescp'); return err('bad_login', 401); }
      await okTries('triescp');
      return json({ token: await sign({ v: a.v, role: 'cp', cv: cp.v, exp: Date.now() + TOKEN_HOURS * 3600e3 }), tabs: cp.tabs || [] });
    }
    if (route === 'auth/cpinfo') { const cp = await getCp(); return json({ has: !!(cp && cp.hash) }); }

    // A partir de aquí todo exige sesión
    const who = await verify(req);
    if (!who) return err('unauthorized', 401);
    const isCp = who.role === 'cp';
    if (isCp && !['db/sync', 'db/get', 'db/write', 'asset'].includes(route)) return err('forbidden', 403);
    const cpAllowed = isCp ? cpCols(who.cpRec) : null;
    const cpCfgOk = id => id === 'app' || id === 'archivos';

    // Lectura con IA (PDF, Excel, fotos). Necesita ANTHROPIC_API_KEY en Netlify; tope diario para controlar el gasto.
    if (route === 'ai/status') {
      const lim = Number(process.env.AI_DAILY_LIMIT) || 40; const day = new Date().toISOString().slice(0, 10);
      const u = (await st('sys').get('aiuse', { type: 'json' })) || {};
      return json({ enabled: !!process.env.ANTHROPIC_API_KEY, left: Math.max(0, lim - (u.d === day ? u.n : 0)), limit: lim });
    }
    if (route === 'ai/start' && req.method === 'POST') {
      if (!process.env.ANTHROPIC_API_KEY) return err('no_key', 503);
      const lim = Number(process.env.AI_DAILY_LIMIT) || 40; const day = new Date().toISOString().slice(0, 10);
      const u = (await st('sys').get('aiuse', { type: 'json' })) || {};
      const n = u.d === day ? u.n : 0;
      if (n >= lim) return err('daily_limit', 429, { limit: lim });
      const prompt = String(body.prompt || '').slice(0, 250000);
      const images = (Array.isArray(body.images) ? body.images : []).slice(0, 8).filter(im => im && /^image\/(jpeg|png|webp|gif)$/.test(im.media_type) && typeof im.data === 'string' && im.data.length < 3_500_000);
      if (!prompt) return err('bad_request');
      await st('sys').setJSON('aiuse', { d: day, n: n + 1 });
      const id = crypto.randomBytes(16).toString('hex'), nonce = crypto.randomBytes(16).toString('hex');
      await st('ai').setJSON('job/' + id, { status: 'pending', nonce, prompt, images, at: Date.now() });
      const origin = new URL(req.url).origin;
      const r = await fetch(origin + '/.netlify/functions/ai-background', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id, nonce }) }).catch(() => null);
      if (!r || (r.status !== 202 && !r.ok)) return err('start_failed', 502);
      return json({ id });
    }
    if (route === 'ai/result') {
      const id = url.searchParams.get('id') || '';
      if (!/^[a-f0-9]{32}$/.test(id)) return err('bad_request');
      const job = await st('ai').get('job/' + id, { type: 'json' });
      if (!job) return err('not_found', 404);
      if (job.status === 'done' || job.status === 'error') { await st('ai').delete('job/' + id); return json({ status: job.status, result: job.result || null, text: job.text || null, error: job.error || null }); }
      if (Date.now() - job.at > 10 * 60_000) { await st('ai').delete('job/' + id); return json({ status: 'error', error: 'timeout' }); }
      return json({ status: job.status });
    }

    if (route === 'cp/get') { const cp = await getCp(); return json({ has: !!(cp && cp.hash), tabs: (cp && cp.tabs) || [] }); }
    if (route === 'cp/set' && req.method === 'POST') {
      const cp0 = await getCp(); const tabs = (Array.isArray(body.tabs) ? body.tabs : (cp0 && cp0.tabs) || []).filter(t => CP_TABS[t]);
      if (!tabs.length) return err('need_tab', 400);
      let salt = cp0 && cp0.salt, h = cp0 && cp0.hash;
      if (body.pin !== undefined && body.pin !== '') {
        if (!/^\d{4}$/.test(String(body.pin))) return err('bad_format', 400);
        salt = crypto.randomBytes(16).toString('hex'); h = hash(String(body.pin), salt);
      }
      if (!h) return err('need_pin', 400);
      await st('sys').setJSON('cp', { salt, hash: h, tabs, v: ((cp0 && cp0.v) || 0) + 1 });
      return json({ ok: true, has: true, tabs });
    }
    if (route === 'cp/off' && req.method === 'POST') { await st('sys').delete('cp'); return json({ ok: true }); }

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
    if (route === 'push/status') return json({ run: await lastRun(), subs: await listSubs(), hora: new Date().toISOString() });
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
      const want = (Array.isArray(body.cols) ? body.cols.filter(c => COLS.includes(c)) : []).filter(c => !isCp || cpAllowed.has(c) || c === 'config');
      const have = body.sig || {};
      const out = {};
      await Promise.all(want.map(async c => { const e = await listCol(c); const s = sig(e); if (have[c] !== s) out[c] = { sig: s, etags: e }; }));
      return json({ changed: out });
    }
    // Leer documentos concretos
    if (route === 'db/get' && req.method === 'POST') {
      const c = body.col; if (!COLS.includes(c)) return err('bad_request');
      if (isCp && !cpAllowed.has(c) && c !== 'config') return err('forbidden', 403);
      const ids = (Array.isArray(body.ids) ? body.ids : []).filter(i => SAFE_SEG.test(i) && (!isCp || c !== 'config' || cpCfgOk(i))).slice(0, 2000);
      const s = st('db'); const docs = {};
      await Promise.all(ids.map(async id => { const r = await s.getWithMetadata(dkey(c, id), { type: 'json' }); if (r) { let d = clean(c, id, r.data); if (isCp && c === 'config' && id === 'app') { d = { ...d }; ['finHash', 'finSalt', 'cpTabs'].forEach(k => delete d[k]); } docs[id] = { data: d, etag: r.etag }; } }));
      return json({ docs });
    }
    // Escribir
    if (route === 'db/write' && req.method === 'POST') {
      const p = splitPath(body.path); if (!p) return err('bad_path');
      if (isCp && !(cpAllowed.has(p[0]) || (p[0] === 'config' && p[1] === 'archivos'))) return err('forbidden', 403);
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

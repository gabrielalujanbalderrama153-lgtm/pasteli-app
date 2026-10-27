// Se ejecuta cada hora (en punto) y manda los avisos que toquen según lo configurado en el panel.
import { getStore } from '@netlify/blobs';
import { localNow, readCfg, dueNow, compose, toPayload } from '../lib/avisos.mjs';
import { sendAll, countSubs, logRun } from '../lib/push.mjs';

export const config = { schedule: '0 * * * *' };

export default async () => {
  const now = localNow();
  const app = await getStore({ name: 'db', consistency: 'strong' }).get('d/config/app', { type: 'json' });
  const cfg = readCfg(app);
  const due = dueNow(cfg, now);
  if (!due.general && !due.pedidos) { await logRun({ reason: 'no_toca', hora: now.hour }); return new Response('nada por enviar'); }
  if (!(await countSubs())) { await logRun({ reason: 'sin_aparatos', hora: now.hour }); return new Response('sin aparatos registrados'); }

  // evita duplicados si el programador se ejecuta dos veces en la misma hora
  const sys = getStore({ name: 'sys', consistency: 'strong' });
  const key = `${now.date}T${now.hour}`;
  const last = await sys.get('lastAvisos', { type: 'json' });
  if (last && last.key === key) return new Response('ya enviado');

  const lines = await compose(cfg, now, due);
  const payload = toPayload(lines);
  if (!payload) { await sys.setJSON('lastAvisos', { key }); await logRun({ reason: 'todo_en_orden', hora: now.hour }); return new Response('todo en orden'); }
  const r = await sendAll(payload);
  if (r.sent) await sys.setJSON('lastAvisos', { key });
  await logRun({ reason: r.sent ? 'enviado' : 'fallo', hora: now.hour, lineas: lines.length, ...r });
  console.log('avisos', key, lines.length, JSON.stringify(r));
  return new Response(JSON.stringify(r));
};

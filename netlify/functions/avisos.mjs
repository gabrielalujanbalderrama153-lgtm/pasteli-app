// Se ejecuta cada hora (en punto) y manda los avisos que toquen según lo configurado en el panel.
import { getStore } from '@netlify/blobs';
import { localNow, readCfg, dueNow, compose, toPayload } from '../lib/avisos.mjs';
import { sendAll, countSubs } from '../lib/push.mjs';

export const config = { schedule: '0 * * * *' };

export default async () => {
  const now = localNow();
  const app = await getStore({ name: 'db', consistency: 'strong' }).get('d/config/app', { type: 'json' });
  const cfg = readCfg(app);
  const due = dueNow(cfg, now);
  if (!due.general && !due.pedidos) return new Response('nada por enviar');
  if (!(await countSubs())) return new Response('sin aparatos registrados');

  // evita duplicados si el programador se ejecuta dos veces en la misma hora
  const sys = getStore({ name: 'sys', consistency: 'strong' });
  const key = `${now.date}T${now.hour}`;
  const last = await sys.get('lastAvisos', { type: 'json' });
  if (last && last.key === key) return new Response('ya enviado');
  await sys.setJSON('lastAvisos', { key });

  const lines = await compose(cfg, now, due);
  const payload = toPayload(lines);
  if (!payload) return new Response('todo en orden');
  const r = await sendAll(payload);
  console.log('avisos', key, lines.length, JSON.stringify(r));
  return new Response(JSON.stringify(r));
};

// Lectura con IA en segundo plano (hasta 15 min): lee la tarea guardada, llama a Anthropic y guarda el resultado.
import { getStore } from '@netlify/blobs';

const ai = () => getStore({ name: 'ai', consistency: 'strong' });

function extractJson(text) {
  const t = String(text || '').trim();
  const fence = /```(?:json)?\s*([\s\S]*?)```/i.exec(t);
  const cand = fence ? fence[1] : t;
  const a = cand.indexOf('{'), b = cand.lastIndexOf('}');
  if (a < 0 || b <= a) throw new Error('no_json');
  return JSON.parse(cand.slice(a, b + 1));
}

export default async (req) => {
  let id = '', nonce = '';
  try { ({ id, nonce } = await req.json()); } catch { return new Response('bad', { status: 400 }); }
  if (!/^[a-f0-9]{32}$/.test(String(id))) return new Response('bad', { status: 400 });
  const job = await ai().get('job/' + id, { type: 'json' });
  if (!job || job.nonce !== nonce || job.status !== 'pending') return new Response('nope', { status: 403 });
  await ai().setJSON('job/' + id, { ...job, status: 'running' });
  const key = process.env.ANTHROPIC_API_KEY;
  try {
    if (!key) throw new Error('no_key');
    const content = [
      ...(job.images || []).map(im => ({ type: 'image', source: { type: 'base64', media_type: im.media_type, data: im.data } })),
      { type: 'text', text: job.prompt },
    ];
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: process.env.AI_MODEL || 'claude-sonnet-5-5', max_tokens: 8000, messages: [{ role: 'user', content }] }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((j && j.error && j.error.type) || 'http_' + r.status);
    const text = ((j.content || []).find(c => c.type === 'text') || {}).text || '';
    let out = null; try { out = extractJson(text); } catch { /* el cliente decide */ }
    await ai().setJSON('job/' + id, { status: 'done', at: Date.now(), result: out, text: out ? undefined : text.slice(0, 4000) });
  } catch (e) {
    console.error('ai', e && e.message);
    await ai().setJSON('job/' + id, { status: 'error', at: Date.now(), error: String((e && e.message) || 'error').slice(0, 80) });
  }
  return new Response('ok');
};

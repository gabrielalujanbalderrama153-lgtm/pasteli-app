// Cálculo de los avisos del negocio (mismas reglas que el panel) y de cuándo toca enviarlos.
import { getStore } from '@netlify/blobs';

export const TZ = 'America/Chihuahua';
const db = () => getStore({ name: 'db', consistency: 'strong' });

export function localNow(d = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hourCycle: 'h23', weekday: 'short',
  }).formatToParts(d).map(p => [p.type, p.value]));
  const dow = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }[parts.weekday];
  return { date: `${parts.year}-${parts.month}-${parts.day}`, hour: +parts.hour, dow };
}
export const daysBetween = (fromISO, toISO) => Math.round((new Date(toISO + 'T12:00:00Z') - new Date(fromISO + 'T12:00:00Z')) / 864e5);

async function readCol(c) {
  const s = db();
  const { blobs } = await s.list({ prefix: `d/${c}/` });
  const out = [];
  for (let i = 0; i < blobs.length; i += 25) {
    const part = await Promise.all(blobs.slice(i, i + 25).map(async b => {
      const v = await s.get(b.key, { type: 'json' });
      return v ? { id: b.key.slice(c.length + 3), ...v } : null;
    }));
    out.push(...part.filter(Boolean));
  }
  return out;
}
async function readDoc(c, id) { return db().get(`d/${c}/${id}`, { type: 'json' }); }

const sem = p => {
  if (p.min == null || p.max == null) return 'gris';
  const s = Number(p.stock) || 0;
  if (s <= p.min) return 'rojo';
  if (s <= Math.max(p.min, p.max / 2)) return 'amarillo';
  return 'verde';
};
const pedirQ = p => Math.max(0, Math.ceil(((p.max ?? 0) - (Number(p.stock) || 0)) * 2) / 2);
const qty = n => (n == null || isNaN(n)) ? '—' : Number(n).toLocaleString('es-MX', { maximumFractionDigits: 2 });
const hora12 = s => { if (!s) return ''; let [h, m] = s.split(':').map(Number); const ap = h >= 12 ? 'pm' : 'am'; h = h % 12 || 12; return `${h}:${String(m).padStart(2, '0')} ${ap}`; };

export const TIPOS = ['min', 'mitad', 'prov', 'ped', 'bit', 'fac'];

/** Configuración con valores por omisión, igual que en el panel. */
export function readCfg(app) {
  const a = (app && app.avisos) || {};
  const ped = (app && app.avisosPed) || {};
  const horas = Array.isArray(a.horas) && a.horas.length ? a.horas.map(Number) : [7, 14];
  const dias = Array.isArray(a.dias) ? a.dias.map(Number) : [0, 1, 2, 3, 4, 5, 6];
  return {
    activo: a.activo !== false,
    horas, dias,
    tipos: { min: true, mitad: true, prov: true, ped: true, bit: true, fac: true, ...(a.tipos || {}) },
    ped: {
      horas: Array.isArray(ped.horas) && ped.horas.length ? ped.horas.map(Number) : horas,
      dias: Array.isArray(ped.dias) ? ped.dias.map(Number) : [0, 1, 2, 3, 4, 5, 6],
      antes: Array.isArray(ped.antes) ? ped.antes.map(Number) : [3, 2, 1, 0],
    },
  };
}

/** ¿Qué grupos de avisos tocan en este momento? */
export function dueNow(cfg, now) {
  const general = cfg.activo && cfg.horas.includes(now.hour) && cfg.dias.includes(now.dow);
  const pedidos = cfg.activo && cfg.tipos.ped && cfg.ped.horas.includes(now.hour) && cfg.ped.dias.includes(now.dow);
  return { general, pedidos };
}

/** Arma las líneas de aviso. `want` = { general, pedidos } */
export async function compose(cfg, now, want) {
  const lines = [];
  const needProds = want.general && (cfg.tipos.min || cfg.tipos.mitad || cfg.tipos.prov);
  const prods = needProds ? await readCol('productos') : [];
  const provs = (want.general && cfg.tipos.prov) ? await readCol('proveedores') : [];
  const provName = id => (provs.find(p => p.id === id) || {}).nombre || id || 'Sin proveedor';

  if (want.general && cfg.tipos.min) prods.filter(p => sem(p) === 'rojo').forEach(p => lines.push({ k: 'min', t: `⚠️ ${p.nombre}: pide ${qty(pedirQ(p))}` }));
  if (want.general && cfg.tipos.mitad) prods.filter(p => sem(p) === 'amarillo').forEach(p => lines.push({ k: 'mitad', t: `${p.nombre}: va a la mitad` }));
  if (want.general && cfg.tipos.prov) {
    for (const pv of provs) {
      const items = prods.filter(p => p.prov === pv.id && ['rojo', 'amarillo'].includes(sem(p)));
      const red = items.some(p => sem(p) === 'rojo');
      if (((pv.diasPedido || []).includes(now.dow) || red) && (items.length || (pv.diasPedido || []).includes(now.dow))) {
        lines.push({ k: 'prov', t: `Hacer pedido a ${pv.nombre}${items.length ? ` (${items.length} ${items.length === 1 ? 'producto' : 'productos'})` : ''}` });
      }
    }
  }
  if (want.pedidos) {
    const peds = (await readCol('pedidos')).filter(o => o.estado !== 'entregado' && o.entrega);
    peds.map(o => ({ o, d: daysBetween(now.date, o.entrega) }))
      .filter(x => x.d < 0 || cfg.ped.antes.includes(x.d))
      .sort((a, b) => a.d - b.d)
      .forEach(({ o, d }) => lines.push({
        k: 'ped',
        t: `Pedido de ${o.cliente}: ${d < 0 ? `era para hace ${-d} ${d === -1 ? 'día' : 'días'}` : d === 0 ? 'se entrega HOY' : d === 1 ? 'se entrega mañana' : `se entrega en ${d} días`}${o.hora ? ' · ' + hora12(o.hora) : ''}`,
      }));
  }
  if (want.general && cfg.tipos.fac) {
    const fp = (await readCol('facturas_cli')).filter(f => f.estado !== 'enviada');
    if (fp.length) {
      const sin = fp.filter(f => !f.pdf).length;
      lines.push({ k: 'fac', t: `Facturas: ${sin ? sin + ' por hacer' : ''}${sin && fp.length - sin ? ' · ' : ''}${fp.length - sin ? (fp.length - sin) + ' listas por enviar' : ''}` });
    }
  }
  if (want.general && cfg.tipos.bit) {
    for (const [name, planId, dayPre] of [['Admi', 'plan', ''], ['Caja', 'plan_caja', 'caja_']]) {
      const plan = await readDoc('bitacora', planId);
      const day = await readDoc('bitacora', dayPre + now.date);
      const done = (day && day.done) || {};
      const tasks = ((plan && plan.dias && plan.dias[now.dow]) || []).filter(t => !done[t.id]);
      if (tasks.length) lines.push({ k: 'bit', t: `Bitácora ${name}: ${tasks.length} ${tasks.length === 1 ? 'pendiente' : 'pendientes'} hoy` });
    }
  }
  return lines;
}

export function toPayload(lines, extra = {}) {
  if (!lines.length) return null;
  const body = lines.slice(0, 5).map(l => l.t).join('\n') + (lines.length > 5 ? `\n+${lines.length - 5} más` : '');
  return { title: 'Pasteli', body, tag: 'pasteli-avisos', url: '/#negocio', ...extra };
}

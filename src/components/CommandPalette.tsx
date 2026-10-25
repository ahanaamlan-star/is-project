import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, AlertTriangle, Server, Network, CornerDownLeft, Layers, Navigation } from 'lucide-react';
import { useStore } from '../store/useStore';

type Item = { kind: 'page' | 'finding' | 'host' | 'flow' | 'incident'; id: string; label: string; sub?: string; run: () => void };

const PAGES: Array<[string, string]> = [
  ['dashboard', 'Case Dashboard'], ['ingest', 'PCAP Ingestion'], ['overview', 'Analysis Overview'], ['findings', 'Findings Explorer'], ['incidents', 'Incidents'],
  ['flows', 'Packets & Flows'], ['graph', 'Host Network Graph'], ['timeline', 'Incident Timeline'], ['assistant', 'Evidence Assistant'], ['diff', 'PCAP Diff'],
  ['notes', 'Analyst Notes & Audit'], ['reports', 'Investigation Reports'], ['lab', 'Evaluation Lab'], ['settings', 'Detection Settings'], ['diagnostics', 'System Diagnostics'],
];

export function CommandPalette() {
  const { paletteOpen, setPalette, run, setInspect } = useStore();
  const nav = useNavigate();
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => { if (paletteOpen) { setQ(''); setSel(0); setTimeout(() => ref.current?.focus(), 10); } }, [paletteOpen]);

  const items = useMemo<Item[]>(() => {
    const close = () => setPalette(false);
    const list: Item[] = PAGES.map(([to, label]) => ({ kind: 'page', id: to, label, run: () => { close(); nav(`/app/${to}`); } }));
    if (run) {
      for (const f of run.findings) list.push({ kind: 'finding', id: f.id, label: f.title, sub: `${f.id} · ${f.severity} · priority ${f.risk?.score}`, run: () => { close(); setInspect({ inspectFindingId: f.id }); } });
      for (const i of run.incidents) list.push({ kind: 'incident', id: i.id, label: i.title, sub: i.id, run: () => { close(); nav(`/app/incidents?id=${i.id}`); } });
      for (const h of run.hosts.slice(0, 400)) list.push({ kind: 'host', id: h.ip, label: h.ip, sub: [h.internal ? 'internal' : 'external', ...h.hostnames.slice(0, 2)].join(' · '), run: () => { close(); setInspect({ inspectHost: h.ip }); } });
      for (const f of run.flows.slice(0, 2000)) list.push({ kind: 'flow', id: f.id, label: `${f.src}:${f.sport} → ${f.dst}:${f.dport}`, sub: `${f.id} · ${f.app}${f.sni ? ' · ' + f.sni : ''}`, run: () => { close(); setInspect({ inspectFlowId: f.id }); } });
    }
    return list;
  }, [run, nav, setInspect, setPalette]);

  const results = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (!t) return items.filter((i) => i.kind === 'page' || i.kind === 'incident').slice(0, 14).concat(items.filter((i) => i.kind === 'finding').slice(0, 6));
    return items.filter((i) => `${i.id} ${i.label} ${i.sub || ''}`.toLowerCase().includes(t)).slice(0, 40);
  }, [q, items]);

  if (!paletteOpen) return null;
  const icon = (k: Item['kind']) => k === 'finding' ? <AlertTriangle className="w-3.5 h-3.5 text-rose-300" /> : k === 'host' ? <Server className="w-3.5 h-3.5 text-sky-300" /> : k === 'flow' ? <Network className="w-3.5 h-3.5 text-indigo-300" /> : k === 'incident' ? <Layers className="w-3.5 h-3.5 text-amber-300" /> : <Navigation className="w-3.5 h-3.5 text-slate-400" />;
  return (
    <div className="fixed inset-0 z-[55] bg-black/70 backdrop-blur-sm flex items-start justify-center p-4 pt-[12vh]" onMouseDown={(e) => e.target === e.currentTarget && setPalette(false)}>
      <div className="w-full max-w-xl bg-ink-800 border border-slate-700 rounded-xl shadow-2xl overflow-hidden animate-fadein">
        <div className="flex items-center gap-2 px-4 border-b border-slate-800">
          <Search className="w-4 h-4 text-slate-500" />
          <input ref={ref} value={q} onChange={(e) => { setQ(e.target.value); setSel(0); }} placeholder="Jump to a page, finding, host, flow or incident…"
            onKeyDown={(e) => {
              if (e.key === 'Escape') setPalette(false);
              if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(results.length - 1, s + 1)); }
              if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
              if (e.key === 'Enter') results[sel]?.run();
            }}
            className="flex-1 bg-transparent py-3.5 text-sm text-slate-100 outline-none placeholder:text-slate-600" />
        </div>
        <div className="max-h-[50vh] overflow-y-auto p-1.5">
          {results.length === 0 && <div className="p-4 text-xs text-slate-500">No matches{run ? '' : ' — analyse a capture to search evidence'}.</div>}
          {results.map((r, i) => (
            <button key={`${r.kind}-${r.id}`} onMouseEnter={() => setSel(i)} onClick={r.run} className={`w-full text-left flex items-center gap-3 px-3 py-2 rounded-lg ${i === sel ? 'bg-sky-500/10 border border-sky-500/30' : 'border border-transparent'}`}>
              {icon(r.kind)}
              <div className="min-w-0 flex-1"><div className="text-xs text-slate-200 truncate">{r.label}</div>{r.sub && <div className="text-[10px] text-slate-500 truncate font-mono">{r.sub}</div>}</div>
              {i === sel && <CornerDownLeft className="w-3.5 h-3.5 text-slate-500" />}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

import { useEffect, useMemo, useRef, useState } from 'react';
import { forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide, type SimulationNodeDatum, type SimulationLinkDatum } from 'd3-force';
import { ZoomIn, ZoomOut, Maximize2, Server, AlertTriangle } from 'lucide-react';
import { useStore } from '../store/useStore';
import { NeedsRun } from '../components/Guards';
import { Card, PageHeader, Select, Btn, KV, SeverityBadge, Pill } from '../components/ui';
import { fmtBytes } from '../lib/format';
import type { Severity } from '../engine/types';
import { SEV_RANK } from '../engine/correlate';

interface N extends SimulationNodeDatum { id: string; bytes: number; internal: boolean; sev?: Severity; label: string; flows: number }
interface L extends SimulationLinkDatum<N> { bytes: number; flows: number; apps: string[]; flagged: boolean }

const SEV_COLOR: Record<Severity, string> = { critical: '#fb7185', high: '#fbbf24', medium: '#facc15', low: '#38bdf8', informational: '#94a3b8' };

export function GraphPage() {
  return <NeedsRun><Graph /></NeedsRun>;
}

function Graph() {
  const s = useStore();
  const run = s.run!;
  const [maxNodes, setMaxNodes] = useState(60);
  const [proto, setProto] = useState('');
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [hover, setHover] = useState<{ x: number; y: number; text: string } | null>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [, setTick] = useState(0);
  const svgRef = useRef<SVGSVGElement>(null);
  const W = 1000, H = 640;

  const sevByEntity = useMemo(() => {
    const m = new Map<string, Severity>();
    for (const f of run.findings) {
      if (f.suppressed || f.status === 'benign_false_positive') continue;
      for (const e of f.evidence.entities) { const p = m.get(e); if (!p || SEV_RANK[f.severity] > SEV_RANK[p]) m.set(e, f.severity); }
    }
    return m;
  }, [run.findings]);

  const { nodes, links } = useMemo(() => {
    const pair = new Map<string, L & { s: string; t: string }>();
    for (const f of run.flows) {
      if (proto && f.app !== proto) continue;
      const k = f.src < f.dst ? `${f.src}|${f.dst}` : `${f.dst}|${f.src}`;
      const e = pair.get(k) || { s: f.src, t: f.dst, source: f.src, target: f.dst, bytes: 0, flows: 0, apps: [], flagged: false };
      e.bytes += f.totalBytes; e.flows++;
      if (!e.apps.includes(f.app)) e.apps.push(f.app);
      pair.set(k, e);
    }
    const vol = new Map<string, number>();
    for (const e of pair.values()) { vol.set(e.s, (vol.get(e.s) || 0) + e.bytes); vol.set(e.t, (vol.get(e.t) || 0) + e.bytes); }
    let ids = [...vol.keys()];
    if (flaggedOnly) {
      const flagged = new Set(ids.filter((i) => sevByEntity.has(i)));
      ids = ids.filter((i) => flagged.has(i) || [...pair.values()].some((e) => (e.s === i && flagged.has(e.t)) || (e.t === i && flagged.has(e.s))));
    }
    ids.sort((a, b) => (sevByEntity.has(b) ? 1 : 0) - (sevByEntity.has(a) ? 1 : 0) || vol.get(b)! - vol.get(a)!);
    const keep = new Set(ids.slice(0, maxNodes));
    const hosts = new Map(run.hosts.map((h) => [h.ip, h]));
    const nodes: N[] = [...keep].map((id) => {
      const h = hosts.get(id);
      return { id, bytes: vol.get(id) || 0, internal: h?.internal ?? false, sev: sevByEntity.get(id), label: h?.hostnames[0] || id, flows: (h?.flowsIn || 0) + (h?.flowsOut || 0) };
    });
    const links: L[] = [...pair.values()].filter((e) => keep.has(e.s) && keep.has(e.t)).map((e) => ({ ...e, source: e.s, target: e.t, flagged: sevByEntity.has(e.s) && sevByEntity.has(e.t) }));
    return { nodes, links };
  }, [run.flows, run.hosts, proto, flaggedOnly, maxNodes, sevByEntity]);

  useEffect(() => {
    const sim = forceSimulation<N>(nodes)
      .force('link', forceLink<N, L>(links).id((d) => d.id).distance((l) => 70 + 40 / Math.sqrt(l.flows)).strength(0.4))
      .force('charge', forceManyBody().strength(-220))
      .force('center', forceCenter(W / 2, H / 2))
      .force('collide', forceCollide<N>().radius((d) => rad(d) + 6))
      .alphaDecay(0.035);
    sim.on('tick', () => setTick((t) => t + 1));
    return () => { sim.stop(); };
  }, [nodes, links]);

  const maxB = Math.max(1, ...nodes.map((n) => n.bytes));
  const rad = (n: N) => 5 + Math.sqrt(n.bytes / maxB) * 20;
  const maxL = Math.max(1, ...links.map((l) => l.bytes));

  // pan / zoom / drag
  const drag = useRef<{ mode: 'pan' | 'node'; node?: N; sx: number; sy: number; vx: number; vy: number } | null>(null);
  const toLocal = (e: React.PointerEvent | React.WheelEvent) => {
    const r = svgRef.current!.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * W, py = ((e.clientY - r.top) / r.height) * H;
    return { px, py, x: (px - view.x) / view.k, y: (py - view.y) / view.k };
  };
  const onWheel = (e: React.WheelEvent) => {
    const { px, py } = toLocal(e);
    const k = Math.min(4, Math.max(0.3, view.k * (e.deltaY < 0 ? 1.12 : 0.89)));
    setView({ k, x: px - ((px - view.x) / view.k) * k, y: py - ((py - view.y) / view.k) * k });
  };
  const zoom = (f: number) => setView((v) => { const k = Math.min(4, Math.max(0.3, v.k * f)); return { k, x: W / 2 - ((W / 2 - v.x) / v.k) * k, y: H / 2 - ((H / 2 - v.y) / v.k) * k }; });

  const sel = selected ? run.hosts.find((h) => h.ip === selected) : null;
  const selFindings = selected ? run.findings.filter((f) => f.evidence.entities.includes(selected) && !f.suppressed) : [];
  const apps = [...new Set(run.flows.map((f) => f.app))].sort();

  return (
    <div className="space-y-4">
      <PageHeader title="Host Network Graph" subtitle="Hosts as nodes (size = traffic volume), conversations as edges (width = bytes). Rings mark entities involved in open findings. Drag nodes, scroll to zoom, drag the background to pan." />
      <Card className="p-3 flex flex-wrap items-center gap-2">
        <Select value={proto} onChange={(e) => setProto(e.target.value)}><option value="">All protocols</option>{apps.map((a) => <option key={a}>{a}</option>)}</Select>
        <Select value={maxNodes} onChange={(e) => setMaxNodes(Number(e.target.value))}>{[25, 60, 120, 250].map((n) => <option key={n} value={n}>Top {n} hosts</option>)}</Select>
        <label className="text-[11px] text-slate-400 flex items-center gap-1.5"><input type="checkbox" checked={flaggedOnly} onChange={(e) => setFlaggedOnly(e.target.checked)} />Flagged entities & neighbours only</label>
        <div className="ml-auto flex gap-1">
          <Btn size="sm" variant="secondary" onClick={() => zoom(1.25)} aria-label="Zoom in"><ZoomIn className="w-3.5 h-3.5" /></Btn>
          <Btn size="sm" variant="secondary" onClick={() => zoom(0.8)} aria-label="Zoom out"><ZoomOut className="w-3.5 h-3.5" /></Btn>
          <Btn size="sm" variant="secondary" onClick={() => setView({ x: 0, y: 0, k: 1 })} aria-label="Reset view"><Maximize2 className="w-3.5 h-3.5" /></Btn>
        </div>
      </Card>
      <div className="grid lg:grid-cols-4 gap-4">
        <Card className="lg:col-span-3 relative overflow-hidden">
          <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} className="w-full h-[480px] md:h-[620px] bg-ink-950/60 grid-bg touch-none cursor-grab active:cursor-grabbing"
            onWheel={onWheel}
            onPointerDown={(e) => { const { px, py } = toLocal(e); drag.current = { mode: 'pan', sx: px, sy: py, vx: view.x, vy: view.y }; (e.target as Element).setPointerCapture?.(e.pointerId); }}
            onPointerMove={(e) => {
              const d = drag.current; if (!d) return;
              const { px, py, x, y } = toLocal(e);
              if (d.mode === 'pan') setView({ ...view, x: d.vx + px - d.sx, y: d.vy + py - d.sy });
              else if (d.node) { d.node.fx = x; d.node.fy = y; setTick((t) => t + 1); }
            }}
            onPointerUp={() => { if (drag.current?.node) { drag.current.node.fx = null; drag.current.node.fy = null; } drag.current = null; }}>
            <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
              {links.map((l, i) => {
                const a = l.source as N, b = l.target as N;
                if (a.x == null || b.x == null) return null;
                const dim = selected && a.id !== selected && b.id !== selected;
                return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={l.flagged ? '#fb7185' : '#475569'} strokeOpacity={dim ? 0.08 : l.flagged ? 0.7 : 0.45} strokeWidth={1 + Math.log10(1 + (l.bytes / maxL) * 99) * 2.5}
                  onPointerEnter={(e) => setHover({ x: e.clientX, y: e.clientY, text: `${a.id} ⇄ ${b.id} · ${l.flows} flows · ${fmtBytes(l.bytes)} · ${l.apps.slice(0, 4).join(', ')}` })} onPointerLeave={() => setHover(null)} />;
              })}
              {nodes.map((n) => {
                if (n.x == null) return null;
                const r = rad(n);
                const dim = selected && selected !== n.id && !links.some((l) => ((l.source as N).id === selected && (l.target as N).id === n.id) || ((l.target as N).id === selected && (l.source as N).id === n.id));
                return (
                  <g key={n.id} transform={`translate(${n.x},${n.y})`} opacity={dim ? 0.25 : 1} className="cursor-pointer"
                    onPointerDown={(e) => { e.stopPropagation(); drag.current = { mode: 'node', node: n, sx: 0, sy: 0, vx: 0, vy: 0 }; }}
                    onClick={() => setSelected(selected === n.id ? null : n.id)}
                    onPointerEnter={(e) => setHover({ x: e.clientX, y: e.clientY, text: `${n.id}${n.label !== n.id ? ' (' + n.label + ')' : ''} · ${n.internal ? 'internal' : 'external'} · ${fmtBytes(n.bytes)}${n.sev ? ' · ' + n.sev + ' finding' : ''}` })} onPointerLeave={() => setHover(null)}>
                    {n.sev && <circle r={r + 5} fill="none" stroke={SEV_COLOR[n.sev]} strokeWidth={2.5} strokeDasharray={n.sev === 'critical' ? '0' : '4 3'} />}
                    <circle r={r} fill={n.internal ? '#0284c7' : '#d97706'} stroke={selected === n.id ? '#fff' : '#0e1626'} strokeWidth={2} />
                    {(r > 9 || n.sev || selected === n.id) && <text y={r + 14} textAnchor="middle" fontSize={10} fill="#cbd5e1" className="pointer-events-none font-mono" style={{ paintOrder: 'stroke', stroke: '#090d16', strokeWidth: 3 }}>{n.label.length > 26 ? n.label.slice(0, 24) + '…' : n.label}</text>}
                  </g>
                );
              })}
            </g>
          </svg>
          <div className="absolute bottom-3 left-3 flex flex-wrap gap-3 text-[10px] text-slate-400 bg-ink-900/90 border border-slate-800 rounded-lg px-3 py-2">
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#0284c7]" />Internal</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#d97706]" />External</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full border-2 border-rose-400" />In finding (ring = severity)</span>
            <span className="flex items-center gap-1.5"><span className="w-4 h-0.5 bg-rose-400" />Flagged conversation</span>
          </div>
          <div className="absolute top-3 right-3 text-[10px] text-slate-500">{nodes.length} nodes · {links.length} edges</div>
        </Card>
        <Card className="p-4">
          {sel ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2"><Server className="w-4 h-4 text-sky-400" /><span className="text-sm font-mono text-white break-all">{sel.ip}</span></div>
              {sel.hostnames.length > 0 && <div className="text-[11px] text-slate-400">{sel.hostnames.join(', ')}</div>}
              <div className="flex gap-1"><Pill className={sel.internal ? 'text-emerald-300' : 'text-amber-300'}>{sel.internal ? 'internal' : 'external'}</Pill><Pill>{sel.role}</Pill></div>
              <div><KV k="Bytes out / in" v={`${fmtBytes(sel.bytesOut)} / ${fmtBytes(sel.bytesIn)}`} /><KV k="Fan-out / fan-in" v={`${sel.fanOut} / ${sel.fanIn}`} /><KV k="Dst ports" v={sel.distinctDstPorts} /><KV k="Failed conns" v={sel.failedConns} /></div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-1.5 flex items-center gap-1"><AlertTriangle className="w-3 h-3" />Findings ({selFindings.length})</div>
                {selFindings.slice(0, 8).map((f) => <button key={f.id} onClick={() => s.setInspect({ inspectFindingId: f.id })} className="w-full text-left p-2 rounded border border-slate-800 hover:border-sky-500/40 mb-1"><SeverityBadge s={f.severity} /><div className="text-[11px] text-slate-300 mt-1 leading-snug">{f.title}</div></button>)}
              </div>
              <Btn size="sm" variant="secondary" className="w-full" onClick={() => s.setInspect({ inspectHost: sel.ip })}>Open full host profile</Btn>
            </div>
          ) : (
            <div className="text-xs text-slate-500 leading-relaxed space-y-2">
              <p className="text-slate-300 font-semibold">Select a node</p>
              <p>Click a host to highlight its conversations and see its behaviour profile and related findings.</p>
              <p>Hosts in open findings are always kept in view; the rest are ranked by traffic volume.</p>
            </div>
          )}
        </Card>
      </div>
      {hover && <div className="fixed z-50 pointer-events-none bg-ink-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-[11px] text-slate-200 shadow-xl font-mono max-w-sm" style={{ left: hover.x + 14, top: hover.y + 14 }}>{hover.text}</div>}
    </div>
  );
}

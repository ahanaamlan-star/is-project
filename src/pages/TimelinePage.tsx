import { useMemo, useState } from 'react';
import { Clock, RotateCcw } from 'lucide-react';
import { useStore } from '../store/useStore';
import { NeedsRun } from '../components/Guards';
import { Card, PageHeader, SeverityBadge, StatusBadge, Input, Select, Btn, Pill, SectionTitle } from '../components/ui';
import { fmtTs, humanize, SEV_HEX } from '../lib/format';
import { SEV_RANK } from '../engine/correlate';

export function TimelinePage() {
  return <NeedsRun><Timeline /></NeedsRun>;
}

function Timeline() {
  const s = useStore();
  const run = s.run!;
  const [entity, setEntity] = useState('');
  const [minSev, setMinSev] = useState(0);
  const [range, setRange] = useState<[number, number]>([0, 1000]);
  const [hover, setHover] = useState<{ x: number; y: number; id: string } | null>(null);

  const t0 = run.summary.start ?? 0, t1 = run.summary.end ?? 1;
  const span = Math.max(1, t1 - t0);
  const vs = t0 + (range[0] / 1000) * span, ve = t0 + (range[1] / 1000) * span;

  const items = useMemo(() => run.findings.filter((f) => !f.suppressed && SEV_RANK[f.severity] >= minSev && (!entity || f.evidence.entities.some((e) => e.toLowerCase().includes(entity.toLowerCase())))).sort((a, b) => a.evidence.tsRange[0] - b.evidence.tsRange[0]), [run.findings, entity, minSev]);
  const lanes = useMemo(() => [...new Set(items.map((f) => f.category))], [items]);
  const W = 1000, laneH = 34, top = 28, H = top + Math.max(1, lanes.length) * laneH + 10, left = 140;
  const x = (t: number) => left + ((t - vs) / Math.max(0.001, ve - vs)) * (W - left - 10);
  const ticks = Array.from({ length: 6 }, (_, i) => vs + ((ve - vs) * i) / 5);
  const visible = items.filter((f) => f.evidence.tsRange[1] >= vs && f.evidence.tsRange[0] <= ve);
  const hf = hover ? run.findings.find((f) => f.id === hover.id) : null;

  return (
    <div className="space-y-5">
      <PageHeader title="Incident Timeline" subtitle="Findings plotted on the capture clock, one lane per category, with correlated incidents as background bands. Zoom with the range handles; click any mark to open its evidence." />
      <Card className="p-3 flex flex-wrap items-center gap-2">
        <Input value={entity} onChange={(e) => setEntity(e.target.value)} placeholder="Filter by entity (IP / domain)…" className="w-56 font-mono" />
        <Select value={minSev} onChange={(e) => setMinSev(Number(e.target.value))}><option value={0}>All severities</option><option value={1}>Low and above</option><option value={2}>Medium and above</option><option value={3}>High and above</option><option value={4}>Critical only</option></Select>
        <div className="flex items-center gap-2 text-[11px] text-slate-400 flex-1 min-w-[260px]">
          <span>Zoom</span>
          <input type="range" min={0} max={999} value={range[0]} onChange={(e) => setRange([Math.min(Number(e.target.value), range[1] - 1), range[1]])} className="flex-1" aria-label="Range start" />
          <input type="range" min={1} max={1000} value={range[1]} onChange={(e) => setRange([range[0], Math.max(Number(e.target.value), range[0] + 1)])} className="flex-1" aria-label="Range end" />
          <Btn size="sm" variant="ghost" onClick={() => setRange([0, 1000])} aria-label="Reset zoom"><RotateCcw className="w-3.5 h-3.5" /></Btn>
        </div>
      </Card>

      <Card className="p-4 overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full min-w-[720px]" style={{ height: H }}>
          {ticks.map((t, i) => (
            <g key={i}>
              <line x1={x(t)} x2={x(t)} y1={top - 6} y2={H - 6} stroke="#1e293b" />
              <text x={x(t)} y={14} fontSize={10} fill="#64748b" textAnchor={i === 0 ? 'start' : i === 5 ? 'end' : 'middle'} className="font-mono">{fmtTs(t, false).slice(0, 12)}</text>
            </g>
          ))}
          {run.incidents.map((inc) => inc.end >= vs && inc.start <= ve && (
            <g key={inc.id}>
              <rect x={Math.max(left, x(inc.start))} y={top - 4} width={Math.max(3, Math.min(W - 10, x(inc.end)) - Math.max(left, x(inc.start)))} height={H - top} fill="#6366f1" fillOpacity={0.07} stroke="#6366f1" strokeOpacity={0.25} rx={4} />
              <text x={Math.max(left, x(inc.start)) + 4} y={H - 10} fontSize={9} fill="#818cf8">{inc.id}</text>
            </g>
          ))}
          {lanes.map((l, i) => (
            <g key={l}>
              <rect x={0} y={top + i * laneH} width={W} height={laneH} fill={i % 2 ? 'transparent' : 'rgba(30,41,59,.25)'} />
              <text x={8} y={top + i * laneH + laneH / 2 + 4} fontSize={11} fill="#94a3b8">{humanize(l)}</text>
            </g>
          ))}
          {visible.map((f) => {
            const lane = lanes.indexOf(f.category);
            const xa = Math.max(left, x(f.evidence.tsRange[0])), xb = Math.min(W - 10, x(f.evidence.tsRange[1]));
            const y = top + lane * laneH + 8;
            return (
              <g key={f.id} className="cursor-pointer" onClick={() => s.setInspect({ inspectFindingId: f.id })} onMouseEnter={(e) => setHover({ x: e.clientX, y: e.clientY, id: f.id })} onMouseLeave={() => setHover(null)}>
                <rect x={xa - 6} y={y - 6} width={Math.max(14, xb - xa + 12)} height={laneH - 4} fill="transparent" />
                <rect x={xa} y={y} width={Math.max(4, xb - xa)} height={laneH - 16} rx={4} fill={SEV_HEX[f.severity]} fillOpacity={f.status === 'benign_false_positive' ? 0.25 : 0.85} stroke="#0e1626" strokeWidth={2} />
              </g>
            );
          })}
          {!lanes.length && <text x={W / 2} y={top + 20} textAnchor="middle" fontSize={12} fill="#64748b">No findings match the filters.</text>}
        </svg>
        <div className="flex flex-wrap gap-3 text-[10px] text-slate-400 mt-2">
          {(['critical', 'high', 'medium', 'low'] as const).map((sv) => <span key={sv} className="flex items-center gap-1.5"><span className="w-3 h-2 rounded-sm" style={{ background: SEV_HEX[sv] }} />{sv}</span>)}
          <span className="flex items-center gap-1.5"><span className="w-3 h-2 rounded-sm bg-indigo-500/30 border border-indigo-500/50" />incident window</span>
        </div>
      </Card>

      <Card className="p-5">
        <SectionTitle icon={<Clock className="w-4 h-4 text-sky-400" />}>Chronological event log ({visible.length})</SectionTitle>
        <div className="relative pl-5 space-y-2.5 before:absolute before:left-1.5 before:top-1 before:bottom-1 before:w-px before:bg-slate-800">
          {visible.map((f) => (
            <button key={f.id} onClick={() => s.setInspect({ inspectFindingId: f.id })} className="relative w-full text-left">
              <span className="absolute -left-[18px] top-3 w-2.5 h-2.5 rounded-full border-2 border-ink-800" style={{ background: SEV_HEX[f.severity] }} />
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/50 hover:border-sky-500/40">
                <div className="flex flex-wrap items-center gap-1.5"><span className="text-[10px] font-mono text-slate-500">{fmtTs(f.evidence.tsRange[0])}</span><SeverityBadge s={f.severity} /><StatusBadge s={f.status} />{f.incidentId && <Pill className="text-indigo-300">{f.incidentId}</Pill>}</div>
                <div className="text-xs text-slate-200 mt-1">{f.title}</div>
              </div>
            </button>
          ))}
        </div>
      </Card>
      {hf && hover && (
        <div className="fixed z-50 pointer-events-none bg-ink-800 border border-slate-700 rounded-lg p-2.5 text-[11px] shadow-xl max-w-xs" style={{ left: Math.min(hover.x + 14, window.innerWidth - 300), top: hover.y + 14 }}>
          <div className="flex items-center gap-1.5 mb-1"><SeverityBadge s={hf.severity} /><span className="font-mono text-slate-500">{hf.id}</span></div>
          <div className="text-slate-200">{hf.title}</div>
          <div className="text-slate-500 font-mono mt-1">{fmtTs(hf.evidence.tsRange[0], false)} → {fmtTs(hf.evidence.tsRange[1], false)}</div>
        </div>
      )}
    </div>
  );
}

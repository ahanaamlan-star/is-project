import { useMemo, useState, useEffect } from 'react';
import { Search, Filter, Download, Bookmark, X, CheckSquare, Square } from 'lucide-react';
import { useStore, STATUS_LABEL } from '../store/useStore';
import { NeedsRun } from '../components/Guards';
import { Card, PageHeader, SeverityBadge, StatusBadge, ConfidenceBadge, Pill, Input, Select, Btn, cx } from '../components/ui';
import { fmtTs, humanize, download, SEV_ORDER } from '../lib/format';
import { findingsCsv } from '../lib/report';
import type { FindingStatus, Severity } from '../engine/types';
import { SEV_RANK } from '../engine/correlate';

interface Filters { q: string; sev: string; status: string; source: string; cat: string; showSuppressed: boolean; hideDismissed: boolean; sort: 'priority' | 'severity' | 'time' }
const DEF: Filters = { q: '', sev: '', status: '', source: '', cat: '', showSuppressed: false, hideDismissed: false, sort: 'priority' };
const LS_KEY = 'nsx.savedFilters';

function loadSaved(): Array<{ name: string; f: Filters }> {
  try { return JSON.parse(localStorage.getItem(LS_KEY) || '[]'); } catch { return []; }
}

export function FindingsPage() {
  return <NeedsRun><Findings /></NeedsRun>;
}

function Findings() {
  const s = useStore();
  const run = s.run!;
  const [f, setF] = useState<Filters>(DEF);
  const [saved, setSaved] = useState(loadSaved);
  const [sel, setSel] = useState<Set<string>>(new Set());
  useEffect(() => { try { localStorage.setItem(LS_KEY, JSON.stringify(saved)); } catch { /* storage unavailable */ } }, [saved]);

  const cats = [...new Set(run.findings.map((x) => x.category))];
  const list = useMemo(() => {
    const q = f.q.toLowerCase();
    const out = run.findings.filter((x) =>
      (f.showSuppressed || !x.suppressed) && (!f.hideDismissed || x.status !== 'benign_false_positive') &&
      (!f.sev || x.severity === f.sev) && (!f.status || x.status === f.status) && (!f.source || x.source === f.source) && (!f.cat || x.category === f.cat) &&
      (!q || `${x.id} ${x.title} ${x.detectorId} ${x.evidence.entities.join(' ')} ${x.tags.join(' ')} ${x.mitre.map((m) => m.id).join(' ')}`.toLowerCase().includes(q)));
    if (f.sort === 'severity') out.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || (b.risk?.score || 0) - (a.risk?.score || 0));
    else if (f.sort === 'time') out.sort((a, b) => a.evidence.tsRange[0] - b.evidence.tsRange[0]);
    else out.sort((a, b) => (b.risk?.score || 0) - (a.risk?.score || 0));
    return out;
  }, [run.findings, f]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const x of run.findings) if (!x.suppressed) c[x.severity] = (c[x.severity] || 0) + 1;
    return c;
  }, [run.findings]);
  const bySource = useMemo(() => ({
    rule: run.findings.filter((x) => x.source === 'rule' && !x.suppressed).length,
    statistical: run.findings.filter((x) => x.source === 'statistical' && !x.suppressed).length,
    model: run.findings.filter((x) => x.source === 'model' && !x.suppressed).length,
  }), [run.findings]);

  const bulk = async (status: FindingStatus) => {
    for (const id of sel) await s.updateFinding(id, { status }, `Bulk disposition → ${status}`);
    s.toast('success', `${sel.size} findings marked ${humanize(status)}.`);
    setSel(new Set());
  };
  const active = JSON.stringify(f) !== JSON.stringify(DEF);
  const cap = s.captures.find((c) => c.id === s.activeCaptureId)!;
  const c = s.cases.find((x) => x.id === s.activeCaseId)!;

  return (
    <div className="space-y-5">
      <PageHeader title="Findings Explorer" subtitle="Rule, statistical and model signals are kept separate. Priority is a transparent, configurable ranking — never a probability of compromise."
        right={<Btn variant="secondary" size="sm" onClick={() => download(`findings_${run.runId}.csv`, findingsCsv({ c, cap, run: { ...run, findings: list }, events: [], analyst: s.analyst, includeDismissed: true, includeSuppressed: true }), 'text/csv')}><Download className="w-3.5 h-3.5" />Export filtered CSV</Btn>} />

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {SEV_ORDER.map((sv) => (
          <button key={sv} onClick={() => setF({ ...f, sev: f.sev === sv ? '' : sv })} className={cx('p-3 rounded-xl border text-left transition-colors', f.sev === sv ? 'border-sky-500/50 bg-sky-500/5' : 'border-slate-800 bg-slate-900/60 hover:border-slate-700')}>
            <SeverityBadge s={sv as Severity} /><div className="text-xl font-bold text-white mt-1.5 tabular-nums">{counts[sv] || 0}</div>
          </button>
        ))}
      </div>
      <div className="flex flex-wrap gap-2 text-[11px] text-slate-400">
        <span>Signal layers:</span>
        <Pill className="text-emerald-300">rules {bySource.rule}</Pill><Pill className="text-indigo-300">statistical {bySource.statistical}</Pill><Pill className="text-fuchsia-300">model {bySource.model}</Pill>
      </div>

      <Card className="p-3 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <Input value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} placeholder="Search title, IP, domain, tag, ATT&CK ID…" className="w-full pl-8" />
        </div>
        <Select value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })}><option value="">All statuses</option>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</Select>
        <Select value={f.source} onChange={(e) => setF({ ...f, source: e.target.value })}><option value="">All layers</option><option value="rule">Rule</option><option value="statistical">Statistical</option><option value="model">Model</option></Select>
        <Select value={f.cat} onChange={(e) => setF({ ...f, cat: e.target.value })}><option value="">All categories</option>{cats.map((x) => <option key={x} value={x}>{humanize(x)}</option>)}</Select>
        <Select value={f.sort} onChange={(e) => setF({ ...f, sort: e.target.value as Filters['sort'] })}><option value="priority">Sort: priority</option><option value="severity">Sort: severity</option><option value="time">Sort: time</option></Select>
        <label className="text-[11px] text-slate-400 flex items-center gap-1.5"><input type="checkbox" checked={f.hideDismissed} onChange={(e) => setF({ ...f, hideDismissed: e.target.checked })} />Hide dismissed</label>
        <label className="text-[11px] text-slate-400 flex items-center gap-1.5"><input type="checkbox" checked={f.showSuppressed} onChange={(e) => setF({ ...f, showSuppressed: e.target.checked })} />Show allowlisted</label>
        {active && <Btn size="sm" variant="ghost" onClick={() => setF(DEF)}><X className="w-3 h-3" />Reset</Btn>}
        {active && <Btn size="sm" variant="secondary" onClick={() => { const name = prompt('Name this saved filter'); if (name) setSaved([...saved.filter((x) => x.name !== name), { name, f }]); }}><Bookmark className="w-3 h-3" />Save</Btn>}
      </Card>
      {saved.length > 0 && (
        <div className="flex flex-wrap gap-1.5 items-center text-[11px]"><Filter className="w-3.5 h-3.5 text-slate-500" />
          {saved.map((x) => (
            <span key={x.name} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-700 bg-slate-900">
              <button onClick={() => setF(x.f)} className="text-sky-300 hover:text-sky-200">{x.name}</button>
              <button onClick={() => setSaved(saved.filter((y) => y.name !== x.name))} className="text-slate-500 hover:text-rose-300" aria-label={`Delete saved filter ${x.name}`}><X className="w-3 h-3" /></button>
            </span>
          ))}
        </div>
      )}

      {sel.size > 0 && (
        <Card className="p-3 flex flex-wrap items-center gap-2 border-sky-500/30 sticky top-20 z-20 bg-ink-800/95 backdrop-blur">
          <span className="text-xs text-slate-300">{sel.size} selected</span>
          <Btn size="sm" variant="secondary" onClick={() => bulk('benign_false_positive')}>Benign / FP</Btn>
          <Btn size="sm" variant="secondary" onClick={() => bulk('under_review')}>Under review</Btn>
          <Btn size="sm" variant="secondary" onClick={() => bulk('suspicious')}>Suspicious</Btn>
          <Btn size="sm" variant="secondary" onClick={() => bulk('escalated')}>Escalate</Btn>
          <Btn size="sm" variant="ghost" onClick={() => setSel(new Set())}>Clear</Btn>
        </Card>
      )}

      <div className="space-y-2">
        <div className="flex items-center gap-2 text-[11px] text-slate-500 px-1">
          <button onClick={() => setSel(sel.size === list.length ? new Set() : new Set(list.map((x) => x.id)))} className="flex items-center gap-1 hover:text-slate-300">{sel.size === list.length && list.length ? <CheckSquare className="w-3.5 h-3.5" /> : <Square className="w-3.5 h-3.5" />}Select all</button>
          <span>· {list.length} of {run.findings.length} findings</span>
        </div>
        {list.map((x) => (
          <Card key={x.id} className={cx('p-4 hover:border-sky-500/40 transition-colors cursor-pointer flex gap-3', x.suppressed && 'opacity-50', x.status === 'benign_false_positive' && 'opacity-70')} onClick={() => s.setInspect({ inspectFindingId: x.id })}>
            <button onClick={(e) => { e.stopPropagation(); const n = new Set(sel); n.has(x.id) ? n.delete(x.id) : n.add(x.id); setSel(n); }} className="text-slate-500 hover:text-sky-300 shrink-0 self-start mt-1" aria-label="Select finding">
              {sel.has(x.id) ? <CheckSquare className="w-4 h-4 text-sky-400" /> : <Square className="w-4 h-4" />}
            </button>
            <div className="w-12 h-12 rounded-lg bg-slate-950 border border-slate-800 flex flex-col items-center justify-center shrink-0">
              <span className="text-base font-extrabold text-white tabular-nums leading-none">{x.risk?.score}</span><span className="text-[8px] text-slate-500 uppercase mt-0.5">priority</span>
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <SeverityBadge s={x.severity} /><StatusBadge s={x.status} /><ConfidenceBadge c={x.confidence} />
                <Pill className={x.source === 'rule' ? 'text-emerald-300' : x.source === 'model' ? 'text-fuchsia-300' : 'text-indigo-300'}>{x.source}</Pill>
                <Pill>{humanize(x.category)}</Pill>
                {x.incidentId && <Pill className="text-indigo-300">{x.incidentId}</Pill>}
                {x.mitre.slice(0, 2).map((m) => <Pill key={m.id} className="font-mono text-rose-300/80" title={m.name}>{m.id}</Pill>)}
                {x.tags.map((t) => <Pill key={t} className="text-sky-300">#{t}</Pill>)}
              </div>
              <div className="text-sm font-semibold text-slate-100 mt-1.5 leading-snug">{x.title}</div>
              <div className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">{x.explanation.summary}</div>
              <div className="text-[10px] text-slate-500 mt-1.5 font-mono">{x.id} · {x.detectorId} · {fmtTs(x.evidence.tsRange[0])} · {x.evidence.packetIdx.length} pkt refs · {x.evidence.flowIds.length} flow refs{x.assignee ? ` · @${x.assignee}` : ''}</div>
            </div>
          </Card>
        ))}
        {list.length === 0 && <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">No findings match these filters.</div>}
      </div>
    </div>
  );
}
